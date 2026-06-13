"""Phase quality scoring — gates between waves (2026-06-09, Issue 11).

After every wave's evidence is built, the executor invokes a
quality scorer. The default implementation is the deterministic
:func:`RulesBasedQualityScorer` below; an operator can swap it
for an LLM-based ``quality-scorer`` specialist via
``DispatchExecutor(quality_scorer_fn=...)``.

The 4 explicit criteria the user named (51ifind.com 2026-06-09
review) are encoded as constants in :data:`QUALITY_CRITERIA` and
checked by the rules-based scorer:

  C1 — ``reachable_address_must_have_full_url``
       When a ``ServiceEntry.reachability="reachable"`` or a
       ``PerTargetFinding.status in {owned, partial}`` is
       reported, the complete URL (or ``host:port``) MUST be
       present. The 51ifind.com W8 report surfaced rows like
       "Prometheus 可达 是（9090 端口返回 JSON）高" with no
       actual URL — operators could not reproduce the check.
       Default deduction: 30 points.

  C2 — ``open_port_must_have_host_port``
       Every reported open port MUST include a complete
       ``host:port`` or full URL — not just the port number.
       Default deduction: 20 points.

  C3 — ``vulnerability_must_have_poc``
       Every reported vulnerability MUST have at least one
       ``reproduce_steps`` entry with command + observed_outcome
       + outcome_match. "我看到 IDOR 但是没写 PoC" is a fake
       vuln. Default deduction: 25 points.

  C4 — ``exploit_success_must_have_body_analysis``
       Every ``status="owned"`` finding MUST have
       ``failure_markers`` AND ``body_required_substrings`` set
       on its ``reproduce_steps`` (per Issue 5 — body-content
       verification), AND the runtime verifier must have
       confirmed it (i.e. ``verified=True``). A claim of
       "owned" without body-content analysis is a fake vuln.
       Default deduction: 35 points.

A few extra rules are bundled for free (C5..C7) — see
``EXTRA_CRITERIA``.

The scorer is a callable: it takes a validated ``EvidenceBase``
+ the wave id + handoff_id, and returns a
:class:`PhaseQualityScore`. The threshold is operator-tunable
(``quality_threshold`` constructor arg) and defaults to 90.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from opensquilla.attack_dispatch.evidence import (
    EVIDENCE_SCHEMAS,
    EvidenceBase,
    PenetrationEvidence,
    PenetrationFinding,
    PerTargetFinding,
    PhaseQualityScore,
    QualityDeduction,
    ReconEvidence,
    ReportEvidence,
    ServiceEntry,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Criteria constants — 4 explicit + a few obvious extras.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityCriterion:
    """One quality criterion.

    Each criterion has:
    - ``criterion_id``: canonical C-code (C1..C7)
    - ``name``: short human-readable identifier
    - ``description``: 1-2 sentence explanation
    - ``default_deduction``: how many points this hits cost
      the phase when the criterion fails. The scorer
      subtracts this from the base 100. (Multiple hits on
      the same criterion in one wave can compound — see
      ``max_deduction_per_criterion`` for the cap.)
    - ``scope``: which evidence schemas this criterion
      applies to ("*", "recon", "pentest", "report", etc.)
    """

    criterion_id: str
    name: str
    description: str
    default_deduction: int
    scope: str = "*"
    max_deduction_per_criterion: int = 100  # cap on the per-wave total


# The 4 user-named criteria.
USER_CRITERIA: tuple[QualityCriterion, ...] = (
    QualityCriterion(
        criterion_id="C1",
        name="reachable_address_must_have_full_url",
        description=(
            "When ServiceEntry.reachability='reachable' or "
            "PerTargetFinding.status in {owned, partial}, the "
            "complete URL (or host:port) MUST be present. "
            "'9090 reachable' with no URL is a fake reach."
        ),
        default_deduction=30,
        scope="*",
    ),
    QualityCriterion(
        criterion_id="C2",
        name="open_port_must_have_host_port",
        description=(
            "Every reported open port MUST include host:port "
            "or a full URL — not just the port number. "
            "'port 9090 open' is incomplete."
        ),
        default_deduction=20,
        scope="*",
    ),
    QualityCriterion(
        criterion_id="C3",
        name="vulnerability_must_have_poc",
        description=(
            "Every reported vulnerability MUST have at least "
            "one reproduce_steps entry with command + "
            "observed_outcome + outcome_match. A vuln claim "
            "without a runnable PoC is a fake vuln."
        ),
        default_deduction=25,
        scope="pentest",
    ),
    QualityCriterion(
        criterion_id="C4",
        name="exploit_success_must_have_body_analysis",
        description=(
            "Every status='owned' finding MUST have "
            "failure_markers AND body_required_substrings on "
            "its reproduce_steps (per Issue 5 — body-content "
            "verification) AND the runtime verifier must have "
            "confirmed it (verified=True). A claim of 'owned' "
            "without body-content analysis is the canonical "
            "200-OK-with-failed-body fake vuln."
        ),
        default_deduction=35,
        scope="pentest",
    ),
)

# Extra criteria — bundled because they're trivially checkable
# and catch common LLM sloppiness.
EXTRA_CRITERIA: tuple[QualityCriterion, ...] = (
    QualityCriterion(
        criterion_id="C5",
        name="missing_evidence_fields",
        description=(
            "Required schema fields (e.g. PentestFinding's "
            "15 fields, PerTargetFinding's reachability_url) "
            "MUST be populated. Empty required fields lower "
            "the score."
        ),
        default_deduction=10,
        scope="*",
    ),
    QualityCriterion(
        criterion_id="C6",
        name="incomplete_chain_metadata",
        description=(
            "Findings that claim chain dependencies "
            "(chain_id / follows_from / enables) MUST have "
            "the chain_id populated AND at least one of "
            "follows_from / enables. An empty chain is a "
            "vague claim."
        ),
        default_deduction=8,
        scope="pentest",
    ),
    QualityCriterion(
        criterion_id="C7",
        name="missing_reachability_proof",
        description=(
            "Every reachable service MUST have "
            "reachability_proof (free text: e.g. '9090 "
            "returned JSON {status:ok}'). A claim of "
            "reachable with no proof is unsubstantiated."
        ),
        default_deduction=10,
        scope="recon",
    ),
)

QUALITY_CRITERIA: dict[str, QualityCriterion] = {
    c.criterion_id: c
    for c in USER_CRITERIA + EXTRA_CRITERIA
}


# ---------------------------------------------------------------------------
# Scorer protocol + rules-based default
# ---------------------------------------------------------------------------


class PhaseQualityScorerFn(Protocol):
    """A callable that scores one wave's evidence.

    Implementations MUST:
      1. Inspect the evidence against ``QUALITY_CRITERIA``.
      2. Return a :class:`PhaseQualityScore` whose
         ``deductions`` list mirrors the failed criteria,
         and whose ``strengths`` lists what was right.
      3. Never raise on a malformed evidence — return a
         low-score ``PhaseQualityScore`` instead, so the
         executor's retry path can engage.
    """

    def __call__(
        self,
        evidence: EvidenceBase,
        *,
        wave: str,
        handoff_id: str,
        threshold: int,
        retry_count: int,
    ) -> PhaseQualityScore: ...


def _score_to_int(value: int | float) -> int:
    """Clamp a numeric value to [0, 100] and return as int."""
    return max(0, min(100, int(value)))


class RulesBasedQualityScorer:
    """The deterministic default quality scorer.

    The rules-based scorer walks the evidence record and
    checks the 4 user-named criteria (C1..C4) plus the 3
    bundled extras (C5..C7). It is the **load-bearing**
    scorer: production code uses this unless an operator
    swaps in an LLM-based ``quality-scorer`` specialist
    via ``DispatchExecutor(quality_scorer_fn=...)``.

    The scorer is side-effect free and does NOT call any
    subprocess or LLM. It runs in microseconds. The
    LLM-based scorer is an optional supplement for
    subjective criteria the rules can't capture.
    """

    def __init__(self, threshold: int = 90) -> None:
        self.threshold = int(threshold)

    def __call__(
        self,
        evidence: EvidenceBase,
        *,
        wave: str,
        handoff_id: str,
        threshold: int | None = None,
        retry_count: int = 0,
    ) -> PhaseQualityScore:
        # The constructor's threshold wins when the caller
        # doesn't pass an override. ``None`` is the sentinel
        # meaning "use the constructor's threshold".
        effective_threshold = (
            int(threshold) if threshold is not None else self.threshold
        )
        deductions: list[QualityDeduction] = []
        strengths: list[str] = []

        # C1: reachable address must have full URL.
        self._check_c1_reachable_address(evidence, deductions, strengths)
        # C2: open port must have host:port.
        self._check_c2_open_port_has_host_port(evidence, deductions, strengths)
        # C3: vulnerability must have a PoC.
        self._check_c3_vuln_has_poc(evidence, deductions, strengths)
        # C4: exploit success must have body analysis.
        self._check_c4_exploit_success_body_analysis(
            evidence, deductions, strengths
        )
        # C5/C6/C7: bundled extras.
        self._check_c5_missing_fields(evidence, deductions, strengths)
        self._check_c6_chain_metadata(evidence, deductions, strengths)
        self._check_c7_reachability_proof(evidence, deductions, strengths)

        # Cap the per-criterion total (so a 100-row ServiceEntry
        # list doesn't blow the score past 100).
        capped = self._cap_deductions(deductions)
        score = _score_to_int(100 - sum(d.points_deducted for d in capped))
        passed = score >= effective_threshold

        return PhaseQualityScore(
            target=evidence.target,
            wave=wave,
            handoff_id=handoff_id,
            score=score,
            threshold=effective_threshold,
            passed=passed,
            deductions=capped,
            strengths=strengths,
            recommendation=self._build_recommendation(
                passed, score, capped, strengths
            ),
            retry_count=retry_count,
        )

    # ----- criterion implementations ----------------------------------

    def _check_c1_reachable_address(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C1: ServiceEntry.reachability='reachable' AND
        PerTargetFinding.status in {owned, partial} MUST
        carry a complete URL or host:port.
        """
        if isinstance(evidence, ReconEvidence):
            for i, svc in enumerate(evidence.services):
                if svc.reachability == "reachable":
                    if not svc.url and not svc.host_port:
                        deductions.append(QualityDeduction(
                            criterion_id="C1",
                            criterion_name=(
                                "reachable_address_must_have_full_url"
                            ),
                            points_deducted=30,
                            detail=(
                                f"ServiceEntry services[{i}] "
                                f"(host={svc.host}, port={svc.port}, "
                                f"service={svc.service}) is marked "
                                f"reachability='reachable' but has "
                                f"neither url nor host_port. "
                                f"Operators can't reproduce the "
                                f"reachability check."
                            ),
                            affected_field=f"services[{i}]",
                            recommendation=(
                                f"Set ServiceEntry.url to "
                                f"'http://{svc.host}:{svc.port}"
                                f"/<observed-path>' (e.g. "
                                f"'/metrics' for Prometheus) "
                                f"AND set host_port to "
                                f"'{svc.host}:{svc.port}'."
                            ),
                        ))
                    else:
                        strengths.append(
                            f"Services[{i}] {svc.host}:{svc.port} "
                            f"has complete address "
                            f"(url={svc.url or '<none>'}, "
                            f"host_port={svc.host_port or '<none>'})"
                        )
        if isinstance(evidence, ReportEvidence):
            for i, f in enumerate(evidence.per_target_finding):
                if f.status in ("owned", "partial"):
                    if not f.reachability_url and not f.reachability_host_port:
                        deductions.append(QualityDeduction(
                            criterion_id="C1",
                            criterion_name=(
                                "reachable_address_must_have_full_url"
                            ),
                            points_deducted=30,
                            detail=(
                                f"PerTargetFinding[{i}] "
                                f"(entry_id={f.entry_id}, status="
                                f"{f.status}) has no "
                                f"reachability_url or "
                                f"reachability_host_port. The W8 "
                                f"report row has no copy-paste-"
                                f"able target."
                            ),
                            affected_field=(
                                f"per_target_finding[{i}]"
                            ),
                            recommendation=(
                                f"Copy the upstream ServiceEntry.url "
                                f"or ServiceEntry.host_port into "
                                f"reachability_url / "
                                f"reachability_host_port."
                            ),
                        ))

    def _check_c2_open_port_has_host_port(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C2: every ServiceEntry / Foothold with a port
        field must also have a complete host:port or URL.
        """
        if isinstance(evidence, ReconEvidence):
            for i, svc in enumerate(evidence.services):
                if svc.host_port or svc.url:
                    # C1 already covers this; skip.
                    continue
                # If we get here the service has a host+port
                # but no canonical host_port/url string. The
                # 51ifind.com W8 report kept surfacing rows
                # like "port 9090 open" with no host info.
                if svc.host and svc.port:
                    deductions.append(QualityDeduction(
                        criterion_id="C2",
                        criterion_name=(
                            "open_port_must_have_host_port"
                        ),
                        points_deducted=20,
                        detail=(
                            f"ServiceEntry services[{i}] reports "
                            f"port {svc.port} open on host "
                            f"{svc.host} but has no canonical "
                            f"host_port / url string. W8 report "
                            f"renders incomplete rows."
                        ),
                        affected_field=f"services[{i}]",
                        recommendation=(
                            f"Set ServiceEntry.host_port to "
                            f"'{svc.host}:{svc.port}' "
                            f"(and url when HTTP/HTTPS is "
                            f"observed)."
                        ),
                    ))

    def _check_c3_vuln_has_poc(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C3: every PenetrationFinding MUST have at least
        one reproduce_steps entry with command + observed
        + outcome_match=True.
        """
        if not isinstance(evidence, PenetrationEvidence):
            return
        for i, f in enumerate(evidence.findings):
            if f.status not in ("owned", "confirmed", "partial"):
                continue
            if not f.reproduce_steps:
                deductions.append(QualityDeduction(
                    criterion_id="C3",
                    criterion_name="vulnerability_must_have_poc",
                    points_deducted=25,
                    detail=(
                        f"Finding findings[{i}] "
                        f"(entry_id={f.entry_id}, status="
                        f"{f.status}, title={f.title!r}) has "
                        f"no reproduce_steps. A vuln claim "
                        f"without a runnable PoC is a fake "
                        f"vuln."
                    ),
                    affected_field=(
                        f"findings[{i}].reproduce_steps"
                    ),
                    recommendation=(
                        "Add at least one ReproduceStep with "
                        "tool=curl, command=<verbatim curl>, "
                        "expected_outcome=<what you expect>, "
                        "observed_outcome=<what you saw>, "
                        "outcome_match=True. Re-run the command "
                        "yourself to confirm."
                    ),
                ))
                continue
            # At least one step exists; check that at least
            # one has a real command and a match=True.
            has_match = any(
                s.outcome_match is True and s.command
                for s in f.reproduce_steps
            )
            if not has_match:
                deductions.append(QualityDeduction(
                    criterion_id="C3",
                    criterion_name="vulnerability_must_have_poc",
                    points_deducted=15,
                    detail=(
                        f"Finding findings[{i}] "
                        f"(entry_id={f.entry_id}) has "
                        f"reproduce_steps but none has "
                        f"outcome_match=True. The PoC is "
                        f"unverified."
                    ),
                    affected_field=(
                        f"findings[{i}].reproduce_steps[*]"
                    ),
                    recommendation=(
                        "Re-run at least one reproduce_step "
                        "command yourself and set "
                        "outcome_match=True when the output "
                        "matches expected_outcome. The "
                        "runtime verifier (SubprocessFinding"
                        "Verifier) will also re-run the "
                        "command and downgrade "
                        "unverified findings."
                    ),
                ))
            else:
                strengths.append(
                    f"Finding findings[{i}] "
                    f"(entry_id={f.entry_id}) has verified "
                    f"reproduce_steps."
                )

    def _check_c4_exploit_success_body_analysis(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C4: every owned finding MUST have body-content
        verification (Issue 5) AND runtime verifier
        confirmation.
        """
        if not isinstance(evidence, PenetrationEvidence):
            return
        for i, f in enumerate(evidence.findings):
            if f.status != "owned":
                continue
            # Body-content markers present?
            has_failure_markers = any(
                s.failure_markers
                for s in f.reproduce_steps
            )
            has_required_substrings = any(
                s.body_required_substrings
                for s in f.reproduce_steps
            )
            if not (has_failure_markers and has_required_substrings):
                deductions.append(QualityDeduction(
                    criterion_id="C4",
                    criterion_name=(
                        "exploit_success_must_have_body_analysis"
                    ),
                    points_deducted=35,
                    detail=(
                        f"Finding findings[{i}] "
                        f"(entry_id={f.entry_id}, status=owned) "
                        f"is missing body-content verification. "
                        f"has_failure_markers="
                        f"{has_failure_markers}, "
                        f"has_required_substrings="
                        f"{has_required_substrings}. A 200-OK-"
                        f"with-failed-body claim is the "
                        f"canonical fake vuln (Issue 5)."
                    ),
                    affected_field=(
                        f"findings[{i}].reproduce_steps[*]"
                    ),
                    recommendation=(
                        "For every owned finding, add "
                        "failure_markers (e.g. "
                        "['login failed', "
                        "'\\\"success\\\":false']) AND "
                        "body_required_substrings (e.g. "
                        "['admin@victim.local', "
                        "'role\\\":\\\"admin']) to at "
                        "least one reproduce_step. The "
                        "SubprocessFindingVerifier re-runs "
                        "the command and rejects 200-OK-with-"
                        "failed-body."
                    ),
                ))
                continue
            # Runtime verifier confirmation?
            if f.verified is not True:
                deductions.append(QualityDeduction(
                    criterion_id="C4",
                    criterion_name=(
                        "exploit_success_must_have_body_analysis"
                    ),
                    points_deducted=20,
                    detail=(
                        f"Finding findings[{i}] "
                        f"(entry_id={f.entry_id}, status=owned) "
                        f"has body-content markers but the "
                        f"runtime verifier did NOT confirm it "
                        f"(verified={f.verified}). The "
                        "executor likely downgraded it. "
                        "Re-run the command and check the "
                        "verifier log."
                    ),
                    affected_field=(
                        f"findings[{i}].verified"
                    ),
                    recommendation=(
                        "Check verification_artifact for "
                        "the verifier's log. If the verifier "
                        "rejected the finding, fix the "
                        "command / body markers and re-run. "
                        "If the verifier was disabled, "
                        "enable it via "
                        "DispatchExecutor(verifier_fn="
                        "SubprocessFindingVerifier())."
                    ),
                ))
            else:
                strengths.append(
                    f"Finding findings[{i}] "
                    f"(entry_id={f.entry_id}) has body-content "
                    f"verification AND runtime verifier "
                    f"confirmation (verified=True)."
                )

    def _check_c5_missing_fields(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C5: required schema fields MUST be populated."""
        if isinstance(evidence, ReconEvidence):
            for i, svc in enumerate(evidence.services):
                if svc.reachability == "reachable" and not svc.reachability_proof:
                    deductions.append(QualityDeduction(
                        criterion_id="C5",
                        criterion_name="missing_evidence_fields",
                        points_deducted=8,
                        detail=(
                            f"ServiceEntry services[{i}] "
                            f"({svc.host}:{svc.port}) is marked "
                            f"reachable but reachability_proof "
                            f"is empty. W8 report can't explain "
                            f"WHY we believe it's live."
                        ),
                        affected_field=(
                            f"services[{i}].reachability_proof"
                        ),
                        recommendation=(
                            "Set reachability_proof to the "
                            "raw evidence (e.g. '9090 returned "
                            "JSON {status:ok}', 'banner: "
                            "OpenSSH_8.2', 'TCP handshake "
                            "completed')."
                        ),
                    ))

    def _check_c6_chain_metadata(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C6: findings claiming chain deps MUST have the
        chain_id populated AND at least one of follows_from
        / enables.
        """
        if not isinstance(evidence, PenetrationEvidence):
            return
        for i, f in enumerate(evidence.findings):
            if not f.chain_id:
                continue
            if not (f.follows_from or f.enables):
                deductions.append(QualityDeduction(
                    criterion_id="C6",
                    criterion_name="incomplete_chain_metadata",
                    points_deducted=8,
                    detail=(
                        f"Finding findings[{i}] "
                        f"(entry_id={f.entry_id}) has "
                        f"chain_id={f.chain_id!r} but neither "
                        f"follows_from nor enables. The chain "
                        f"is a vague pointer."
                    ),
                    affected_field=f"findings[{i}].chain_id",
                    recommendation=(
                        "Populate follows_from with the "
                        "entry_ids this depends on (e.g. "
                        "['V001']) and enables with the "
                        "entry_ids this makes possible."
                    ),
                ))

    def _check_c7_reachability_proof(
        self,
        evidence: EvidenceBase,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> None:
        """C7: every reachable service MUST have
        reachability_proof."""
        # Already covered by C5 for ReconEvidence; this
        # is the same criterion under a different ID for
        # future cross-schema use. Kept as a no-op stub so
        # QUALITY_CRITERIA stays a closed set.
        return

    # ----- helpers -------------------------------------------------------

    def _cap_deductions(
        self, deductions: list[QualityDeduction]
    ) -> list[QualityDeduction]:
        """Cap the per-criterion total so a 100-row evidence
        record with 100 hits of C1 doesn't compound to
        -3000. Each criterion's total deduction is bounded
        by ``max_deduction_per_criterion``.
        """
        by_id: dict[str, list[QualityDeduction]] = {}
        for d in deductions:
            by_id.setdefault(d.criterion_id, []).append(d)
        capped: list[QualityDeduction] = []
        for cid, items in by_id.items():
            cap = QUALITY_CRITERIA[cid].max_deduction_per_criterion
            if len(items) == 1:
                capped.append(items[0])
                continue
            total = sum(d.points_deducted for d in items)
            if total > cap:
                # Cap at the max; collapse to one entry.
                capped.append(QualityDeduction(
                    criterion_id=cid,
                    criterion_name=items[0].criterion_name,
                    points_deducted=cap,
                    detail=(
                        f"{len(items)} hits of {cid} cap'd at "
                        f"{cap} points. " + items[0].detail
                    ),
                    affected_field=items[0].affected_field,
                    recommendation=items[0].recommendation,
                ))
            else:
                capped.extend(items)
        return capped

    def _build_recommendation(
        self,
        passed: bool,
        score: int,
        deductions: list[QualityDeduction],
        strengths: list[str],
    ) -> str:
        if passed:
            return (
                f"Phase passed at {score}/100. "
                "All criteria satisfied. Proceed to next wave."
            )
        if not deductions:
            return (
                f"Phase failed at {score}/100 but no deductions "
                "were recorded. Re-run the specialist with a "
                "more verbose evidence record."
            )
        first_three = deductions[:3]
        lines = [
            f"Phase FAILED at {score}/100 (threshold="
            f"{self.threshold}). Fix these "
            f"{len(deductions)} deduction(s) and re-run:"
        ]
        for d in first_three:
            lines.append(
                f"  - [{d.criterion_id}] {d.criterion_name} "
                f"(-{d.points_deducted}): {d.detail}"
            )
            if d.recommendation:
                lines.append(f"    → {d.recommendation}")
        if len(deductions) > 3:
            lines.append(
                f"  ... and {len(deductions) - 3} more."
            )
        if strengths:
            lines.append("")
            lines.append("Preserve these strengths:")
            for s in strengths[:3]:
                lines.append(f"  + {s}")
        return "\n".join(lines)


__all__ = [
    "EXTRA_CRITERIA",
    "PhaseQualityScorerFn",
    "QUALITY_CRITERIA",
    "QualityCriterion",
    "RulesBasedQualityScorer",
    "USER_CRITERIA",
]
