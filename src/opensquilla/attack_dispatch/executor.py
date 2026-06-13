"""Synchronous, testable wave executor.

The executor drives the wave DAG step by step:

  1. For each parent wave, build the Typed Envelope(s) for its specialist(s)
  2. Resolve the fan-out (single / static / dynamic) from upstream evidence
  3. Call each specialist via the injected callable
  4. Validate the returned evidence against its schema
  5. **Persist the validated evidence to a per-session artifact file** at
     ``<artifact_root>/<wave>/<handoff_id>.json`` (2026-06-07). The file
     is the durable source-of-truth for the next wave's context — it
     survives process restarts, LLM context evictions, and the
     orchestrator's own memory. The path is recorded in
     ``state.evidence_paths[wave]`` and exposed to downstream waves via
     ``HandoffEnvelope.input_artifacts``.
  6. Decide whether to drill-in (Wn.5a / b / c)
  7. If drill-in, repeat steps 1-5 for the drill-in slot (drill-in
     artifacts land at ``<artifact_root>/<wave>.drill_in/<slot>.json``)
  8. Move to the next wave only when all deps' evidence is present
     (barrier)

A ``specialist_fn`` is a sync callable:

    specialist_fn(envelope: HandoffEnvelope, brief: str) -> dict

It returns a dict that the executor validates against the wave's
``evidence_schema``. The executor is **asset-agnostic** — there is no
hardcoded max for subdomains / ports / findings.

The executor is designed to be driven either by real ``sessions_spawn``
calls (in production) or by in-memory test doubles (in unit tests).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

from opensquilla.attack_dispatch.drill_in import (
    DEFAULT_THINNESS_THRESHOLD,
    DrillInDecision,
    DrillInSpec,
    build_emit_new_target_spec,
    decide_drill_in,
)
from opensquilla.attack_dispatch import trail as _trail_mod
from opensquilla.attack_dispatch.envelope import HandoffEnvelope
from opensquilla.attack_dispatch.evidence import (
    EVIDENCE_SCHEMAS,
    EVIDENCE_SCHEMA_NAMES,
    EvidenceBase,
    PenetrationEvidence,
    PenetrationFinding,
    ReconEvidence,
    SubTargetHandleList,
    make_evidence,
)
from opensquilla.attack_dispatch.verifier import (
    DEFAULT_VERIFIER_TIMEOUT_S,
    FindingVerifierFn,
    SubprocessFindingVerifier,
    VerifyResult,
)
from opensquilla.attack_dispatch.waves import (
    LAYERS,
    WAVE_NAMES,
    WAVES,
    DRILL_IN_SLOTS,
    WaveSpec,
    get_wave,
    is_drill_in_allowed,
    list_drill_in_slots,
)


# Dynamic fan-out: how many entry buckets per penetration sub-track.
SUB_TRACK_BUCKET_SIZE = 8

# Default per-step artifact archive root. Production code (hack-deep) runs
# against this; tests can pass a tmp_path to keep the real workspace clean.
DEFAULT_ARTIFACT_ROOT = Path.home() / ".opensquilla" / "agents" / "hack-deep" / "memory" / "waves"


# ---------------------------------------------------------------------------
# Callable type + dispatch mode
# ---------------------------------------------------------------------------


class DispatchMode(str, Enum):
    """Concurrency mode for fan-out waves (v3.2, 2026-06-07).

    PARALLEL — default. The executor's ``for env in envelopes:`` loop is
      already sequential at the Python level; the LLM layer is the
      actually-parallel layer (multiple ``sessions_spawn`` in one
      assistant message). The merged per-wave artifact is written ONCE
      at the end of the wave.

    SERIAL — opt-in. The executor persists EACH specialist's raw output
      to a per-specialist JSON file BEFORE invoking the next specialist,
      and fires a ``context_reduction`` callback (if injected) so the
      LLM can release the raw from its context. A combined per-wave
      artifact is still written at the end (slim summary + a
      ``per_specialist_artifacts`` map). This is the context-window
      saving path: at any time, only one specialist's raw is in flight.
    """

    PARALLEL = "parallel"
    SERIAL = "serial"


# A specialist is a sync function that takes the envelope + brief, and
# returns a dict (the unvalidated evidence) OR an EvidenceBase instance.
SpecialistFn = Callable[[HandoffEnvelope, str], dict | EvidenceBase]


# Fired by the executor in SERIAL mode after each specialist's raw has
# been persisted to disk. Production hack-deep LLM can use this to
# discard the raw from its context and keep only the path + a short
# summary. The callback is informational — it does not affect the
# executor's behavior. Parameters:
#   wave:          parent wave id (e.g. "W1") or drill-in slot (e.g. "W1.6a")
#   handoff_id:    the specialist's full handoff id (e.g. "W1.recon.1")
#   artifact_path: absolute path to the per-specialist JSON file
#   raw:           the raw dict (or EvidenceBase) the specialist returned
ContextReductionFn = Callable[[str, str, Path, Any], None]


# ---------------------------------------------------------------------------
# State / Result
# ---------------------------------------------------------------------------


@dataclass
class DispatchState:
    """Blackboard shared across waves.

    The executor never assumes a fixed maximum count for any field — every
    collection on this state is a list of arbitrary length.
    """

    evidence: dict[str, EvidenceBase] = field(default_factory=dict)
    """wave_id -> validated evidence record"""

    evidence_paths: dict[str, str] = field(default_factory=dict)
    """wave_id -> absolute path to the persisted per-session artifact
    file written by the executor (2026-06-07). Surfaced to downstream
    waves via ``HandoffEnvelope.input_artifacts`` so the next specialist
    can read its context from disk instead of relying on the in-memory
    state alone. Keys match the parent wave (e.g. ``W1``); per-fanout
    sub-session paths live under ``<wave>/<handoff_id>.json`` but are
    not tracked here."""

    drill_ins: list[DrillInSpec] = field(default_factory=list)
    """All drill-in specs triggered, in order (both thinness-driven and
    emit_new_target from raw output)."""

    fanout_counts: dict[str, int] = field(default_factory=dict)
    """wave_id -> number of specialist calls made (1 for single, N for fanout)"""

    raw_calls: list[dict[str, Any]] = field(default_factory=list)
    """Audit log: one entry per specialist invocation (envelope + brief + raw output)"""

    errors: list[str] = field(default_factory=list)

    drill_in_overlay: dict[str, dict[str, Any]] = field(
        default_factory=dict,
        # 2026-06-07: parent_wave -> shallow-merged drill-in raw output.
        # Drill-in raws are recorded here WITHOUT overwriting the parent's
        # evidence record. The orchestrator can read this to see what the
        # drill-in found.
    )

    target_queue: list[str] = field(
        default_factory=list,
        # 2026-06-07: subdomain / asset targets pushed by W4/W5/W6
        # emit_new_target raw outputs. The orchestrator (LLM) re-spawns
        # W1.5 / W1 on these targets.
    )

    released_handoff_ids: set[str] = field(
        default_factory=set,
        # v3.2 (2026-06-07, serial mode): the set of specialist handoff_ids
        # whose raw has been persisted to a per-specialist artifact and
        # whose context_reduction callback (if any) has been fired. The
        # LLM may safely discard these raws from its in-context state.
        # Populated only when running with ``DispatchMode.SERIAL``.
    )

    specialist_artifacts: dict[str, str] = field(
        default_factory=dict,
        # v3.2 (2026-06-07, serial mode): handoff_id -> absolute path of
        # the per-specialist JSON file written in SERIAL mode. Populated
        # only when running with ``DispatchMode.SERIAL``; for drill-in
        # slots the handoff_id is the slot name (e.g. "W1.6a").
    )

    # 2026-06-08 (Issue 3): per-subdomain driver bookkeeping.
    # Populated by ``run_per_subdomain``; empty in the single-pass
    # path. The verifier (Issue 2) reads ``subdomain_artifact_roots``
    # to write per-finding logs to the per-subdomain tree; the
    # manifest writer reads ``per_subdomain_results`` to emit the
    # ``subdomain_index`` field.
    per_subdomain_results: dict[str, list["WaveResult"]] = field(
        default_factory=dict,
    )
    subdomain_artifact_roots: dict[str, str] = field(
        default_factory=dict,
    )


@dataclass
class WaveResult:
    """The outcome of one (parent or drill-in) wave run."""

    wave: str
    layer: str
    specialist_calls: int
    evidence: EvidenceBase | None
    drill_in: DrillInDecision | None
    error: str | None = None
    drill_in_merged: bool = False
    # 2026-06-07: True if any drill-in slot ran under this parent and
    # contributed a raw record to state.drill_in_overlay[parent_wave].

    drill_in_overlay: dict[str, Any] = field(default_factory=dict)
    # 2026-06-07: the shallow-merged drill-in raw output for this parent.
    # Empty when no drill-in ran.

    mode: DispatchMode = DispatchMode.PARALLEL
    # v3.2 (2026-06-07): the dispatch mode under which this wave ran.
    # SERIAL means per-specialist artifacts were written and the
    # context_reduction callback was fired after each specialist.

    specialist_artifacts: dict[str, str] = field(default_factory=dict)
    # v3.2 (2026-06-07, serial mode): handoff_id -> absolute path of
    # the per-specialist JSON file written in SERIAL mode. Empty in
    # PARALLEL mode (the combined per-wave artifact is in
    # state.evidence_paths[wave]).

    # 2026-06-08 (Issue 2): runtime verification counters. Populated
    # by ``_verify_pentest_findings`` for waves that produce
    # ``PenetrationEvidence`` (i.e. W4 and its drill-ins). Both default
    # to 0 for non-W4 waves.
    findings_verified: int = 0
    findings_downgraded: int = 0

    # 2026-06-09 (Issue 11): phase quality score. Populated by
    # the executor's score gate. ``None`` when the scorer is
    # disabled or hasn't run yet. When populated, the
    # orchestrator (LLM) reads ``quality_score.passed`` to
    # decide whether to re-spawn the specialist. The score
    # report is also persisted in the per-wave artifact so
    # the W8 reporting specialist can render the score
    # ledger in the operator-facing report.
    quality_score: "PhaseQualityScore | None" = None
    # 2026-06-09 (Issue 11): how many times this wave was
    # retried due to low score. Capped at
    # ``quality_max_retries`` (default 3).
    quality_retry_count: int = 0


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


# v3.2 (2026-06-07): W4 penetration sub-track brief — pentest-specific
# reminder + result-marker footer. Lives at module scope (not a method)
# because _make_brief calls it without `self`. The brief is much more
# detailed than the W4 placeholder it replaces: it explicitly names the
# fields the LLM must fill, enumerates the PTES-aligned methodology
# steps, and ends with a strong RESULT MARKER reminder (the 2026-06-07
# hack-deep W4.1 V001 IDOR incident).
# v3.2 (2026-06-07): W4 penetration sub-track brief footer.
# The pure-prose part used to be an inline triple-quoted string in this
# file. Extracted to a sibling .md so editors can syntax-highlight,
# linters can validate, and diffs stay small. State-dependent parts
# (header, W2 triage inline, W3 opsec inline) stay in
# ``_build_w4_pentest_subtrack_brief`` because they require
# ``state.evidence`` lookups at call time.
_W4_PENTEST_BRIEF_FOOTER = (
    Path(__file__).resolve().parent
    / "_templates"
    / "penetration_brief_footer.md"
).read_text(encoding="utf-8")


# v3.3 (2026-06-08): W7 persistence-maintenance sub-track brief
# footer. Mirrors the W4 footer pattern: extracted to a sibling .md
# so editors can syntax-highlight + diffs stay small. Driven by the
# 2026-06-08 W7 session optimization report (10 pain points from
# the 51ifind.com pressure test). The schema is now fully typed
# (TopologyHop / OutputTarget / PassCriterion / VerificationTiming /
# PersistenceOption), and the brief enumerates every field the LLM
# must fill, plus a pre-flight checklist that prevents the
# "试了 10+ curl 才发现正确路由" anti-pattern.
_W7_PERSIST_BRIEF_FOOTER = (
    Path(__file__).resolve().parent
    / "_templates"
    / "persistence_brief_footer.md"
).read_text(encoding="utf-8")



def _build_w4_pentest_subtrack_brief(
    env: HandoffEnvelope,
    state: DispatchState,
    target_str: str,
) -> str:
    """Build the v3.2 W4 penetration sub-track brief.

    v3.1 had a one-liner placeholder that was a major root cause of
    the 2026-06-07 hack-deep W4.1 incident — the LLM had no schema
    detail and no marker reminder. v3.2 expands to a 80-line brief
    that:
      - reads W2 triage findings + W3 opsec strategy from upstream
        artifacts and surfaces the key fields inline
      - tells the LLM exactly which fields to fill (15 numbered
        items, mirroring the PenetrationFinding model)
      - reminds the LLM that the schema is now fully typed
      - ends with a strong RESULT MARKER footer that the LLM cannot
        reasonably miss.

    The footer is the most defensive piece. The runtime already
    auto-appends a synthetic marker if the LLM forgets
    (synthesize_marker in attack_dispatch.envelope), but a real
    marker with a real schema is always preferred.
    """
    entry_count = DispatchExecutor._count_entries(state)
    n_sub = max(1, entry_count // SUB_TRACK_BUCKET_SIZE)

    # Surface W2 triage findings + W3 opsec strategy as inline hints.
    triage_lines: list[str] = []
    triage = state.evidence.get("W2")
    if triage is not None and getattr(triage, "prioritized_top_n", None):
        triage_lines.append("")
        triage_lines.append("## Upstream triage (W2, top-N)")
        for i, cand in enumerate(triage.prioritized_top_n[:5], start=1):
            triage_lines.append(
                f"{i}. {cand.get('id', '?')} — {cand.get('name', '?')} "
                f"(CVSS {cand.get('cvss', '?')}, vector {cand.get('vector_class', '?')})"
            )
    opsec = state.evidence.get("W3")
    if opsec is not None and getattr(opsec, "per_target_group", None):
        triage_lines.append("")
        triage_lines.append("## OpSec strategy (W3, per-target-group)")
        for g in opsec.per_target_group[:3]:
            triage_lines.append(
                f"- group_id={g.group_id}  strategy={g.strategy}  "
                f"stop_signal={g.stop_signal}"
            )

    header = (
        f"Penetration sub-track {env.handoff_id} of {n_sub} "
        f"(W4 fan-out, vector_class = {env.handoff_id.split('.')[1] if '.' in env.handoff_id else 'unknown'}). "
        f"Target: {target_str}. "
        f"Sub-track covers ~{SUB_TRACK_BUCKET_SIZE} W1 services from your share "
        f"of the W4 entry bucket."
    )

    parts = [header]
    if triage_lines:
        parts.append("\n".join(triage_lines))
    parts.append(_W4_PENTEST_BRIEF_FOOTER)

    return "\n".join(parts)


# v3.2 (2026-06-07): W4 penetration sub-track brief — pentest-specific
# reminder + result-marker footer. Lives at module scope (not a method)
# because _make_brief calls it without `self`. The brief is much more
# detailed than the W4 placeholder it replaces: it explicitly names the
# fields the LLM must fill, enumerates the PTES-aligned methodology
# steps, and ends with a strong RESULT MARKER reminder (the 2026-06-07
# hack-deep W4.1 V001 IDOR incident).

# v3.3 (2026-06-08): W7 persistence-maintenance sub-track brief
# footer. Same pattern as W4 — extracted to a sibling .md so editors
# can syntax-highlight + diffs stay small. State-dependent parts
# (header, W6 lateral inline, footholds inline) stay in
# ``_build_w7_persist_brief`` because they require
# ``state.evidence`` lookups at call time.


def _build_w7_persist_brief(
    env: HandoffEnvelope,
    state: DispatchState,
    target_str: str,
) -> str:
    """Build the v3.3 W7 persistence-maintenance sub-track brief.

    v3.2 (and earlier) had a one-line W7 brief that was a major root
    cause of the 2026-06-08 W7 session pain points — the LLM had no
    schema detail, no topology-first instruction, no output-target
    guidance, no antipattern list, no parallel-verification
    reminder, and no RESULT MARKER footer. v3.3 expands to a
    multi-section brief that:
      - reads W6 lateral evidence + W4 footholds from upstream
        artifacts and surfaces the key foothold_ids inline
      - tells the LLM exactly which fields to fill (15 numbered
        items, mirroring the PersistenceOption model)
      - mandates a pre-flight checklist before any curl runs
      - ends with a strong RESULT MARKER footer.

    The footer is the most defensive piece. The runtime already
    auto-appends a synthetic marker if the LLM forgets
    (synthesize_marker in attack_dispatch.envelope), but a real
    marker with a real schema is always preferred.
    """
    # Surface W6 lateral pivot points + W4 footholds as inline hints
    # so the LLM doesn't have to re-discover the topology each time.
    upstream_lines: list[str] = []
    lateral = state.evidence.get("W6")
    if lateral is not None and getattr(lateral, "pivot_points", None):
        upstream_lines.append("")
        upstream_lines.append("## Upstream lateral (W6, pivot points)")
        for i, p in enumerate(lateral.pivot_points[:5], start=1):
            upstream_lines.append(
                f"{i}. {p.get('host', '?')}:{p.get('port', '?')} "
                f"({p.get('type', '?')}) — access={p.get('access', '?')}"
            )
    pentest = state.evidence.get("W4")
    if pentest is not None and getattr(pentest, "footholds", None):
        upstream_lines.append("")
        upstream_lines.append("## Upstream footholds (W4, persistence candidates)")
        for i, fh in enumerate(pentest.footholds[:5], start=1):
            upstream_lines.append(
                f"{i}. foothold_id={fh.get('foothold_id', '?')} "
                f"type={fh.get('type', '?')} "
                f"host={fh.get('target_host', '?')}:{fh.get('target_port', '?')} "
                f"user={fh.get('target_user', '?')} "
                f"level={fh.get('persistence_level', '?')}"
            )

    header = (
        f"Persistence sub-track {env.handoff_id}. "
        f"Target: {target_str}. "
        f"Output schema: persist-v1 (typed — see evidence.py). "
        f"Required: topology_map FIRST, then output_target + "
        f"expected_behavior + antipatterns + pass_criteria, "
        f"then ONE verification_script with verification_timing "
        f"set for any file/DB write. Run 4 verifications in parallel."
    )

    parts = [header]
    if upstream_lines:
        parts.append("\n".join(upstream_lines))
    parts.append(_W7_PERSIST_BRIEF_FOOTER)

    return "\n".join(parts)



class DispatchExecutor:
    """Drive the 4-layer × 9-wave DAG end-to-end (or one wave at a time).

    Usage:
        executor = DispatchExecutor(specialist_fn=my_specialist)
        results = executor.run(target="51ifind.com")
        # or
        result = executor.run_wave("W4", state)

    The executor is sync, deterministic given the specialist function, and
    fully testable without any real target.
    """

    def __init__(
        self,
        specialist_fn: SpecialistFn,
        *,
        thinness_threshold: float = DEFAULT_THINNESS_THRESHOLD,
        peer_attach_fn: Callable[[str], EvidenceBase | None] | None = None,
        artifact_root: Path | None = None,
        mode: DispatchMode = DispatchMode.PARALLEL,
        context_reduction: ContextReductionFn | None = None,
        auto_approve_specialists: bool = False,
        verifier_fn: FindingVerifierFn | bool | None = None,
        per_subdomain: bool = False,
        skip_w15: bool = True,
        quality_scorer_fn: "PhaseQualityScorerFn | None" = None,
        quality_threshold: int = 90,
        quality_max_retries: int = 3,
    ) -> None:
        self.specialist_fn = specialist_fn
        self.thinness_threshold = thinness_threshold
        # Optional hook used by run() to attach cyberstrike-deep's W0
        # evidence when both deeps are running on the same target.
        # Production (hack-deep) injects a real implementation that talks
        # to session_manager + storage; tests inject a mock.
        self.peer_attach_fn = peer_attach_fn
        # 2026-06-07: per-step artifact archive root. After each wave's
        # evidence is validated, the executor writes a JSON file at
        # ``<artifact_root>/<wave>/<handoff_id>.json`` and records the
        # path in ``state.evidence_paths[wave]``. The next wave's
        # envelope ``input_artifacts`` field is populated from this
        # mapping. Default points at the hack-deep workspace; tests pass
        # ``tmp_path`` to keep the real workspace clean.
        self.artifact_root: Path = (
            artifact_root if artifact_root is not None else DEFAULT_ARTIFACT_ROOT
        )
        # v3.2 (2026-06-07): dispatch concurrency mode. PARALLEL (default)
        # preserves the original behavior: one combined per-wave artifact
        # at the end of the wave. SERIAL persists each specialist's raw
        # to a per-specialist file BEFORE the next specialist runs, and
        # fires ``context_reduction`` (if set) so the LLM can release the
        # raw from its context window. Both modes write the combined
        # per-wave artifact; SERIAL additionally includes a
        # ``per_specialist_artifacts`` map in that combined file.
        self.mode: DispatchMode = mode
        # v3.2 (2026-06-07, serial mode only): optional callback fired
        # after each specialist's raw is persisted. See ContextReductionFn
        # for the signature. Safe to leave None — the executor still
        # writes the per-specialist files.
        self.context_reduction: ContextReductionFn | None = context_reduction
        # 2026-06-08 (Issue 1): session-level default for the
        # ``HandoffEnvelope.auto_approve`` field. When True, every
        # envelope built by this executor carries ``auto_approve=True``
        # unless the per-envelope kwarg overrides. The
        # ``sessions_spawn`` gateway reads this and sets
        # ``ToolContext.auto_approve_specialists=True`` on the child,
        # which causes the shell approval pipeline to return a
        # synthetic ``approval_denied`` envelope instead of raising
        # ``UnsupportedSurfaceError`` (the latter would block the W4
        # specialist). Default False keeps the cyberstrike-deep
        # default and the v3.2 test suite unchanged.
        self.auto_approve_specialists: bool = auto_approve_specialists
        # 2026-06-08 (Issue 2): runtime finding verifier. The
        # 3-valued param:
        #  - ``None`` (default) → install the default
        #    :class:`SubprocessFindingVerifier` (re-executes
        #    ``reproduce_steps[0].command`` and substring-matches the
        #    output against ``expected_outcome``).
        #  - callable matching :data:`FindingVerifierFn` → use that
        #    verifier (e.g. a dry-run mock in tests, or a custom
        #    verifier that wraps sqlmap in a sandbox).
        #  - ``False`` → skip verification entirely (the "sentinel"
        #    form; tests and the v3.2 / cyberstrike paths that don't
        #    want subprocess side-effects use this).
        if verifier_fn is None:
            self.verifier_fn: FindingVerifierFn | None = SubprocessFindingVerifier()
            self.verifier_disabled: bool = False
        elif verifier_fn is False:
            self.verifier_fn = None
            self.verifier_disabled = True
        else:
            self.verifier_fn = verifier_fn
            self.verifier_disabled = False
        # 2026-06-08 (Issue 3): per-subdomain driver toggle. When
        # True, ``run()`` delegates to ``run_per_subdomain``; the
        # existing single-pass path is preserved when False (the
        # default, which keeps cyberstrike-deep and the v3.2 test
        # suite unchanged). ``skip_w15`` controls whether the
        # per-subdomain driver runs the v3.2 W1.5 fan-out; the
        # default is True because the per-subdomain driver does its
        # own per-subdomain recon inline as W1.
        self.per_subdomain: bool = per_subdomain
        self.skip_w15: bool = skip_w15
        # 2026-06-09 (Issue 11 — phase quality scoring). After
        # every wave's evidence is built, the executor calls
        # ``quality_scorer_fn(evidence)`` which returns a
        # ``PhaseQualityScore``. Default is the deterministic
        # :class:`RulesBasedQualityScorer`; operators can swap
        # in an LLM-based ``quality-scorer`` specialist via
        # ``quality_scorer_fn=llm_scorer``. The scorer is
        # opt-out via ``quality_scorer_fn=False`` (sentinel) for
        # tests that don't care about scoring — same shape as
        # ``verifier_fn=False``.
        if quality_scorer_fn is None:
            from opensquilla.attack_dispatch.quality import (
                RulesBasedQualityScorer,
            )

            self.quality_scorer_fn = RulesBasedQualityScorer(
                threshold=quality_threshold
            )
            self.quality_scorer_disabled: bool = False
        elif quality_scorer_fn is False:
            self.quality_scorer_fn = None
            self.quality_scorer_disabled = True
        else:
            self.quality_scorer_fn = quality_scorer_fn
            self.quality_scorer_disabled = False
        self.quality_threshold: int = int(quality_threshold)
        self.quality_max_retries: int = int(quality_max_retries)
        # Per-wave retry counter; reset on each new wave.
        # ``_score_phase_quality`` reads / increments this.
        self._wave_retry_count: dict[str, int] = {}

    # -- public -------------------------------------------------------------

    def run(self, target: str, state: DispatchState | None = None) -> list[WaveResult]:
        """Run all 11 parent waves in DAG order, with barriers + drill-in
        + feedback loop scaffolding.

        If ``state`` is provided, evidence / drill-ins / errors accumulate
        into it (useful for inspection). If None, a fresh state is created.

        2026-06-07: at entry, calls ``_try_attach_to_peer_deep``; if a peer
        deep (cyberstrike-deep) is running on the same target, attaches
        its W0 evidence to ``state.evidence["W0_peer_attach"]`` so the
        orchestrator can pick up where it left off.

        Also writes a top-level run manifest at
        ``<artifact_root>/manifest.json`` so the orchestrator / report
        reader can reconstruct the full (stage, agent, session,
        file_path) routing table from one file.

        2026-06-08 (Issue 3): when the executor was constructed with
        ``per_subdomain=True``, ``run()`` delegates to
        :meth:`run_per_subdomain`. The single-pass path is the
        default; cyberstrike-deep and the v3.2 test suite continue
        to use it.
        """
        if getattr(self, "per_subdomain", False):
            return self._run_via_per_subdomain(target, state)
        if state is None:
            state = DispatchState()
        started_at = datetime.now(timezone.utc)
        # Ensure trail.md exists on disk before any wave runs so the
        # in-prompt hook (StepTrailRebuilderHook) can read it on the
        # first compaction. No-op if artifact_root is unwritable.
        self._maybe_rebuild_trail(state, target=target, started_at=started_at)
        # T14: peer attach (best-effort, no-op if no peer_attach_fn)
        peer_w0 = self._try_attach_to_peer_deep(target)
        if peer_w0 is not None:
            state.evidence["W0_peer_attach"] = peer_w0
        for wave in WAVE_NAMES:
            self.run_wave(wave, state, target=target)
        finished_at = datetime.now(timezone.utc)
        # Manifest write failure is non-fatal; the in-memory results are
        # still returned. The orchestrator decides whether to abort the
        # parent run on a missing manifest.
        manifest = self._write_run_manifest(
            target=target, state=state,
            started_at=started_at, finished_at=finished_at,
        )
        if manifest is not None:
            state.evidence_paths["__manifest__"] = str(manifest)
        return self._collect_results(state)

    def _run_via_per_subdomain(
        self,
        target: str,
        state: DispatchState | None,
    ) -> list[WaveResult]:
        """Helper: call ``run_per_subdomain`` and flatten its return to
        a single ``list[WaveResult]`` for the ``run()`` contract.

        The per-subdomain driver returns a ``dict[str, list[WaveResult]]``
        (subdomain → wave results). The ``run()`` contract is a flat
        list — this helper flattens and also writes a flat manifest
        in the existing single-file form so the W8 reporting specialist
        can read it the same way regardless of which path the executor
        took.
        """
        per = self.run_per_subdomain(target=target, state=state)
        flat: list[WaveResult] = []
        for key in sorted(per.keys()):
            flat.extend(per[key])
        return flat

    def run_per_subdomain(
        self,
        target: str,
        state: DispatchState | None = None,
    ) -> dict[str, list[WaveResult]]:
        """Per-subdomain full-pipeline driver (2026-06-08, Issue 3).

        After W0.5 produces a :class:`SubTargetHandleList`, runs the
        full W1 → W8 pipeline ONCE PER SUBDOMAIN, in order. W0 and
        W0.5 run ONCE for the main domain (the "prelude"); W1.5 is
        skipped by default (the per-subdomain driver does its own
        per-subdomain recon inline as W1 — turn the skip off with
        ``skip_w15=False`` to keep the v3.2 W1.5 fan-out).

        Each subdomain gets:
          - its own :class:`DispatchState` (``sub_state``)
          - its own evidence root: ``<artifact_root>/<subdomain>/``
          - its own combined per-wave artifact under that root
          - its own W8 final report (one per subdomain)

        W4's dynamic fan-out is sized locally per subdomain (the
        existing ``_count_entries_for_wave`` reads from the
        sub_state's W1 services list, not the engagement's
        aggregate). A subdomain with 2 services gets 1 sub-track;
        one with 16 services gets 2 sub-tracks.

        Returns a mapping ``subdomain → list[WaveResult]`` plus a
        ``"__prelude__"`` key for the W0/W0.5 wave results. The
        prelude's W0 evidence is injected into each sub_state so
        ``_make_brief`` can resolve ``target_str`` in the barrier
        check.

        The driver does NOT suppress errors: a per-subdomain W4
        failure still aborts that subdomain's pipeline, but other
        subdomains continue. The operator's view is N+1
        sub-engagements, each with its own trail / manifest slice.
        """
        if state is None:
            state = DispatchState()
        # 1) Run the prelude (W0 + W0.5) once for the main domain.
        prelude_state = state
        prelude_state.target_queue = list(prelude_state.target_queue)  # in-place safe
        # 1a) W0
        prelude_state.evidence.get("W0")  # may already exist (peer attach)
        if "W0" not in prelude_state.evidence:
            self.run_wave("W0", prelude_state, target=target)
        # 1b) W0.5
        if "W0.5" not in prelude_state.evidence:
            self.run_wave("W0.5", prelude_state, target=target)
        # 2) Read the subdomain handle list produced by W0.5.
        w05 = prelude_state.evidence.get("W0.5")
        if not isinstance(w05, SubTargetHandleList) or not w05.handles:
            # No subdomains discovered; fall back to the single-pass path.
            return {"__main__": self.run(target=target, state=state)}
        # 3) For each handle, in declared order, run W1→W8 with a
        #    per-subdomain state. The per-subdomain W4 fan-out is
        #    scoped to that subdomain's services.
        results: dict[str, list[WaveResult]] = {
            "__prelude__": [
                # Reconstruct prelude results from the state.evidence
                # keys for the manifest. The actual WaveResult objects
                # from the prelude path are not retained (the prelude
                # is short — 2 waves — and the run() call below would
                # overwrite them), so we record a minimal marker.
            ]
        }
        # Per-subdomain prelude slices (W0 + W0.5) are reflected via
        # prelude_state.evidence; readers that want the prelude's
        # full WaveResult can call run_wave directly.
        for handle in w05.handles:
            sub = handle.subdomain
            sub_state = DispatchState()
            # Inject the prelude's W0 evidence so target_str resolves
            # in the barrier check. (W0.5 is not a dep of any wave
            # in the per-subdomain loop; W1.5 is skipped.)
            if "W0" in prelude_state.evidence:
                sub_state.evidence["W0"] = prelude_state.evidence["W0"]
            sub_state.evidence["W0_subdomain_handle"] = handle
            sub_root = self.artifact_root / self._subdomain_dirname(sub)
            sub_state.subdomain_artifact_roots[sub] = str(sub_root)
            sub_results: list[WaveResult] = []
            # Optional W1.5 (off by default; the per-subdomain driver
            # does its own per-subdomain recon inline as W1).
            if not getattr(self, "skip_w15", True):
                sub_results.append(
                    self.run_wave("W1.5", sub_state, target=sub)
                )
            for wave in ("W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"):
                sub_results.append(
                    self.run_wave(wave, sub_state, target=sub)
                )
            results[sub] = sub_results
            # Mirror per-subdomain evidence back into the engagement
            # state so the W8 reporting specialist (which reads from
            # the engagement state) can see all subdomains.
            state.per_subdomain_results[sub] = sub_results
        # 4) Write a top-level manifest with the subdomain_index.
        started_at = datetime.now(timezone.utc)
        finished_at = datetime.now(timezone.utc)
        try:
            manifest = self._write_run_manifest(
                target=target, state=state,
                started_at=started_at, finished_at=finished_at,
            )
            if manifest is not None:
                state.evidence_paths["__manifest__"] = str(manifest)
        except OSError as exc:
            state.errors.append(f"per-subdomain manifest write failed: {exc}")
        # 5) Rebuild the trail so it surfaces the per-subdomain slices.
        self._maybe_rebuild_trail(state, target=target, started_at=started_at)
        return results

    @staticmethod
    def _subdomain_dirname(subdomain: str) -> str:
        """Compute the on-disk directory name for a subdomain (2026-06-08, Issue 3).

        Sanitizes the subdomain string so it can be used as a path
        component. The transformation is intentionally reversible
        (the operator reading the manifest can map back): ``.`` is
        replaced with ``_``, and any other filesystem-unsafe
        characters are replaced with ``-``.
        """
        safe = subdomain.replace(".", "_")
        # Conservative sanitization: replace any non-[A-Za-z0-9_-] with -
        out_chars: list[str] = []
        for ch in safe:
            if ch.isalnum() or ch in ("_", "-"):
                out_chars.append(ch)
            else:
                out_chars.append("-")
        return "".join(out_chars) or "default"

    def run_wave(
        self,
        wave: str,
        state: DispatchState,
        *,
        target: str | None = None,
    ) -> WaveResult:
        """Run one wave (parent or drill-in). Validates deps, dispatches, drills.

        If wave is a parent (e.g. "W4"), this is the full lifecycle including
        drill-in trigger. Drill-in slots (e.g. "W4.5a") are NOT directly
        callable via this method — they are dispatched by the parent's flow.

        v3.2 (2026-06-07): dispatches to ``_run_wave_parallel`` (default)
        or ``_run_wave_serial`` based on ``self.mode``. The two share
        barrier / merge / drill-in / emit_new_target logic; they differ
        ONLY in when per-specialist raw outputs are persisted and
        whether ``context_reduction`` is fired.

        v3.3 (2026-06-08, Issue 4): per-envelope override. The wave's
        ``HandoffEnvelope`` (the FIRST fan-out envelope built by
        ``_build_envelopes``) carries an optional ``dispatch_mode``
        field. When set, that overrides ``self.mode`` for THIS wave
        only. Absent the field, ``self.mode`` applies. The resolution
        is performed by :meth:`_resolve_dispatch_mode`.
        """
        if wave in state.evidence:
            # Idempotent: already ran (drill-in or re-entry). Return prior.
            ev = state.evidence[wave]
            return WaveResult(
                wave=wave,
                layer=self._layer_of(wave),
                specialist_calls=state.fanout_counts.get(wave, 0),
                evidence=ev,
                drill_in=None,
                mode=self.mode,
                specialist_artifacts=dict(state.specialist_artifacts),
            )
        # 2026-06-08 (Issue 4): peek the dispatch_mode the envelope
        # would carry. We do this BEFORE barrier enforcement so that
        # the resolution is purely a header-level decision — a missing
        # dep still aborts the wave with a normal error, regardless of
        # mode.
        spec = get_wave(wave)
        requested = self._resolve_dispatch_mode(wave, spec, state, target=target)
        if requested == DispatchMode.SERIAL:
            return self._run_wave_serial(wave, state, target=target)
        return self._run_wave_parallel(wave, state, target=target)

    def _resolve_dispatch_mode(
        self,
        wave: str,
        spec: WaveSpec,
        state: DispatchState,
        *,
        target: str | None,
    ) -> DispatchMode:
        """Resolve the effective ``DispatchMode`` for one wave (2026-06-08, Issue 4).

        Resolution order (highest priority first):
          1. The first fan-out envelope's ``dispatch_mode`` field, when set.
          2. The session-level ``self.mode``.

        Barrier check is NOT done here — this helper only reads
        metadata. A missing dep still aborts the wave via the normal
        ``_run_wave_*`` path.

        For drill-in slot invocations (which go through
        ``_run_drill_slot`` directly), the parent's resolved mode is
        inherited by the drill-in envelope at construction time; see
        :func:`opensquilla.attack_dispatch.drill_in._build_drill_in_envelope`.
        """
        # Build a peek envelope (no state mutation) to read the field.
        # The fan-out count computation is cheap (it's a function of
        # upstream evidence which is already in state) so we can
        # safely call _build_envelopes here without dispatching.
        try:
            envelopes = self._build_envelopes(wave, spec, state, target=target)
        except Exception:
            # Barrier not met or upstream count not yet computed — fall
            # back to session-level mode. The actual _run_wave_* path
            # will re-raise the real error.
            return self.mode
        if not envelopes:
            return self.mode
        first = envelopes[0]
        if first.dispatch_mode is None:
            return self.mode
        return DispatchMode(first.dispatch_mode)

    def _run_wave_parallel(
        self,
        wave: str,
        state: DispatchState,
        *,
        target: str | None,
    ) -> WaveResult:
        """PARALLEL mode (v3.1, default): original behavior.

        The for-loop over envelopes is sequential at the Python level;
        the actual fan-out parallelism is at the LLM layer (multiple
        ``sessions_spawn`` in one assistant message). One combined
        per-wave artifact is written at the end of the wave.
        """
        spec = get_wave(wave)
        # Barrier: every dep must have evidence already
        missing = [d for d in spec.deps if d not in state.evidence]
        if missing:
            msg = f"wave {wave} barrier unmet; missing upstream evidence: {missing}"
            state.errors.append(msg)
            return WaveResult(
                wave=wave, layer=spec.layer,
                specialist_calls=0, evidence=None,
                drill_in=None, error=msg, mode=self.mode,
            )

        # Resolve fan-out plan
        envelopes = self._build_envelopes(wave, spec, state, target=target)
        state.fanout_counts[wave] = len(envelopes)

        # 2026-06-09 (Issue 11/12 — score gate hard-enforce).
        # Run the specialist(s) under the score gate. The
        # helper invokes the specialist(s), merges, verifies,
        # scores, and re-spawns with a retry brief if the
        # score fails (up to ``quality_max_retries`` times).
        try:
            (
                raw_results,
                evidence,
                findings_verified,
                findings_downgraded,
                briefs_by_env,
                quality_score,
                retry_count,
            ) = self._invoke_with_score_gate(
                wave, spec, envelopes, state, target=target
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"wave {wave} evidence merge failed: {exc}"
            state.errors.append(msg)
            return WaveResult(
                wave=wave, layer=spec.layer,
                specialist_calls=len(envelopes), evidence=None,
                drill_in=None, error=msg, mode=self.mode,
            )
        state.evidence[wave] = evidence

        # 2026-06-07 per-step artifact archive. Write the merged evidence
        # + brief + envelope to a per-session file under
        # ``<artifact_root>/<wave>/<handoff_id>.json``. For fan-out waves
        # we use the parent-wave form (W1 has 3 sub-specialists; one
        # combined artifact is enough for the next wave's barrier, and
        # the per-sub raw_calls entries keep the fan-out detail). The
        # path is exposed downstream via state.evidence_paths[wave] and
        # auto-injected into the next wave's envelope ``input_artifacts``.
        # Write failure is logged to errors but does NOT abort the wave
        # — the in-memory state.evidence remains the source of truth.
        try:
            artifact_path = self._write_artifact(
                wave=wave,
                spec=spec,
                evidence=evidence,
                envelopes=envelopes,
                briefs_by_env=briefs_by_env,
                target=target or "",
                state=state,
            )
            state.evidence_paths[wave] = str(artifact_path)
        except OSError as exc:
            msg = f"wave {wave} artifact write failed: {exc}"
            state.errors.append(msg)

        # Drill-in trigger
        drill: DrillInDecision | None = None
        drill_in_merged = False
        drill_in_overlay_combined: dict[str, Any] = {}
        if spec.drill_in_allowed and not spec.is_drill_in():
            drill = decide_drill_in(
                wave, evidence, threshold=self.thinness_threshold
            )
            if drill.triggered:
                state.drill_ins.extend(drill.specs)
                # 2026-06-07: drill_in_merged means "drill-in ran" (any slot
                # opened), regardless of whether the raw output was non-empty.
                drill_in_merged = True
                for d_spec in drill.specs:
                    # Recursively run the drill-in slot. The slot name is
                    # d_spec.slot (e.g. "W1.6a"), which is *not* in WAVES;
                    # the executor dispatches it via the parent's schema.
                    overlay = self._run_drill_slot(
                        d_spec, spec, state, target=target,
                    )
                    if overlay:
                        # Shallow-merge this slot's overlay into the
                        # combined overlay (lists concat, dicts update,
                        # scalars last-write-wins).
                        for k, v in overlay.items():
                            existing = drill_in_overlay_combined.get(k)
                            if isinstance(existing, list) and isinstance(v, list):
                                drill_in_overlay_combined[k] = existing + v
                            elif isinstance(existing, dict) and isinstance(v, dict):
                                existing.update(v)
                            else:
                                drill_in_overlay_combined[k] = v
        # Also scan this parent wave's own raw output for emit_new_target
        # (W4/W5/W6 can discover new subdomains / services). This runs
        # for any wave, not just drill-in parents.
        for raw in raw_results:
            self._scan_emit_new_target(raw, state, wave)

        # 2026-06-09 (Issue 11/12): the score is now computed
        # inside ``_invoke_with_score_gate`` and re-spawns
        # happen automatically. The final score + retry
        # count are returned from the gate; the audit
        # log entry was already written by the gate. We
        # just attach the score to the WaveResult.
        return WaveResult(
            wave=wave, layer=spec.layer,
            specialist_calls=len(envelopes), evidence=evidence,
            drill_in=drill,
            drill_in_merged=drill_in_merged,
            drill_in_overlay=drill_in_overlay_combined,
            mode=self.mode,
            # 2026-06-08 (Issue 2): verifier counters are populated by
            # the helper above (mutated in place; same as evidence).
            findings_verified=findings_verified,
            findings_downgraded=findings_downgraded,
            # 2026-06-09 (Issue 11): phase quality score.
            quality_score=quality_score,
            quality_retry_count=self._wave_retry_count.get(wave, 0),
        )

    def _run_wave_serial(
        self,
        wave: str,
        state: DispatchState,
        *,
        target: str | None,
    ) -> WaveResult:
        """SERIAL mode (v3.2, 2026-06-07): persist per-specialist raw outputs.

        For each envelope in the fan-out, in order:
          1. Invoke ``specialist_fn(env, brief)`` to get the raw output.
          2. Persist the raw to a per-specialist JSON file at
             ``<artifact_root>/<wave>/<handoff_id>.json``.
          3. Fire ``self.context_reduction`` (if set) so the LLM can
             release the raw from its context window.
          4. Record the handoff_id in ``state.released_handoff_ids`` and
             the artifact path in ``state.specialist_artifacts``.

        After all specialists, behaves like ``_run_wave_parallel``:
          - merge evidence into a typed record
          - write a combined per-wave artifact (slim evidence + a
            ``per_specialist_artifacts`` map pointing at each
            per-specialist file)
          - trigger drill-in / emit_new_target.

        Drill-in slots are also dispatched serially (each one writes
        a per-slot artifact under ``<artifact_root>/<wave>.drill_in/``).
        """
        spec = get_wave(wave)
        # Barrier: every dep must have evidence already
        missing = [d for d in spec.deps if d not in state.evidence]
        if missing:
            msg = f"wave {wave} barrier unmet; missing upstream evidence: {missing}"
            state.errors.append(msg)
            return WaveResult(
                wave=wave, layer=spec.layer,
                specialist_calls=0, evidence=None,
                drill_in=None, error=msg, mode=self.mode,
            )

        # Resolve fan-out plan
        envelopes = self._build_envelopes(wave, spec, state, target=target)
        state.fanout_counts[wave] = len(envelopes)

        # 2026-06-09 (Issue 11/12 — score gate hard-enforce).
        # Run the specialist(s) under the score gate (same
        # helper as the parallel path). The helper invokes
        # the specialist(s), merges, verifies, scores, and
        # re-spawns with a retry brief if the score fails
        # (up to ``quality_max_retries`` times).
        try:
            (
                raw_results,
                evidence,
                findings_verified,
                findings_downgraded,
                briefs_by_env,
                quality_score,
                retry_count,
            ) = self._invoke_with_score_gate(
                wave, spec, envelopes, state, target=target
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"wave {wave} evidence merge failed: {exc}"
            state.errors.append(msg)
            return WaveResult(
                wave=wave, layer=spec.layer,
                specialist_calls=len(envelopes), evidence=None,
                drill_in=None, error=msg,
                mode=self.mode,
            )
        state.evidence[wave] = evidence

        # Persist per-specialist artifacts + fire the
        # context_reduction callback for the FINAL retry
        # attempt. (Per-retry artifacts aren't useful —
        # only the final result is committed to
        # state.evidence.) The serial path keeps the same
        # per-specialist JSON files + per_specialist_paths
        # map as v3.2.
        per_specialist_paths: dict[str, str] = {}
        for env, raw in zip(envelopes, raw_results):
            try:
                spec_path = self._write_specialist_artifact(
                    wave=wave,
                    spec=spec,
                    handoff_id=env.handoff_id,
                    evidence=raw,
                    envelope=env,
                    brief=briefs_by_env[env.handoff_id],
                    target=target or "",
                    state=state,
                )
                per_specialist_paths[env.handoff_id] = str(spec_path)
                state.specialist_artifacts[env.handoff_id] = str(spec_path)
                state.released_handoff_ids.add(env.handoff_id)
            except OSError as exc:
                msg = f"wave {wave} per-specialist artifact write failed: {exc}"
                state.errors.append(msg)
            if self.context_reduction is not None:
                try:
                    self.context_reduction(
                        wave,
                        env.handoff_id,
                        Path(
                            per_specialist_paths.get(
                                env.handoff_id, ""
                            )
                        ),
                        raw,
                    )
                except Exception as exc:  # noqa: BLE001
                    state.errors.append(
                        f"wave {wave} context_reduction callback "
                        f"failed for {env.handoff_id}: {exc}"
                    )

        # Write the combined per-wave artifact. In SERIAL mode it carries
        # an extra ``per_specialist_artifacts`` map (handoff_id -> path)
        # so downstream readers can drill into the per-specialist files
        # on demand. The combined evidence field is the merged record.
        # Write failure is logged to errors but does NOT abort the wave.
        try:
            artifact_path = self._write_artifact(
                wave=wave,
                spec=spec,
                evidence=evidence,
                envelopes=envelopes,
                briefs_by_env=briefs_by_env,
                target=target or "",
                state=state,
                per_specialist_artifacts=per_specialist_paths,
                mode=self.mode,
            )
            state.evidence_paths[wave] = str(artifact_path)
        except OSError as exc:
            msg = f"wave {wave} artifact write failed: {exc}"
            state.errors.append(msg)

        # Drill-in trigger (SERIAL mode: each slot also writes a per-slot
        # artifact; see _run_drill_slot). Drill-in overlay merge is
        # identical to PARALLEL mode.
        drill: DrillInDecision | None = None
        drill_in_merged = False
        drill_in_overlay_combined: dict[str, Any] = {}
        if spec.drill_in_allowed and not spec.is_drill_in():
            drill = decide_drill_in(
                wave, evidence, threshold=self.thinness_threshold
            )
            if drill.triggered:
                state.drill_ins.extend(drill.specs)
                drill_in_merged = True
                for d_spec in drill.specs:
                    overlay = self._run_drill_slot(
                        d_spec, spec, state, target=target,
                    )
                    if overlay:
                        for k, v in overlay.items():
                            existing = drill_in_overlay_combined.get(k)
                            if isinstance(existing, list) and isinstance(v, list):
                                drill_in_overlay_combined[k] = existing + v
                            elif isinstance(existing, dict) and isinstance(v, dict):
                                existing.update(v)
                            else:
                                drill_in_overlay_combined[k] = v
        # Also scan this parent wave's own raw output for emit_new_target.
        for raw in raw_results:
            self._scan_emit_new_target(raw, state, wave)

        return WaveResult(
            wave=wave, layer=spec.layer,
            specialist_calls=len(envelopes), evidence=evidence,
            drill_in=drill,
            drill_in_merged=drill_in_merged,
            drill_in_overlay=drill_in_overlay_combined,
            mode=self.mode,
            specialist_artifacts=dict(per_specialist_paths),
            # 2026-06-08 (Issue 2): same verifier counters as parallel.
            findings_verified=findings_verified,
            findings_downgraded=findings_downgraded,
            # 2026-06-09 (Issue 11/12): score + retry_count are
            # already computed inside the gate helper; just
            # attach to the WaveResult.
            quality_score=quality_score,
            quality_retry_count=retry_count,
        )

    # -- internals ----------------------------------------------------------

    def _collect_results(self, state: DispatchState) -> list[WaveResult]:
        results: list[WaveResult] = []
        for wave in WAVE_NAMES:
            ev = state.evidence.get(wave)
            # Reconstruct the per-wave specialist_artifacts map from
            # state.specialist_artifacts (which is keyed by handoff_id).
            # A handoff_id belongs to wave W iff either:
            #   (a) it starts with W + "." and the part immediately
            #       after W + "." is NOT a digit (so "W1.recon.1" → W1
            #       but "W1.5.recon.1" → W1.5 not W1), OR
            #   (b) it is exactly a registered drill-in slot name for W
            #       (so "W1.6a" → W1).
            # The first rule handles normal specialists; the second
            # handles drill-in slots. Together they partition the
            # state.specialist_artifacts map by parent wave.
            wave_artifacts: dict[str, str] = {}
            for handoff_id, path_str in state.specialist_artifacts.items():
                if self._handoff_belongs_to_wave(handoff_id, wave):
                    wave_artifacts[handoff_id] = path_str
            results.append(
                WaveResult(
                    wave=wave,
                    layer=self._layer_of(wave),
                    specialist_calls=state.fanout_counts.get(wave, 0),
                    evidence=ev,
                    drill_in=None,
                    error=None,
                    mode=self.mode,
                    specialist_artifacts=wave_artifacts,
                )
            )
        return results

    @staticmethod
    def _handoff_belongs_to_wave(handoff_id: str, wave: str) -> bool:
        """True iff ``handoff_id`` is a per-specialist entry for ``wave``.

        See :meth:`_collect_results` for the matching rules.
        """
        if handoff_id == wave:
            return True
        prefix = wave + "."
        if not handoff_id.startswith(prefix):
            return False
        rest = handoff_id[len(prefix):]
        if rest and rest[0].isdigit():
            # The char after W + "." is a digit — could be a sub-wave
            # (e.g. "W1.5") or a drill-in slot. Drill-in slots for W
            # are listed in DRILL_IN_SLOTS[W] (e.g. W1.6a/b/c).
            return handoff_id in DRILL_IN_SLOTS.get(wave, ())
        return True

    @staticmethod
    def _layer_of(wave: str) -> str:
        for layer, members in LAYERS.items():
            if any(wave == m or wave.startswith(m + ".") for m in members):
                return layer
        return ""

    def _build_envelopes(
        self,
        wave: str,
        spec: WaveSpec,
        state: DispatchState,
        *,
        target: str | None,
        dispatch_mode: Literal["parallel", "serial"] | None = None,
        auto_approve: bool | None = None,
    ) -> list[HandoffEnvelope]:
        """Build the typed envelopes for this wave's fan-out.

        Asset counts (subdomains, ports, services) are computed dynamically
        from upstream evidence; we never hardcode a max.

        2026-06-07: also populates ``input_artifacts`` on each envelope
        from ``state.evidence_paths[dep_wave]`` for every dep that has a
        persisted artifact. This is what the next specialist reads when
        it needs to see the upstream evidence without trusting the
        in-memory state (e.g. across process restarts, LLM context
        evictions, or out-of-band drill-in / emit_new_target callbacks).

        2026-06-08 (Issue 1 + Issue 4): the optional ``dispatch_mode`` and
        ``auto_approve`` kwargs are forwarded to every envelope built
        for this wave. When ``None``, defaults apply: ``dispatch_mode``
        falls back to ``self.mode.value`` (so downstream readers always
        see a concrete value), and ``auto_approve`` falls back to
        ``self.auto_approve_specialists`` (the session-level flag added
        in 2026-06-08 to mirror the per-envelope header field).
        """
        deps = list(spec.deps)
        eta = 300  # default budget
        target_str = target or (state.evidence["W0"].target if "W0" in state.evidence else "")
        # 2026-06-08 (Issue 4): default the envelope's dispatch_mode to
        # the session-level self.mode so downstream readers (the
        # W8 reporting specialist, the manifest writer, the audit log)
        # always see a concrete value. Per-envelope override wins.
        effective_dispatch_mode: Literal["parallel", "serial"] | None = (
            dispatch_mode if dispatch_mode is not None else self.mode.value
        )
        # 2026-06-08 (Issue 1): same pattern for auto_approve. The
        # session-level ``self.auto_approve_specialists`` flag is the
        # default; per-envelope kwargs from the parent override.
        effective_auto_approve: bool = (
            auto_approve if auto_approve is not None else self.auto_approve_specialists
        )
        # Build the dep-session-id -> file-path map. We don't know yet
        # which sub-session of the parent wave the dep refers to, so for
        # static_fanout parents we use the parent-wave's combined
        # artifact; for single / dynamic we use the parent's primary
        # session file. (Both layouts are documented in
        # ``_write_artifact``.)
        dep_artifacts: dict[str, str] = {}
        for dep_wave in deps:
            path = state.evidence_paths.get(dep_wave)
            if path is None:
                continue
            # The dep string is the handoff_id (e.g. "W1.recon.1"); the
            # key in the input_artifacts map matches the dep string.
            dep_artifacts[dep_wave] = path
        # Common envelope kwargs shared by every fan-out branch.
        common_kwargs: dict[str, Any] = dict(
            input_dependencies=deps,
            evidence_schema=spec.evidence_schema,
            expected_runtime_s=eta,
            input_artifacts=dict(dep_artifacts),
            dispatch_mode=effective_dispatch_mode,
            auto_approve=effective_auto_approve,
        )
        if spec.fanout == "single":
            assert spec.specialist is not None
            sub_index = 1
            return [
                HandoffEnvelope(
                    handoff_id=f"{wave}.{spec.specialist}.{sub_index}",
                    **common_kwargs,
                )
            ]
        if spec.fanout == "static_fanout":
            out: list[HandoffEnvelope] = []
            for sub_index, agent in enumerate(spec.fanout_agents, start=1):
                out.append(
                    HandoffEnvelope(
                        handoff_id=f"{wave}.{agent}.{sub_index}",
                        **common_kwargs,
                    )
                )
            return out
        if spec.fanout == "dynamic_fanout":
            # W4 penetration: count = entry_count / SUB_TRACK_BUCKET_SIZE
            # W1.5 per-subdomain: count = subdomain_count / SUB_TRACK_BUCKET_SIZE
            # (W1.5 uses the per-wave count so per-subdomain recon is bucket'd
            # by subdomain count, not service count)
            entry_count = self._count_entries_for_wave(wave, state)
            n_sub = max(1, entry_count // SUB_TRACK_BUCKET_SIZE)
            assert spec.specialist is not None
            out = []
            for sub_index in range(1, n_sub + 1):
                out.append(
                    HandoffEnvelope(
                        handoff_id=f"{wave}.{spec.specialist}.{sub_index}",
                        **common_kwargs,
                    )
                )
            return out
        raise ValueError(f"unknown fanout mode: {spec.fanout}")

    @staticmethod
    def _count_entries(state: DispatchState) -> int:
        """Count (host × port) entries from W1 / W1.5 / W0.5 evidence.

        Prefers W1 (main-domain fan-out: 3 specialists, larger merged
        payload) over W1.5 (per-subdomain fan-out: smaller individual
        payload). Falls back to W0.5 (subdomain count) when no W1/W1.5
        services. Returns 1 when no upstream recon has data.

        We use the **raw** services count (not deduped) because multiple
        specialists in the same fan-out may legitimately report the same
        (host, port) with different banner / version / TLS evidence —
        dedup happens at the report layer (per_target_finding), not at
        the dispatch layer.
        """
        for wave in ("W1", "W1.5"):
            ev = state.evidence.get(wave)
            if isinstance(ev, ReconEvidence) and ev.services:
                return len(ev.services)
        w05 = state.evidence.get("W0.5")
        if isinstance(w05, SubTargetHandleList) and w05.handles:
            return len(w05.handles)
        return 1

    @staticmethod
    def _count_entries_for_wave(wave: str, state: DispatchState) -> int:
        """Per-wave entry count for dynamic_fanout sizing.

        W1.5: subdomain count (from W0.5 handles).
        W4 (or any other dynamic_fanout wave): service count (from W1.5/W1
        services).
        """
        if wave == "W1.5":
            w05 = state.evidence.get("W0.5")
            if isinstance(w05, SubTargetHandleList) and w05.handles:
                return len(w05.handles)
            return 1
        return DispatchExecutor._count_entries(state)



    @staticmethod
    def _make_brief(
        wave: str,
        spec: WaveSpec,
        env: HandoffEnvelope,
        state: DispatchState,
        *,
        target: str | None,
    ) -> str:
        """Build the natural-language brief that goes after the HANDOFF header.

        2026-06-07: when ``env.input_artifacts`` is non-empty, the brief
        gains a ``## Upstream context`` block that points the specialist
        at the persisted artifact files for each dep, with a 1-line
        summary of what was found. The specialist can either read the
        file on demand or trust the summary as a hint. The
        per-artifact content is intentionally NOT inlined — the
        specialist is expected to read the file so that large evidence
        bundles don't blow up the prompt context. (For test doubles
        that don't read files, the in-memory ``state.evidence`` is the
        fallback.)
        """
        target_str = target or (state.evidence["W0"].target if "W0" in state.evidence else "target")
        if wave == "W0":
            return (
                f"For target {target_str}, define ROE: scope, "
                f"forbidden assets, time window, success_unit (per-port|per-host|per-domain), "
                f"success criteria, phase plan. Output roe-v1 evidence."
            )
        if spec.fanout == "dynamic_fanout":
            # v3.2 (2026-06-07): W4 penetration sub-track brief. The
            # dynamic_fanout is shared by W4 (penetration) AND W1.5
            # (per-subdomain recon) — but only W4 needs the
            # pentest-specific strong reminder + result-marker
            # footer. W1.5 fans out recon sub-tracks which are
            # recon-v1, not pentest-v1, so the brief is shorter
            # there.
            if wave == "W4":
                return _build_w4_pentest_subtrack_brief(
                    env, state, target_str
                )
            entry_count = DispatchExecutor._count_entries(state)
            n_sub = max(1, entry_count // SUB_TRACK_BUCKET_SIZE)
            return (
                f"Penetration pass {env.handoff_id} of {n_sub} sub-tracks. "
                f"Cover your share of the W1 services list. Output pentest-v1 findings."
            )
        base = (
            f"Run wave {wave} for target {target_str}. "
            f"Specialist: {spec.specialist or spec.fanout_agents}. "
            f"Output evidence_schema: {spec.evidence_schema}."
        )
        # v3.3 (2026-06-08): W7 persistence-maintenance sub-track
        # brief. W7 is a static_fanout over
        # (persistence-maintenance, impact-exfiltration). Each
        # fan-out agent gets the v3.3 typed-schema brief + the
        # 10-pain-point pre-flight checklist. The previous one-liner
        # brief left the LLM free to repeat the 51ifind.com curl
        # variant discovery pattern; v3.3 forces the topology /
        # output_target / pass_criteria / verification_timing
        # sequence before any curl runs.
        if wave == "W7" and spec.evidence_schema == "persist-v1":
            return _build_w7_persist_brief(env, state, target_str)
        if env.input_artifacts:
            lines = [base, "", "## Upstream context (per-step archive)"]
            for handoff_id, path in env.input_artifacts.items():
                ev = state.evidence.get(handoff_id.split(".", 1)[0])
                schema_hint = ""
                if ev is not None:
                    schema_hint = f" — {type(ev).__name__} ({len(getattr(ev, 'services', []))} services, {len(getattr(ev, 'subdomains', []))} subdomains)"
                lines.append(
                    f"- {handoff_id}{schema_hint} → read artifact at `{path}`"
                )
            lines.append("")
            lines.append(
                "If the in-memory context is not enough, `cat` the file path "
                "above to see the full upstream evidence (subdomains, services, "
                "infra_sharing, etc.)."
            )
            return "\n".join(lines)
        return base

    def _merge_evidence(
        self,
        wave: str,
        spec: WaveSpec,
        raw_results: list[dict | EvidenceBase],
        *,
        target: str,
    ) -> EvidenceBase:
        """Merge N raw results into one typed evidence record.

        For fan-out waves, we deep-merge dicts and concat lists; the merged
        dict is then validated against the wave's evidence_schema.
        """
        schema_name = spec.evidence_schema
        if schema_name not in EVIDENCE_SCHEMAS:
            raise ValueError(f"unknown evidence_schema {schema_name!r}")

        merged: dict[str, Any] = {"target": target}
        for raw in raw_results:
            if isinstance(raw, EvidenceBase):
                d = raw.model_dump()
            else:
                d = dict(raw)
            # Always take the target from W0 (or our arg), not from the child.
            d.pop("target", None)
            d.pop("produced_at", None)
            d.pop("evidence_version", None)
            for k, v in d.items():
                if k not in merged or merged[k] is None:
                    merged[k] = v
                    continue
                existing = merged[k]
                if isinstance(existing, list) and isinstance(v, list):
                    merged[k] = existing + v
                elif isinstance(existing, dict) and isinstance(v, dict):
                    existing.update(v)
                else:
                    # Scalar / single — last-write-wins
                    merged[k] = v
        return make_evidence(schema_name, **merged)

    def _verify_pentest_findings(
        self,
        *,
        evidence: EvidenceBase,
        wave: str,
        state: DispatchState,
        target: str | None,
    ) -> tuple[int, int]:
        """Runtime verification of pentest findings (2026-06-08, Issue 2).

        Iterates ``evidence.findings`` (when the evidence is a
        :class:`PenetrationEvidence`) and re-runs each finding's
        first ``ReproduceStep`` through ``self.verifier_fn``. Findings
        with ``status in {owned, confirmed}`` and
        ``verification_required=True`` are gated; findings with
        ``status in {partial, blocked, fail, in_progress}`` are
        passed through (no need to verify a partial/blocked claim).

        On ``ok=False``:
          - ``f.status`` is downgraded to ``"partial"`` (the
            ``FindingStatus`` enum value that means "partial
            exploitation, partial impact" — the verifier-rejected
            finding is a partial by definition).
          - ``f.verified`` is set to ``False``.
          - ``f.verification_artifact`` is set to the verifier's
            log path.
          - ``f.verification_failure_reason`` is set to the
            ``VerifyResult.failure_reason`` tag (``timeout`` /
            ``exit_nonzero`` / ``match_miss`` /
            ``no_reproduce_steps`` / ``verifier_error``).
          - ``evidence.unverified_findings`` is appended with the
            finding's ``entry_id``.

        On ``ok=True``:
          - ``f.verified`` is set to ``True``.
          - ``f.verification_artifact`` is set to the verifier's
            log path.

        On the verifier being disabled (``verifier_fn=False``) or
        on a non-``PenetrationEvidence`` evidence record, this
        method is a no-op and returns ``(0, 0)``.

        Returns a 2-tuple ``(verified_count, downgraded_count)``
        the caller attaches to the ``WaveResult`` for audit.

        Side effects:
          - ``state.errors`` gains one entry per failed verification
            (NOT a wave-level abort; the wave continues).
          - The on-disk per-wave artifact, when re-written by
            ``_write_artifact`` immediately after this method,
            reflects the patched ``findings[]`` (Pydantic models
            mutated in place; ``model_dump`` picks up the changes).
        """
        # 1) Verifier disabled: no-op.
        if self.verifier_disabled or self.verifier_fn is None:
            return 0, 0
        # 2) Non-pentest evidence: no-op. W4's evidence is the only
        #    one with a `findings` list of PenetrationFinding; other
        #    waves produce reports, recon, etc. that don't carry
        #    exploit claims.
        if not isinstance(evidence, PenetrationEvidence):
            return 0, 0
        # 3) Empty findings list: nothing to verify.
        if not evidence.findings:
            evidence.verifier_version = "v1"
            return 0, 0
        verified_count = 0
        downgraded_count = 0
        evidence.verifier_version = "v1"
        verifier = self.verifier_fn
        for f in evidence.findings:
            # Gate: only verify owned/confirmed claims, and only when
            # the specialist opted in (verification_required=True is
            # the default for backward compat).
            if f.status not in ("owned", "confirmed"):
                continue
            if not f.verification_required:
                continue
            if not f.reproduce_steps:
                # No recipe to replay — the finding is unverifiable.
                # Downgrade to partial so the W8 report marks it
                # unverified; record the reason.
                f.verified = False
                f.verification_failure_reason = "no_reproduce_steps"
                f.status = "partial"
                evidence.unverified_findings.append(f.entry_id)
                state.errors.append(
                    f"wave {wave} finding {f.entry_id} has no "
                    f"reproduce_steps; auto-downgraded to partial"
                )
                downgraded_count += 1
                continue
            step = f.reproduce_steps[0]
            artifact_root = self._subdomain_artifact_root(state, target)
            try:
                result: VerifyResult = verifier(
                    step,
                    timeout_s=step.verifier_timeout_s or DEFAULT_VERIFIER_TIMEOUT_S,
                    artifact_root=artifact_root,
                    entry_id=f.entry_id,
                )
            except Exception as exc:  # noqa: BLE001 — verifier must not raise
                f.verified = False
                f.verification_failure_reason = "verifier_error"
                f.verification_artifact = None
                f.status = "partial"
                evidence.unverified_findings.append(f.entry_id)
                state.errors.append(
                    f"wave {wave} finding {f.entry_id} verifier raised "
                    f"{type(exc).__name__}: {exc}; auto-downgraded to partial"
                )
                downgraded_count += 1
                continue
            f.verification_artifact = result.artifact_path
            if result.ok:
                f.verified = True
                f.verification_failure_reason = None
                verified_count += 1
            else:
                f.verified = False
                f.verification_failure_reason = result.failure_reason or "match_miss"
                f.status = "partial"
                evidence.unverified_findings.append(f.entry_id)
                state.errors.append(
                    f"wave {wave} finding {f.entry_id} verifier rejected: "
                    f"{result.detail} (reason={f.verification_failure_reason})"
                )
                downgraded_count += 1
        return verified_count, downgraded_count

    # 2026-06-09 (Issue 11 — phase quality scoring). Public
    # entry point for scoring a wave's evidence. Called by
    # ``_run_wave_parallel`` / ``_run_wave_serial`` after the
    # verifier and write_artifact. The scorer is the
    # load-bearing safety net for the 4 user-named criteria
    # (C1..C4) plus 3 bundled extras (C5..C7). When
    # ``passed=False`` the orchestrator (LLM) reads the
    # score report from ``WaveResult.quality_score`` and
    # re-spawns the specialist with the score's
    # ``recommendation`` field copied into the brief.
    #
    # The default implementation
    # :class:`RulesBasedQualityScorer` is deterministic and
    # side-effect free. An LLM-based ``quality-scorer``
    # specialist can be injected via
    # ``DispatchExecutor(quality_scorer_fn=...)``.
    def score_wave(
        self,
        evidence: EvidenceBase,
        *,
        wave: str,
        handoff_id: str,
        retry_count: int = 0,
    ) -> "PhaseQualityScore | None":
        """Run the phase quality scorer on ``evidence``.

        Returns the :class:`PhaseQualityScore`, or ``None`` when
        the scorer is disabled (e.g. via
        ``quality_scorer_fn=False``).

        Never raises — on internal scorer error it returns a
        :class:`PhaseQualityScore` with ``score=0`` and a
        single deduction ``criterion_id="scorer_error"`` so
        the orchestrator can still see *something* failed.
        """
        if self.quality_scorer_disabled or self.quality_scorer_fn is None:
            return None
        if evidence is None:
            return None
        try:
            return self.quality_scorer_fn(
                evidence,
                wave=wave,
                handoff_id=handoff_id,
                threshold=self.quality_threshold,
                retry_count=retry_count,
            )
        except Exception as exc:  # noqa: BLE001 — scorer must not raise
            from opensquilla.attack_dispatch.evidence import (
                PhaseQualityScore,
                QualityDeduction,
            )

            return PhaseQualityScore(
                target=getattr(evidence, "target", "unknown"),
                wave=wave,
                handoff_id=handoff_id,
                score=0,
                threshold=self.quality_threshold,
                passed=False,
                deductions=[
                    QualityDeduction(
                        criterion_id="scorer_error",
                        criterion_name="scorer_error",
                        points_deducted=100,
                        detail=(
                            f"Quality scorer raised "
                            f"{type(exc).__name__}: {exc}. "
                            f"Treating as score 0."
                        ),
                    )
                ],
                recommendation=(
                    "The quality scorer crashed. "
                    "Investigate the scorer logs and re-run."
                ),
                retry_count=retry_count,
            )

    def _build_retry_brief(
        self,
        original_brief: str,
        score: "PhaseQualityScore",
    ) -> str:
        """Build a retry brief for a low-score wave.

        Used by the orchestrator (LLM) when
        ``WaveResult.quality_score.passed is False``. The
        brief appends the score's deductions +
        ``recommendation`` to the original brief, prefixed
        with a clear "AUTO-RETRY (low quality score)"
        header so the LLM knows this is a forced re-run.
        """
        if not score.passed:
            header = (
                f"## AUTO-RETRY (low quality score: {score.score}/100, "
                f"threshold={score.threshold})\n\n"
                f"Previous attempt FAILED the quality gate. Fix the "
                f"following deductions and re-run:\n\n"
            )
            return header + score.recommendation + "\n\n---\n\n" + original_brief
        return original_brief

    def _subdomain_artifact_root(
        self,
        state: DispatchState,
        target: str | None,
    ) -> Path:
        """Resolve the artifact root for the current run, honoring
        per-subdomain layout (Issue 3).

        When the per-subdomain driver (Issue 3) is in use, the
        sub_state's artifact_root is overridden via
        ``state.subdomain_artifact_roots[target]``. When the
        single-pass driver is in use, ``self.artifact_root`` applies.
        The verifier writes its per-finding log under
        ``<root>/verify/<entry_id>.<step_index>.json``.
        """
        if target and target in state.subdomain_artifact_roots:
            return Path(state.subdomain_artifact_roots[target])
        return self.artifact_root

    # 2026-06-09 (Issue 11 — hard-enforce the score gate).
    # 2026-06-09 (Issue 12 follow-up — gate actually blocks).
    # The user reported: "打分机制好像没有起效果" — the
    # score was being computed and attached to
    # WaveResult, but the executor was still committing
    # the evidence to ``state.evidence[wave]`` and the
    # next wave ran regardless of score. The LLM
    # orchestrator saw the score, but didn't actually
    # act on it (because the wave had already moved on).
    #
    # The fix: this helper runs the specialist call +
    # merge + verify + score loop. If the score fails,
    # the helper re-invokes the specialist(s) with a
    # retry brief that carries the score report. The
    # loop runs up to ``quality_max_retries`` times. The
    # caller uses the final (raw_results, evidence,
    # verified, downgraded, briefs_by_env, quality_score)
    # tuple to build the WaveResult and (if score
    # passed or retries exhausted) commit to
    # ``state.evidence[wave]``.
    def _invoke_with_score_gate(
        self,
        wave: str,
        spec: WaveSpec,
        envelopes: list[HandoffEnvelope],
        state: DispatchState,
        target: str | None,
    ) -> tuple[
        list[dict | EvidenceBase],
        EvidenceBase,
        int,
        int,
        dict[str, str],
        "PhaseQualityScore | None",
        int,
    ]:
        """Run the wave's specialist(s) under the score gate.

        Returns a 7-tuple ``(raw_results, evidence,
        verified, downgraded, briefs_by_env,
        quality_score, retry_count)``. The caller is
        responsible for the drill-in, write_artifact, and
        WaveResult construction.

        The retry loop's behavior:
          - Iteration 0: build the original brief via
            ``_make_brief``.
          - Iteration N > 0: build a retry brief that
            prefixes the original brief with the
            ``_build_retry_brief`` AUTO-RETRY header +
            score report.
          - After every iteration, score the merged
            evidence. If the score passes, break.
          - If ``quality_max_retries == 0`` OR the
            scorer is disabled, run exactly one
            iteration and return immediately.
        """
        max_retries = max(0, int(self.quality_max_retries))
        # 0 retries = single attempt, no loop.
        attempts = max_retries + 1
        briefs_by_env: dict[str, str] = {}
        raw_results: list[dict | EvidenceBase] = []
        evidence: EvidenceBase | None = None
        findings_verified = 0
        findings_downgraded = 0
        quality_score: "PhaseQualityScore | None" = None
        last_score: "PhaseQualityScore | None" = None
        last_raw: list[dict | EvidenceBase] = []
        last_briefs: dict[str, str] = {}
        retry_count = 0
        for attempt in range(attempts):
            # Build the brief. On attempt 0, the original
            # brief. On attempt N > 0, the retry brief
            # carrying the previous attempt's score
            # report. When scorer is disabled, retry is
            # skipped (no point retrying without
            # guidance).
            if attempt == 0:
                briefs_by_env = {}
                for env in envelopes:
                    briefs_by_env[env.handoff_id] = self._make_brief(
                        wave, spec, env, state, target=target
                    )
            else:
                if last_score is None or last_score.passed:
                    # Nothing to retry.
                    break
                # Use the FIRST attempt's brief as the
                # base; the retry brief accumulates
                # attempt N-1 → attempt N score
                # report. This keeps the brief
                # chain: brief_0 → brief_1 (with
                # score_0) → brief_2 (with score_0 +
                # score_1) — each retry sees ALL
                # prior failures.
                next_brief = self._build_retry_brief(
                    list(last_briefs.values())[0]
                    if last_briefs
                    else "",
                    last_score,
                )
                briefs_by_env = {
                    env.handoff_id: next_brief
                    for env in envelopes
                }
                retry_count = attempt
                # Audit: record the retry in state.errors
                # so the operator can see the loop.
                state.errors.append(
                    f"wave {wave} quality score "
                    f"{last_score.score}/100 FAILED "
                    f"threshold {last_score.threshold}; "
                    f"auto-retrying (attempt {attempt + 1}/"
                    f"{attempts})"
                )
            # Invoke specialist(s).
            raw_results = []
            for env in envelopes:
                raw = self.specialist_fn(
                    env, briefs_by_env[env.handoff_id]
                )
                raw_results.append(raw)
                state.raw_calls.append(
                    {
                        "wave": wave,
                        "envelope": env.model_dump(),
                        "brief": briefs_by_env[env.handoff_id],
                        "raw": (
                            raw
                            if not isinstance(raw, EvidenceBase)
                            else raw.model_dump()
                        ),
                        "retry_count": retry_count,
                    }
                )
            # Merge.
            try:
                evidence = self._merge_evidence(
                    wave, spec, raw_results, target=target
                )
            except Exception as exc:  # noqa: BLE001
                # Merge failure is treated as a low-score
                # pass-through. The caller surfaces the
                # error in the WaveResult.
                state.errors.append(
                    f"wave {wave} evidence merge failed: {exc}"
                )
                # If we've used all retries, give up.
                if attempt + 1 >= attempts:
                    raise
                # Otherwise treat this iteration as a
                # "score=0" pass-through and retry.
                last_score = None  # triggers break above
                last_raw = raw_results
                last_briefs = briefs_by_env
                continue
            # Verify.
            findings_verified, findings_downgraded = (
                self._verify_pentest_findings(
                    evidence=evidence,
                    wave=wave,
                    state=state,
                    target=target,
                )
            )
            # Score.
            primary_handoff = (
                envelopes[0].handoff_id if envelopes else wave
            )
            quality_score = self.score_wave(
                evidence,
                wave=wave,
                handoff_id=primary_handoff,
                retry_count=retry_count,
            )
            # Decision: did we pass?
            if (
                quality_score is None
                or quality_score.passed
                or attempt + 1 >= attempts
            ):
                # Either scorer is disabled, score passed,
                # or we're out of retries.
                last_score = quality_score
                last_raw = raw_results
                last_briefs = briefs_by_env
                break
            # Score failed AND we have more retries.
            last_score = quality_score
            last_raw = raw_results
            last_briefs = briefs_by_env
        # Loop ended. ``evidence`` is the final
        # (possibly last) attempt's merged result; if
        # even the last attempt failed at merge, we
        # re-raise the exception (the caller's existing
        # error path handles it).
        if evidence is None:
            # Should not happen if the merge didn't raise,
            # but be defensive.
            raise RuntimeError(
                f"wave {wave}: score gate exited without "
                f"a successful merge"
            )
        # Record the retry count in state so the
        # per-wave audit trail persists.
        self._wave_retry_count[wave] = retry_count
        return (
            raw_results,
            evidence,
            findings_verified,
            findings_downgraded,
            briefs_by_env,
            quality_score,
            retry_count,
        )

    def _run_drill_slot(
        self,
        d_spec: DrillInSpec,
        parent: WaveSpec,
        state: DispatchState,
        *,
        target: str | None,
    ) -> dict[str, Any]:
        """Execute a single drill-in slot.

        Drill-in slots reuse the parent's evidence_schema and specialist list,
        but with the reason-class-specific brief. We do NOT register a new
        wave in WAVES; we just dispatch one specialist call and record it.

        2026-06-07: the raw output is shallow-merged into
        ``state.drill_in_overlay[parent_wave]`` (NOT into the parent's
        evidence record). The merge rules match :meth:`_merge_evidence`:
        lists concat, dicts update, scalars last-write-wins. Meta fields
        (``target`` / ``produced_at`` / ``evidence_version`` /
        ``evidence_schema``) are stripped.

        v3.2 (2026-06-07, SERIAL mode): each drill-in slot also writes
        a per-slot artifact at ``<artifact_root>/<wave>.drill_in/<slot>.json``
        and fires ``self.context_reduction`` so the LLM can release
        the raw. The handoff_id in the per-slot map is the slot name
        (e.g. ``W1.6a``) — callers see the slot directly, not a
        synthetic key. The path is recorded in
        ``state.specialist_artifacts[slot]``.

        Returns the merged overlay dict for this slot. Empty dict when
        raw is empty.
        """
        target_str = target or (state.evidence["W0"].target if "W0" in state.evidence else "")
        env = HandoffEnvelope(
            handoff_id=d_spec.slot,
            input_dependencies=[d_spec.parent_wave],
            evidence_schema=parent.evidence_schema,
            expected_runtime_s=180,
        )
        brief = (
            f"DRILL-IN {d_spec.slot} on parent {d_spec.parent_wave}. "
            f"Reason: {d_spec.reason_class} ({d_spec.reason}). "
            f"Detail: {d_spec.reason_detail}. "
            f"Target: {target_str}."
        )
        raw = self.specialist_fn(env, brief)
        state.raw_calls.append(
            {
                "wave": d_spec.slot,
                "envelope": env.model_dump(),
                "brief": brief,
                "raw": raw if not isinstance(raw, EvidenceBase) else raw.model_dump(),
            }
        )
        # v3.2 SERIAL mode: persist the slot's raw to a per-slot
        # artifact BEFORE returning. _artifact_path_for routes drill-in
        # slots to the <wave>.drill_in/ sibling tree.
        if self.mode == DispatchMode.SERIAL:
            try:
                slot_path = self._write_specialist_artifact(
                    wave=d_spec.parent_wave,
                    spec=parent,
                    handoff_id=d_spec.slot,
                    evidence=raw,
                    envelope=env,
                    brief=brief,
                    target=target or "",
                    state=state,
                )
                state.specialist_artifacts[d_spec.slot] = str(slot_path)
                state.released_handoff_ids.add(d_spec.slot)
            except OSError as exc:
                state.errors.append(
                    f"drill-in slot {d_spec.slot} per-slot artifact write failed: {exc}"
                )
            if self.context_reduction is not None:
                try:
                    self.context_reduction(
                        d_spec.parent_wave,
                        d_spec.slot,
                        Path(state.specialist_artifacts.get(d_spec.slot, "")),
                        raw,
                    )
                except Exception as exc:  # noqa: BLE001
                    state.errors.append(
                        f"drill-in slot {d_spec.slot} context_reduction callback failed: {exc}"
                    )
        # Scan drill-in raw for emit_new_target (a drill-in on W4 can
        # surface new subdomains too).
        self._scan_emit_new_target(raw, state, d_spec.parent_wave)
        # Shallow-merge raw into state.drill_in_overlay[parent_wave].
        raw_dict: dict[str, Any] = (
            raw.model_dump() if isinstance(raw, EvidenceBase) else dict(raw or {})
        )
        for meta_key in ("target", "produced_at", "evidence_version", "evidence_schema"):
            raw_dict.pop(meta_key, None)
        if not raw_dict:
            return {}
        overlay = state.drill_in_overlay.setdefault(d_spec.parent_wave, {})
        for k, v in raw_dict.items():
            existing = overlay.get(k)
            if isinstance(existing, list) and isinstance(v, list):
                overlay[k] = existing + v
            elif isinstance(existing, dict) and isinstance(v, dict):
                existing.update(v)
            else:
                overlay[k] = v
        return dict(overlay)

    @staticmethod
    def _scan_emit_new_target(
        raw: dict | EvidenceBase | None,
        state: DispatchState,
        parent_wave: str,
    ) -> None:
        """Scan a specialist's raw output for ``emit_new_target`` declarations.

        When a W4/W5/W6 (or any wave's drill-in) discovers new subdomains
        / hidden services / pivots, it surfaces them in the raw output as
        ``emit_new_target: list[str]``. This helper:

        - Pushes each new target to ``state.target_queue`` (deduped).
        - Records a :func:`build_emit_new_target_spec` in
          ``state.drill_ins`` for audit (only when ``parent_wave`` is a
          known drill-in parent).

        Safe no-op when raw is None, when the key is absent, or when
        ``parent_wave`` has no drill-in slot.
        """
        if raw is None:
            return
        if isinstance(raw, EvidenceBase):
            d = raw.model_dump()
        else:
            d = dict(raw)
        new_targets = d.get("emit_new_target")
        if not new_targets or not isinstance(new_targets, list):
            return
        # Dedupe against state.target_queue
        new_only = [
            t for t in new_targets
            if isinstance(t, str) and t and t not in state.target_queue
        ]
        if not new_only:
            return
        state.target_queue.extend(new_only)
        # Record a spec for audit; if parent_wave is not a drill-in parent,
        # skip the spec (the targets are still in the queue).
        if parent_wave in DRILL_IN_SLOTS:
            try:
                spec = build_emit_new_target_spec(
                    parent_wave=parent_wave,
                    new_targets=new_only,
                    target_agent="recon",
                )
                state.drill_ins.append(spec)
            except ValueError:
                # Should not happen given the parent_wave check, but be safe.
                pass

    def _try_attach_to_peer_deep(self, target: str) -> EvidenceBase | None:
        """Best-effort: if a peer deep (cyberstrike-deep) is running on
        the same target, attach its W0 evidence as a starting point.

        Returns the peer's W0 evidence (an EvidenceBase), or None.

        The actual session_manager + storage lookup is delegated to
        ``self.peer_attach_fn`` (set via constructor). Production code
        (hack-deep LLM) injects a real implementation; tests inject a
        mock. When ``peer_attach_fn`` is None or raises, this method
        returns None — the run is unaffected.
        """
        if self.peer_attach_fn is None:
            return None
        try:
            return self.peer_attach_fn(target)
        except Exception:
            return None

    # -- 2026-06-07 per-step artifact archive --------------------------------

    @staticmethod
    def _artifact_path_for(artifact_root: Path, wave: str, handoff_id: str) -> Path:
        """Compute the canonical artifact path for a given (wave, handoff_id).

        Layout: ``<artifact_root>/<wave>/<handoff_id>.json``.

        Drill-in slots get their own sibling sub-tree
        (``<artifact_root>/<wave>.drill_in/<handoff_id>.json``) so the
        parent wave's directory only contains merged-parent evidence.

        v3.2 (2026-06-07, SERIAL mode): the per-slot artifact writer
        calls this for drill-in slots where ``wave`` is the PARENT wave
        and ``handoff_id`` is the slot name (e.g. ``W1`` and
        ``W1.6a``). We detect a drill-in slot by matching
        ``handoff_id`` against the canonical slot names in
        ``DRILL_IN_SLOTS[parent]`` for every parent — the slot
        substring is *not* sufficient (W1's slots are W1.6a/b/c, not
        W1.5a/b/c). Falls back to the legacy ``.5`` substring check
        for W1.5 / W4.5 / W6.5.
        """
        # v3.2: exact match against any registered drill-in slot name.
        for _parent, slot_names in DRILL_IN_SLOTS.items():
            if handoff_id in slot_names:
                return artifact_root / f"{wave}.drill_in" / f"{handoff_id}.json"
        # Legacy .5 check covers W1.5 (registered sub-wave) and the
        # older W4.5 / W6.5 slot names that DO contain ".5".
        if ".5" in wave or handoff_id.startswith("W") and ".5" in handoff_id:
            return artifact_root / f"{wave}.drill_in" / f"{handoff_id}.json"
        return artifact_root / wave / f"{handoff_id}.json"

    def _write_artifact(
        self,
        *,
        wave: str,
        spec: WaveSpec,
        evidence: EvidenceBase,
        envelopes: list[HandoffEnvelope],
        briefs_by_env: dict[str, str],
        target: str,
        state: DispatchState,
        per_specialist_artifacts: dict[str, str] | None = None,
        mode: DispatchMode = DispatchMode.PARALLEL,
    ) -> Path:
        """Persist the validated evidence for one (parent) wave to disk.

        The artifact bundles the merged evidence, the primary envelope
        (first fan-out sub), the per-envelope briefs, the target, and a
        timestamp. The on-disk shape is:

        ``<artifact_root>/<wave>/<primary_handoff_id>.json``

        For fan-out waves we keep ONE file per parent wave (the merged
        evidence) — the per-sub raw_calls are in ``state.raw_calls`` and
        can be recovered by the orchestrator if needed. For drill-in
        slots the file lives in the ``<wave>.drill_in/`` sibling tree.

        v3.2 (2026-06-07, SERIAL mode only): when ``per_specialist_artifacts``
        is non-empty, the combined artifact also carries a
        ``per_specialist_artifacts`` map (handoff_id -> absolute path)
        so downstream readers can drill into each specialist's raw.
        The combined ``mode`` field is set to ``mode.value`` so readers
        can detect SERIAL runs without re-running.

        Returns the absolute path of the written file.
        """
        # Choose a stable filename for the parent-wave merged artifact.
        # For static_fanout we use the first agent; for dynamic_fanout
        # the specialist; for single the specialist. In SERIAL mode the
        # primary_handoff_id would collide with the per-specialist file
        # of the same name; we use ``.combined`` to avoid clobbering.
        if mode == DispatchMode.SERIAL:
            primary_handoff_id = f"{wave}.combined"
            primary_agent = "combined"
        elif spec.fanout == "static_fanout" and spec.fanout_agents:
            primary_agent = spec.fanout_agents[0]
            primary_handoff_id = f"{wave}.{primary_agent}.1"
        elif spec.specialist:
            primary_agent = spec.specialist
            primary_handoff_id = f"{wave}.{primary_agent}.1"
        else:
            primary_agent = "multi"
            primary_handoff_id = f"{wave}.multi.1"
        artifact_path = self._artifact_path_for(
            self._subdomain_artifact_root(state, target), wave, primary_handoff_id
        )
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        # Brief summary: use the primary envelope's brief if present, else
        # synthesize a 1-liner from the wave spec. In SERIAL mode the
        # primary handoff_id is synthetic, so briefs_by_env.get returns
        # ""; we fall back to the first envelope's brief for readability.
        primary_brief = briefs_by_env.get(primary_handoff_id, "")
        if not primary_brief and envelopes:
            first_env = envelopes[0]
            primary_brief = briefs_by_env.get(first_env.handoff_id, "")
        payload: dict[str, Any] = {
            "stage": wave,  # the "stage" key for the routing pattern
            "agent": primary_agent,
            "session_id": primary_handoff_id,
            "schema": spec.evidence_schema,
            "fanout": spec.fanout,
            "deps": list(spec.deps),
            "target": target,
            "evidence": evidence.model_dump(mode="json"),
            "primary_brief": primary_brief,
            "envelopes": [env.model_dump() for env in envelopes],
            "briefs_by_env": briefs_by_env,
            "specialist_calls": len(envelopes),
            "mode": mode.value,
            "produced_at": datetime.now(timezone.utc).isoformat(),
        }
        if per_specialist_artifacts:
            payload["per_specialist_artifacts"] = dict(per_specialist_artifacts)
        artifact_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        # Step-trail: refresh the compact in-prompt view so the next
        # compaction can re-inject it. The rebuild reads evidence_paths
        # + specialist_artifacts from state, so it must run AFTER the
        # state mutations above.
        self._maybe_rebuild_trail(state, target=target)
        return artifact_path

    def _write_specialist_artifact(
        self,
        *,
        wave: str,
        spec: WaveSpec,
        handoff_id: str,
        evidence: dict | EvidenceBase,
        envelope: HandoffEnvelope,
        brief: str,
        target: str,
        state: DispatchState | None = None,
    ) -> Path:
        """Persist ONE specialist's raw output to a per-specialist JSON file.

        v3.2 (2026-06-07, SERIAL mode): called once per specialist call,
        BEFORE the next specialist. The on-disk shape mirrors the
        combined per-wave artifact (``_write_artifact``) but with
        ``specialist_calls == 1`` and the raw evidence field populated
        from the single specialist (not a merge).

        Layout: ``<artifact_root>/<wave>/<handoff_id>.json``. For
        drill-in slots the parent is the slot name (e.g. ``W1.6a``);
        the path uses ``_artifact_path_for`` which routes drill-in
        slots to the ``<wave>.drill_in/`` sibling tree.

        Write failure raises ``OSError``; the caller catches it and
        logs to ``state.errors`` without aborting the wave.
        """
        # _artifact_path_for routes drill-in slots to the
        # ``<wave>.drill_in/`` sibling tree automatically (it detects
        # ``.5`` in the wave / handoff_id). We rely on that here.
        # 2026-06-08 (Issue 3): per-subdomain layout. The per-specialist
        # artifact is written under the same per-subdomain root as
        # the combined per-wave artifact (when applicable).
        artifact_path = self._artifact_path_for(
            self._subdomain_artifact_root(state, target), wave, handoff_id
        )
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        # Resolve the agent name from the handoff_id (best-effort).
        parts = handoff_id.split(".")
        agent = parts[1] if len(parts) >= 2 else "unknown"
        # Normalize the evidence to a dict for the JSON payload.
        if isinstance(evidence, EvidenceBase):
            evidence_payload: Any = evidence.model_dump(mode="json")
        elif isinstance(evidence, dict):
            evidence_payload = dict(evidence)
        else:
            evidence_payload = evidence
        payload: dict[str, Any] = {
            "stage": wave,
            "agent": agent,
            "session_id": handoff_id,
            "schema": spec.evidence_schema,
            "fanout": "single",  # one specialist = single
            "deps": list(spec.deps),
            "target": target,
            "evidence": evidence_payload,
            "primary_brief": brief,
            "envelopes": [envelope.model_dump()],
            "briefs_by_env": {handoff_id: brief},
            "specialist_calls": 1,
            "mode": self.mode.value,
            "produced_at": datetime.now(timezone.utc).isoformat(),
        }
        artifact_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return artifact_path

    def _read_artifact(self, path: str | Path) -> dict[str, Any]:
        """Read a previously-written artifact file back as a dict.

        Used by the specialist (via the executor's pre-read in
        ``_make_brief``) to look up upstream context. Returns an empty
        dict if the file is missing or unreadable — the specialist
        falls back to its own context.
        """
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}

    def _read_upstream_artifacts(
        self, env: HandoffEnvelope
    ) -> dict[str, dict[str, Any]]:
        """Read all upstream artifacts declared on a handoff envelope.

        Returns a mapping ``handoff_id -> artifact_dict`` for every
        path in ``env.input_artifacts``. Missing / unreadable files
        are silently skipped (the specialist still has the in-memory
        evidence via the executor's barrier check, so this is a
        convenience, not the only source of context).
        """
        out: dict[str, dict[str, Any]] = {}
        for handoff_id, path in env.input_artifacts.items():
            data = self._read_artifact(path)
            if data:
                out[handoff_id] = data
        return out

    def _write_run_manifest(
        self,
        target: str,
        state: DispatchState,
        started_at: datetime,
        finished_at: datetime,
    ) -> Path | None:
        """Write a top-level run manifest with every (stage, agent, session,
        file_path) tuple — the routing key the orchestrator uses to
        reconstruct a run from disk.

        Layout: ``<artifact_root>/manifest.json`` (sibling of all wave dirs).

        Returns the path, or None if write fails.
        """
        try:
            self.artifact_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        manifest_path = self.artifact_root / "manifest.json"
        waves_meta: list[dict[str, Any]] = []
        for wave in WAVE_NAMES:
            ev = state.evidence.get(wave)
            if ev is None:
                continue
            spec = WAVES.get(wave)
            if spec is None:
                continue
            # Choose the primary agent the same way _write_artifact does
            if spec.fanout == "static_fanout" and spec.fanout_agents:
                primary_agent = spec.fanout_agents[0]
            elif spec.specialist:
                primary_agent = spec.specialist
            else:
                primary_agent = "multi"
            waves_meta.append(
                {
                    "stage": wave,
                    "agent": primary_agent,
                    "session_id": f"{wave}.{primary_agent}.1",
                    "schema": spec.evidence_schema,
                    "artifact_path": state.evidence_paths.get(wave),
                    "specialist_calls": state.fanout_counts.get(wave, 0),
                    "drill_in_count": sum(
                        1 for d in state.drill_ins
                        if d.parent_wave == wave
                    ),
                }
            )
        manifest = {
            "topic": "hack-deep run manifest",
            "target": target,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "wave_count": len(waves_meta),
            "errors": list(state.errors),
            "waves": waves_meta,
        }
        # 2026-06-08 (Issue 3): per-subdomain index. When the
        # per-subdomain driver populated ``state.per_subdomain_results``,
        # emit one entry per subdomain pointing at the per-subdomain
        # evidence root. Empty when running in single-pass mode.
        if state.per_subdomain_results:
            subdomain_index: list[dict[str, Any]] = []
            for sub, results in sorted(state.per_subdomain_results.items()):
                w4 = next((r for r in results if r.wave == "W4"), None)
                w8 = next((r for r in results if r.wave == "W8"), None)
                # 2026-06-08 (Issue 3): W8 is a static_fanout of
                # cleanup-rollback + reporting-remediation. The
                # report-v1 evidence carries the executive_summary;
                # the cleanup-v1 evidence is a checklist. We use
                # duck-typing on ``executive_summary`` to prefer the
                # report when both are merged into a single record.
                w8_report_evidence = None
                if w8 and w8.evidence is not None and hasattr(
                    w8.evidence, "executive_summary"
                ):
                    w8_report_evidence = w8.evidence
                subdomain_index.append(
                    {
                        "subdomain": sub,
                        "artifact_root": state.subdomain_artifact_roots.get(sub),
                        "w4_artifact_path": (
                            state.evidence_paths.get(f"__sub_{sub}__W4__")
                        ),
                        "w8_artifact_path": (
                            state.evidence_paths.get(f"__sub_{sub}__W8__")
                        ),
                        "w4_findings_verified": w4.findings_verified if w4 else 0,
                        "w4_findings_downgraded": w4.findings_downgraded if w4 else 0,
                        "w8_report": (
                            w8_report_evidence.executive_summary[:200]
                            if w8_report_evidence is not None
                            else None
                        ),
                    }
                )
            manifest["subdomain_index"] = subdomain_index
        try:
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            return None
        # Rebuild the compact in-prompt trail after every manifest write so
        # ``StepTrailRebuilderHook`` always sees a fresh mtime on its next read.
        self._maybe_rebuild_trail(state, target=target, started_at=started_at)
        return manifest_path

    def _maybe_rebuild_trail(
        self,
        state: DispatchState,
        *,
        target: str | None = None,
        started_at: datetime | None = None,
    ) -> Path | None:
        """Rebuild ``<artifact_root>/trail.md`` from state + on-disk evidence.

        Called from three chokepoints: ``run()`` (pre-wave, so the file
        exists on disk even for an empty run), ``_write_artifact`` (per
        parent-wave + per drill-slot write), and ``_write_run_manifest``
        (final pass, so the trail reflects the very last state).

        All exceptions are caught and logged to ``state.errors`` so a
        misbehaving trail producer cannot break a run.
        """
        try:
            return _trail_mod.rebuild_trail_markdown(
                self.artifact_root,
                state,
                target=target,
                started_at=started_at,
            )
        except OSError as exc:
            state.errors.append(f"trail.md rebuild failed (OSError): {exc}")
        except Exception as exc:  # noqa: BLE001 — never break a run for the trail
            state.errors.append(f"trail.md rebuild failed ({type(exc).__name__}): {exc}")
        return None
