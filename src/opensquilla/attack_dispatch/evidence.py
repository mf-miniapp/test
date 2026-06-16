"""14 evidence schemas — the typed contracts every wave's output must satisfy.

All schemas are Pydantic v2 models. All collection fields are ``list[...]``,
so subdomain / port / service / finding counts are unbounded (no
hardcoded limits). Every schema has:

- ``target``           : which scope the evidence is about
- ``produced_at``      : ISO-8601 timestamp
- ``evidence_version`` : schema version (defaults to ``v1``)

The 7 v3.1 fixes from the 51ifind.com pressure test are encoded as fields:
  fix 1: ROEEvidence.success_unit
  fix 2: OPSECEvidence.per_target_group
  fix 3: PenetrationEvidence.dynamic_sub_tracks
  fix 4: DrillInSpec.reason_class (in drill_in.py)
  fix 5: ReconEvidence.infra_sharing
  fix 6: ReportEvidence.per_target_finding
  fix 7: in the executor — W3 allows 2 in-wave sub-calls

The 2026-06-07 multi-target expansion adds:
  + W0.5 → SubTargetHandleList (handles + target_queue)
  + ReconEvidence.parent_domain (link to main domain)
  + ReconEvidence.rate_limit_hits / PenetrationEvidence.rate_limit_hits
  + ReportEvidence.global_finding_index (cross-target view)
  + GlobalFinding sub-schema (cvss / cve / affected_targets / fix_priority)

No field has a max_length or fixed size; ports / subdomains / findings are
all open-ended lists.

Result Marker status enum
-------------------------
``ResultStatus`` is shared with ``attack_dispatch.envelope`` so the typed
Pydantic evidence model and the parser agree on the literal set.
``complete | partial | failed`` is the canonical triplet used both inside
evidence payloads and in the subagent's final reply footer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Shared with attack_dispatch.envelope. Kept here as the Pydantic-typed
# Literal so evidence models can use it as a field type directly.
ResultStatus = Literal["complete", "partial", "failed"]


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class EvidenceBase(BaseModel):
    """Common fields for every evidence record."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        ...,
        description="Scope this evidence is about (domain, IP, or asset_id).",
    )
    produced_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this evidence was produced (UTC).",
    )
    evidence_version: Literal["v1"] = "v1"
    # 2026-06-07: W4/W5/W6 specialists declare newly-discovered subdomains
    # / hidden services / pivots in this field. The executor scans it,
    # pushes to state.target_queue, and records an emit_new_target
    # drill-in spec for audit. The field is meta — it does not affect
    # the evidence's substantive content.
    emit_new_target: Optional[list[str]] = Field(
        default=None,
        description=(
            "Optional list of new targets the specialist discovered "
            "(subdomains / pivots / hidden services). Consumed by the "
            "executor; not part of the evidence payload."
        ),
    )


# ---------------------------------------------------------------------------
# fix 1: ROE must include success_unit
# ---------------------------------------------------------------------------


class ROEEvidence(EvidenceBase):
    """W0 engagement-planning output. Defines the Rules of Engagement."""

    evidence_schema: Literal["roe-v1"] = "roe-v1"
    scope_summary: str
    allowed_assets: list[str] = Field(default_factory=list)
    forbidden_assets: list[str] = Field(default_factory=list)
    time_window: dict[str, str] = Field(default_factory=dict)
    success_unit: Literal["per-port", "per-host", "per-domain"] = Field(
        ...,
        description="Granularity at which 'owned' is measured. fix 1.",
    )
    success_criteria: list[str] = Field(default_factory=list)
    phase_plan: list[dict[str, Any]] = Field(default_factory=list)

    # 2026-06-14 (bb-methodology adoption): engagement type gate.
    # Drives W4 finding filter and W8 report shape. Borrowed verbatim
    # from bb-methodology PART 0.
    #   bug_bounty     : impact-demonstrated bugs ONLY (H1 / Bugcrowd)
    #   red_team       : hygiene + recon + IoCs + chains (client deliverable)
    #   pentest        : depends on signed SoW; usually hygiene + impact + recon
    #   internal_audit : compliance-mapped (PCI / ISO / NIST / DPDPA / GDPR)
    engagement_type: Literal[
        "bug_bounty", "red_team", "pentest", "internal_audit"
    ] = Field(
        default="red_team",
        description=(
            "Engagement type — drives W4 finding filter and W8 report shape. "
            "Adopted from bb-methodology PART 0 (Claude-BugHunter). Default "
            "is red_team to match OpenSquilla deployment posture."
        ),
    )
    # 2026-06-14 (scope.py DSL adoption): in-scope pattern DSL.
    # Mirrors Claude-BugHunter Scope pattern language: bare apex
    # (example.com matches apex + any subdomain), *.wildcard.example.com
    # (any subdomain, NOT bare apex), exact host, CIDR (10.0.0.0/8), or
    # re:^regex$ for custom matches. Deny-wins / default-deny is
    # enforced in code by opensquilla.attack_dispatch.scope_matcher.
    # allowed_assets (free-form) stays as-is for backward-compat; new
    # scope_patterns is the *structured* form the code layer can match
    # deterministically without LLM interpretation.
    scope_patterns: list[str] = Field(
        default_factory=list,
        description=(
            "2026-06-14. Structured in-scope patterns using the "
            "Claude-BugHunter scope DSL: bare apex, *.wildcard, "
            "exact host, CIDR (10.0.0.0/8), or re:^regex$. "
            "Deny-wins + default-deny semantics enforced by "
            "attack_dispatch.scope_matcher. Empty list = "
            "scope_matcher only consults allowed_assets / "
            "forbidden_assets via the legacy whole-string match."
        ),
    )
    # 2026-06-14 (/hunt redteam/wapt split): per-mode severity gate.
    # Adopts Claude-BugHunter /hunt two-track dispatcher behavior:
    #   red_team: only critical/high (medium only if it chains)
    #   wapt:     full OWASP coverage incl. medium
    # Drives W8 per-finding inclusion filter. Defaults to the gate
    # implied by engagement_type if not explicitly set.
    severity_gate: list[Literal["critical", "high", "medium", "low", "info"]] = Field(
        default_factory=lambda: ["critical", "high", "medium", "low", "info"],
        description=(
            "2026-06-14. Severity tiers that pass into the W8 report. "
            "Adopted from /hunt redteam/wapt split. Default = all tiers. "
            "ROE planner should set this per engagement: bug_bounty -> "
            "['critical','high']; red_team -> ['critical','high']; "
            "pentest -> ['critical','high','medium']; internal_audit -> all."
        ),
    )
    # 2026-06-14 (redteam-mindset adoption): mandatory-cadence flags.
    # bb-methodology "Real-engagement cadence" section enumerates
    # what a COMPLETE sweep per live host looks like (top-100 path
    # probe, robots.txt read, JS bundle grep, source-map check, etc.).
    # These booleans make the cadence auditable in the W8 report.
    cadence: dict[str, bool] = Field(
        default_factory=lambda: {
            "top_100_path_probe": True,
            "robots_txt_read": True,
            "sitemap_xml_read": True,
            "js_bundle_grep": True,
            "source_map_check": True,
            "form_sqli_marker_sweep": True,
            "auth_bypass_class_sweep": True,
            "openapi_endpoint_full_coverage": True,
        },
        description=(
            "2026-06-14. Mandatory-cadence flags from bb-methodology. "
            "Each key is a sweep step the W4 specialist committed to "
            "running per live host. W8 reports the cadence completion "
            "ratio; engagements below 80% are flagged as incomplete."
        ),
    )


# ---------------------------------------------------------------------------
# fix 5: W1 recon must include infra_sharing
# ---------------------------------------------------------------------------


class InfraSharingEntry(BaseModel):
    """One row in the W1 infra_sharing table.

    Tells W6 lateral which assets share infra — the primary cross-subdomain
    attack vector.
    """

    model_config = ConfigDict(extra="forbid")

    subdomain: str
    ip: str
    asn: str | None = None
    cidr: str | None = None
    ssl_cert_fp: str | None = None
    js_bundle_hash: str | None = None
    shared_with: list[str] = Field(
        default_factory=list,
        description="Other subdomains that share at least one of asn/cidr/cert/hash.",
    )


class ServiceEntry(BaseModel):
    """One observed (host, port, service) tuple. Unlimited count."""

    model_config = ConfigDict(extra="forbid")

    host: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str
    banner: str | None = None
    version: str | None = None
    tls: dict[str, Any] | None = None
    vector_class: Literal["web", "api", "service", "db", "mgmt", "other"] = "other"
    # 2026-06-09 (Issue 10 — reachability reporting).
    # When the recon specialist confirms the service is
    # REACHABLE (banner grabbed, HTTP response received,
    # DB handshake completed, etc.), the LLM MUST populate
    # this field with the **complete** URL/address — not
    # just the port. The W8 report and operator-facing
    # output rely on this field to give the reader a
    # copy-paste-able target (e.g. ``http://10.0.0.5:9090
    # /metrics``, ``postgres://db.internal:5432``,
    # ``redis://10.1.2.3:6379/0``). When the service is
    # NOT reachable (filtered, timeout, refused), the
    # field stays ``None``. Old artifacts without this
    # field still construct (default=None) so the change
    # is backward-compat.
    url: str | None = Field(
        default=None,
        description=(
            "2026-06-09 (Issue 10). The complete reachable URL "
            "or address the recon specialist verified is "
            "live. E.g. ``http://10.0.0.5:9090/metrics``, "
            "``https://api.target.com:443/v1/health`` for HTTP, "
            "``postgres://db.internal:5432``, "
            "``redis://10.1.2.3:6379/0``, "
            "``mongodb://10.0.0.7:27017/admin``. Required "
            "when the service is reachable; ``None`` when "
            "filtered / timed-out / refused. W8 reporting "
            "and the operator UI surface this verbatim."
        ),
    )
    # 2026-06-09 (Issue 10). Compact ``host:port`` form for
    # non-URL protocols (raw TCP, raw UDP, ICMP). When the
    # service has a ``url`` (e.g. HTTP) the W8 report
    # prefers that; for everything else this is the
    # canonical "where was this thing found" pointer.
    host_port: str | None = Field(
        default=None,
        description=(
            "2026-06-09 (Issue 10). The canonical "
            "``host:port`` string (e.g. ``10.0.0.5:9090``, "
            "``db.internal:5432``). Always populated when "
            "the service is reachable, even when ``url`` is "
            "also populated. W8 reporting uses this when no "
            "``url`` is available (e.g. raw TCP / UDP "
            "services that don't speak an application "
            "protocol)."
        ),
    )
    reachability: Literal[
        "reachable",
        "filtered",
        "timeout",
        "refused",
        "unknown",
    ] = "unknown"
    # 2026-06-09 (Issue 10). Free-text evidence the
    # specialist used to confirm reachability. E.g.
    # ``"9090 returned JSON {status:ok,version:0.45.0}"``,
    # ``"banner: OpenSSH_8.2"``,
    # ``"TCP handshake completed; received 0 bytes"``.
    # Required when ``reachability="reachable"`` so the
    # W8 report can show *why* we believe it's live (and
    # operators can verify by curl / nmap themselves).
    reachability_proof: str | None = None

    @model_validator(mode="after")
    def _reachable_requires_address(self) -> "ServiceEntry":
        """2026-06-09 (Issue 10). When the LLM marks a service
        ``reachability="reachable"``, the schema REQUIRES at
        least one of ``url`` or ``host_port`` to be set.

        The 51ifind.com W8 report repeatedly surfaced rows
        like "Prometheus 可达 是（9090 端口返回 JSON）高"
        that were missing the actual URL — operators had
        to guess the right path (/metrics vs /-/healthy vs
        /api/v1/query). Forcing the LLM to write the
        complete ``http://target:9090/metrics`` (or
        ``target:9090`` for non-HTTP) closes the gap.

        Old artifacts with ``reachability="unknown"`` and
        no URL still construct (the validator only fires
        on explicit "reachable").
        """
        if self.reachability == "reachable":
            if not self.url and not self.host_port:
                raise ValueError(
                    "ServiceEntry with reachability='reachable' MUST "
                    "set at least one of `url` (e.g. "
                    "'http://10.0.0.5:9090/metrics') or `host_port` "
                    "(e.g. '10.0.0.5:9090'). Reporting 'reachable' "
                    "without a complete address makes the W8 report "
                    "un-actionable; see Issue 10."
                )
        return self


class SubTargetHandle(BaseModel):
    """One per-subdomain handle emitted by W0.5 target-expansion.

    W0.5 produces a list of these via ``SubTargetHandleList``. W1.5 consumes
    them as its fan-out basis; the executor can also append to them at
    runtime when W4/W5/W6 emit new targets (see emit_new_target in
    executor._scan_emit_new_target).
    """

    model_config = ConfigDict(extra="forbid")

    subdomain: str
    parent_domain: str
    status: Literal[
        "discovered", "in_progress", "owned", "failed", "untested"
    ] = "discovered"
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this subdomain was first observed.",
    )


class ReconEvidence(EvidenceBase):
    """W1 recon output. Asset-agnostic: lists of arbitrary length."""

    evidence_schema: Literal["recon-v1"] = "recon-v1"
    parent_domain: Optional[str] = Field(
        default=None,
        description=(
            "Main domain this recon is scoped to. None when recon is on the "
            "main domain itself; set to the parent when this recon is the "
            "per-subdomain pass (W1.5)."
        ),
    )
    subdomains: list[str] = Field(default_factory=list)
    dns_records: list[dict[str, Any]] = Field(default_factory=list)
    services: list[ServiceEntry] = Field(default_factory=list)
    tech_stack: dict[str, list[str]] = Field(default_factory=dict)
    certs: list[dict[str, Any]] = Field(default_factory=list)
    infra_sharing: list[InfraSharingEntry] = Field(
        default_factory=list,
        description="fix 5: ASN / CIDR / cert / JS-bundle sharing across subdomains.",
    )
    next_steps: list[str] = Field(default_factory=list)
    rate_limit_hits: int = Field(
        default=0,
        description=(
            "Number of times the recon pass hit a rate-limit / 429 / WAF block. "
            "Visible to the orchestrator so it can throttle later waves."
        ),
    )
    scan_profile: Literal["light", "medium", "full"] = Field(
        default="full",
        description=(
            "Recon scan depth profile added 2026-06-10 by the recon coverage "
            "gap fix. `light` = top-1000 ports + no dir-bust; `medium` = "
            "top-10000 ports + small wordlist; `full` (default) = 1-65535 "
            "all-port scan via naabu + service fingerprint via nmap + "
            "raft-medium directory brute via ffuf/feroxbuster/gobuster. "
            "ROE may downgrade this field to narrow the scan surface."
        ),
    )
    port_scan_complete: bool = Field(
        default=False,
        description=(
            "True iff W1 recon completed a full 1-65535 SYN scan and recorded "
            "all open ports in `services`. Used by the W1.5c expand scan wave "
            "and the attack-surface-enumeration agent to gate its "
            "`priority_top_n` ordering on real port evidence, not on the "
            "filtered 4-port stub that was being returned before the recon "
            "coverage fix."
        ),
    )
    dir_bust_evidence: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Dictionary of directory/file brute-force results added 2026-06-10. "
            "Keys are the tool name (`ffuf` / `feroxbuster` / `gobuster`), "
            "values are lists of discovered paths. Empty dict means either "
            "no dir-bust was run, or it ran but found nothing. Used by the "
            "W1.5c expand scan wave and the attack-surface-enumeration agent "
            "to gate its `priority_top_n` on real dir-bust evidence."
        ),
    )


# ---------------------------------------------------------------------------
# W1.2 intel-collection
# ---------------------------------------------------------------------------


class IntelEvidence(EvidenceBase):
    """W1.2 OSINT output. Asset-agnostic."""

    evidence_schema: Literal["intel-v1"] = "intel-v1"
    sources: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"
    next_actions: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# W1.3 attack-surface-enumeration
# ---------------------------------------------------------------------------


class SurfaceEvidence(EvidenceBase):
    """W1.3 attack-surface output."""

    evidence_schema: Literal["surface-v1"] = "surface-v1"
    asset_map: list[dict[str, Any]] = Field(default_factory=list)
    entrypoints: list[dict[str, Any]] = Field(default_factory=list)
    trust_boundaries: list[dict[str, Any]] = Field(default_factory=list)
    priority_top_n: list[dict[str, Any]] = Field(default_factory=list)
    followup_plan: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# W2 vulnerability-triage
# ---------------------------------------------------------------------------


class TriageEvidence(EvidenceBase):
    """W2 triage output."""

    evidence_schema: Literal["triage-v1"] = "triage-v1"
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    verification_paths: list[dict[str, Any]] = Field(default_factory=list)
    prioritized_top_n: list[dict[str, Any]] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)

    # 2026-06-14 (bb-methodology adoption): disclosed-report pattern
    # grounding. The triage specialist is expected to ground each
    # candidate in patterns distilled from real public reports
    # (HackerOne / Bugcrowd / GitHub Security Advisories). The
    # structured form mirrors the frontmatter of Claude-BugHunter
    # ``hunt-*`` skills (see bundled/hunt-* SKILL.md files for the
    # canonical examples). Each entry references a known public
    # report by source + id so W8 reporting can cite it. Pattern
    # matching against the bundled ``hunt-*`` skills happens in
    # the executor's `_rank_candidates` step.
    disclosed_report_patterns: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "2026-06-14. Patterns distilled from public disclosures "
            "the triage grounded each candidate in. Each entry has "
            "shape: {vuln_class, source (hackerone_public | "
            "bugcrowd | github_security_advisories | snyk_research | "
            "sonarsource_research), report_id, cve (optional), "
            "tech_stack (optional), pattern_summary, payload_template, "
            "bypass_table (optional)}. Empty list = candidate was "
            "novel (no public pattern match) and carries an extra "
            "uncertainty marker."
        ),
    )
    # 2026-06-14 (bb-methodology adoption): class-level knowledge
    # density. Lets W8 report cite which ``hunt-*`` SKILL.md was
    # consulted during triage, mirroring Claude-BugHunter's
    # `bb-methodology` reference table.
    hunt_skills_consulted: list[str] = Field(
        default_factory=list,
        description=(
            "2026-06-14. Names of bundled ``hunt-*`` skills the "
            "triage specialist loaded as knowledge references. "
            "Mirrors Claude-BugHunter's per-class skill map. "
            "W8 surfaces the consulted-skill list in the report's "
            "methodology section so reviewers can audit the "
            "grounding depth."
        ),
    )


# ---------------------------------------------------------------------------
# 2026-06-11 (v4.0 R3 S2): W2.5 port attack plan
# ---------------------------------------------------------------------------


class AttackVectorPlan(BaseModel):
    """One attack vector against a single port.

    W2.5 produces a list of these per-port (per-port + vector 拆,
    high complexity). Each vector carries its own tool sequence,
    prerequisites, success probability, and fallback vectors.

    `attack_class` reuses the ExploitationTechnique Literal from
    PenetrationFinding so downstream W4 sub-tracks can match the
    vector directly without translation.
    """

    model_config = ConfigDict(extra="forbid")

    vector_name: str = Field(
        ...,
        description=(
            "Short stable id, e.g. 'ssh_weak_creds', 'sql_injection', "
            "'rce_deserialization'. Used as W4 sub-track key."
        ),
    )
    attack_class: ExploitationTechnique = Field(
        ...,
        description=(
            "Reuses PenetrationFinding.ExploitationTechnique Literal so "
            "W4 can match vector_class → AttackVectorPlan without translation."
        ),
    )
    tool_sequence: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered tool sequence, e.g. ['hydra -L users.txt -P pass.txt "
            "ssh://target:22', 'ssh-audit target:22']. Free-form strings; "
            "executor runs them sequentially."
        ),
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description=(
            "Free-form prerequisites, e.g. ['credential_wordlist_present', "
            "'ssh_port_22_reachable', 'no_fail2ban']. Empty = no prereq."
        ),
    )
    success_probability: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "LLM-estimated probability of producing an owned foothold via "
            "this vector. Used for sorting in priority_top_n; NOT a hard gate."
        ),
    )
    fallback_vectors: list[str] = Field(
        default_factory=list,
        description=(
            "vector_name references for fallback if this vector fails. "
            "Cross-references AttackVectorPlan.vector_name within the same "
            "PortAttackPlanEntry.attack_vectors list."
        ),
    )


class PortAttackPlanEntry(BaseModel):
    """One port's full attack plan.

    Built by W2.5 from a single ReconEvidence.services entry. Contains
    1+ AttackVectorPlan entries (per-port + vector 拆). Output priority
    drives the order W4 picks sub-tracks.
    """

    model_config = ConfigDict(extra="forbid")

    service_entry_ref: str = Field(
        ...,
        description=(
            "Stable ref into ReconEvidence.services, e.g. 'services[3]' "
            "or 'host:port' (e.g. '10.0.0.5:3306'). Used by W4 to look up "
            "the upstream ServiceEntry for tool chaining."
        ),
    )
    host: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str
    vector_class: VectorClass = "other"
    priority: Literal["P0", "P1", "P2", "P3"] = "P3"
    attack_vectors: list[AttackVectorPlan] = Field(
        default_factory=list,
        description=(
            "1+ attack vectors against this port. Empty list means no viable "
            "vector identified — W4 should treat this port as low-value."
        ),
    )
    estimated_success_probability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "Aggregate probability across all attack_vectors (max). Used "
            "by attack-surface-enumeration.priority_top_n sort."
        ),
    )
    estimated_runtime_s: int = Field(
        default=300,
        ge=1,
        description="Estimated total runtime across all vectors (seconds).",
    )
    tool_chain: list[str] = Field(
        default_factory=list,
        description=(
            "Flat union of attack_vectors[*].tool_sequence for fast executor "
            "introspection. W4 picks the first vector whose prereqs are met."
        ),
    )
    notes: str | None = None


class PortAttackPlanEvidence(EvidenceBase):
    """W2.5 output. Per-port attack plan ready for W4 sub-track split.

    v4.0 (2026-06-11): the W2.5 wave is dynamic_fanout with bucket=6.
    Each sub-track emits one PortAttackPlanEvidence; the executor merges
    them into a combined record with all plan_entries concatenated.

    W4 reads `plan_entries` and groups by vector_class to spawn sub-tracks.
    """

    evidence_schema: Literal["port-attack-plan-v1"] = "port-attack-plan-v1"
    plan_entries: list[PortAttackPlanEntry] = Field(
        default_factory=list,
        description=(
            "One entry per reachable port. Sorted by priority (P0 first) "
            "then by estimated_success_probability desc."
        ),
    )
    total_ports_planned: int = Field(
        default=0,
        ge=0,
        description="Count of plan_entries (== count of reachable services).",
    )
    total_vectors: int = Field(
        default=0,
        ge=0,
        description="Sum of attack_vectors length across all plan_entries.",
    )
    skipped_ports: list[str] = Field(
        default_factory=list,
        description=(
            "host:port strings for services that were excluded from the plan "
            "(e.g. filtered / timed-out / no viable vector). Surfaced to "
            "W8 report so the operator sees what was NOT attacked."
        ),
    )


# ---------------------------------------------------------------------------
# 2026-06-11 (v4.0 R4 S3): W3.5 web crawl
# ---------------------------------------------------------------------------


class WebCrawlEvidence(EvidenceBase):
    """W3.5 output. Per-web-service crawl results.

    v4.0 (2026-06-11): the W3.5 wave is dynamic_fanout with bucket=4.
    Each sub-track emits one WebCrawlEvidence per web service (vector_class
    in {web, api} or service in {http, https, http-alt, http-proxy}).

    Outputs feed W4 by giving penetration specialists a pre-built path
    inventory: hidden_paths become attack entries directly;
    extracted_endpoints become parameter-fuzz candidates;
    auth_required_paths become authenticated sub-track candidates.
    """

    evidence_schema: Literal["web-crawl-v1"] = "web-crawl-v1"
    target_url: str = Field(
        ...,
        description=(
            "Complete URL with scheme + host + port, e.g. "
            "'https://target:443' or 'http://10.0.0.5:8080'. Mirrors "
            "ServiceEntry.url convention from Issue 10 (2026-06-09)."
        ),
    )
    crawl_tool_results: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "key=tool_name (katana/waybackurls/subjs/jsluice/etc.), "
            "value=discovered URLs/paths from that tool. Empty dict = "
            "crawl ran but found nothing. Used by attack-surface to "
            "verify crawl actually executed."
        ),
    )
    discovered_js_files: list[str] = Field(
        default_factory=list,
        description=(
            "JS file URLs discovered during crawl. W4 penetration reads "
            "these for endpoint extraction (linkfinder / jsluice pass 2)."
        ),
    )
    extracted_endpoints: list[str] = Field(
        default_factory=list,
        description=(
            "API endpoints / form actions / AJAX targets extracted from "
            "JS + HTML during crawl. W4 routes these to vector_class='api'."
        ),
    )
    hidden_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Paths returned by waybackurls + ffuf / recursive crawling that "
            "are NOT in the live sitemap. Capped at 100 per service (LLM-side "
            "truncate). W4 penetration reads these as primary attack entries."
        ),
    )
    auth_required_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Paths that returned 401/403 during crawl. W4 routes these to "
            "authenticated sub-tracks (default-cred bruteforce / JWT "
            "fuzzing / session-cookie replay)."
        ),
    )
    total_urls: int = Field(
        default=0,
        ge=0,
        description="Sum of all discovered URL/path counts.",
    )
    crawl_runtime_s: int = Field(
        default=0,
        ge=0,
        description="Actual runtime of this sub-track (seconds).",
    )


# ---------------------------------------------------------------------------
# fix 2: W3 opsec must include per_target_group
# ---------------------------------------------------------------------------


class PerTargetGroup(BaseModel):
    """One stealth-tweak row in W3's per_target_group table."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    strategy: str
    stop_signal: str


class OPSECEvidence(EvidenceBase):
    """W3 opsec output. Per-target stealth plans."""

    evidence_schema: Literal["opsec-v1"] = "opsec-v1"
    noise_hotspots: list[str] = Field(default_factory=list)
    low_interference_strategy: list[str] = Field(default_factory=list)
    audit_requirements: list[str] = Field(default_factory=list)
    stop_rollback_criteria: list[str] = Field(default_factory=list)
    per_target_group: list[PerTargetGroup] = Field(
        default_factory=list,
        description="fix 2: per-target stealth tweaks (W3 wide-noise case).",
    )


# ---------------------------------------------------------------------------
# fix 3: W4 penetration — dynamic sub-tracks
# v3.2 (2026-06-07): full rewrite to be the strongest possible pentest
# contract. Each finding now carries the structured request/response,
# classification (CWE/OWASP/MITRE), CVSS 3.1 base score, chain metadata,
# auth context, ROE compliance flag, and structured reproduction. The
# footholds list is typed so W5/W6/W7 can read it. The 2026-06-07
# hack-deep W4.1 V001 IDOR incident exposed the gap: the old free-text
# schema gave the LLM no structural constraint, so it could produce a
# "I tried login, password wrong" result with no chain, no auth context,
# no CVSS, no RoE guard — and the parent had no way to roll forward.
# See docs/hack-deep.md §5.5 for the field rationale.
# ---------------------------------------------------------------------------


# 2026-06-14 (triage-validation adoption): 7-Question Gate.
# Borrowed verbatim from Claude-BugHunter `triage-validation` SKILL.md
# (the 7-Question Gate section). The Gate is a post-collection
# filter that the W4 specialist fills per finding; the W8 reporter
# consumes it to drop findings that fail any "fail" answer. Each
# question maps to one of the 7 gate questions; the executor
# auto-downgrades a finding to `partial` if any QAResult.verdict is
# 'fail'. The `reasons` field carries the free-text reasoning
# verbatim so the W8 report can cite the gate verdicts in the
# finding body.
QAVerdict = Literal["pass", "fail", "unknown"]


class QAResult(BaseModel):
    """One answer in the 7-Question Gate.

    The ``verdict`` is the discriminator; ``reason`` is the
    free-text rationale the W4 specialist typed (the W8 report
    surfaces it verbatim so reviewers can audit the gate call).
    ``evidence_ref`` optionally points at a piece of supporting
    evidence (e.g. an H1 report id, a CVSS vector, a chain entry).
    """

    model_config = ConfigDict(extra="forbid")

    verdict: QAVerdict = "unknown"
    reason: str = Field(default="", description="Free-text rationale the W8 report cites verbatim.")
    evidence_ref: str | None = Field(
        default=None,
        description=(
            "Optional pointer to supporting evidence: an H1 report id, "
            "a CVSS vector, a chain entry, etc. The W8 report can "
            "render this as a footnote link."
        ),
    )


class SevenQuestionGate(BaseModel):
    """The 7-Question Gate applied to one PenetrationFinding.

    All 7 questions are required (i.e. always present) so the
    executor can index the verdict set without None handling. A
    finding WITHOUT a `seven_question_gate` field is legacy (no
    gate applied); a finding WITH the field but any 'fail' answer
    is auto-downgraded to `partial` by the executor.

    The question semantics (verbatim from upstream):

    * Q1: Can an attacker use this RIGHT NOW, step by step?
    * Q2: Is the impact on the engagement's accepted impact list?
    * Q3: Is the root cause in an in-scope asset? (mirrors
          roe_violation=False semantically; a fail here duplicates
          the ROE guard but the report cites it for human review.)
    * Q4: Does it require privileged access that an attacker can't
          realistically get?
    * Q5: Is this already known or accepted behavior?
    * Q6: Is it part of an A->B->C chain (or chainable)?
    * Q7: Does it map to the engagement's accepted business impact?
    """

    model_config = ConfigDict(extra="forbid")

    q1_attacker_usable: QAResult = Field(default_factory=QAResult)
    q2_impact_accepted: QAResult = Field(default_factory=QAResult)
    q3_in_scope: QAResult = Field(default_factory=QAResult)
    q4_privilege_realistic: QAResult = Field(default_factory=QAResult)
    q5_not_known: QAResult = Field(default_factory=QAResult)
    q6_chainable: QAResult = Field(default_factory=QAResult)
    q7_business_impact: QAResult = Field(default_factory=QAResult)
    # Convenience: which engagement_type's gate policy was applied.
    # Defaults to None for legacy findings; the W8 report reads
    # this to render the right gate section heading.
    applied_engagement_type: Optional[str] = Field(
        default=None,
        description=(
            "The engagement_type whose gate policy was applied. "
            "Mirrors ROEEvidence.engagement_type so the W8 report "
            "can show the same gate shape in the finding body."
        ),
    )

    def any_fail(self) -> bool:
        """True iff any question verdict is 'fail'."""
        for q in (
            self.q1_attacker_usable,
            self.q2_impact_accepted,
            self.q3_in_scope,
            self.q4_privilege_realistic,
            self.q5_not_known,
            self.q6_chainable,
            self.q7_business_impact,
        ):
            if q.verdict == "fail":
                return True
        return False

    def fail_questions(self) -> list[str]:
        """Return the q-ids (e.g. ['q1_attacker_usable']) that failed."""
        out: list[str] = []
        for qid, q in (
            ("q1_attacker_usable", self.q1_attacker_usable),
            ("q2_impact_accepted", self.q2_impact_accepted),
            ("q3_in_scope", self.q3_in_scope),
            ("q4_privilege_realistic", self.q4_privilege_realistic),
            ("q5_not_known", self.q5_not_known),
            ("q6_chainable", self.q6_chainable),
            ("q7_business_impact", self.q7_business_impact),
        ):
            if q.verdict == "fail":
                out.append(qid)
        return out


# Auth context — what level of authentication was needed to trigger the
# finding. Critical for impact: anonymous RCE >> admin-only RCE.
AuthContext = Literal[
    "anonymous",                # no auth needed; public access
    "authenticated_low_privilege",  # any logged-in user (e.g. customer)
    "authenticated_user",       # standard user role
    "authenticated_admin",      # admin / superuser / root in app context
    "internal_only",            # requires VPN / internal network / SSRF pivot
]


# Exploitation technique — 30+ common types covering SQLi/NoSQLi/CMDi/
# template/SSTI/deserialization/XXE/auth/session/JWT/OAuth/IDOR/BOLA/
# BFLA/path traversal/LFI/RFI/crypto/misconfig/race condition/business
# logic/rate-limit/supply-chain/SSRF. The "other" escape hatch is for
# novel attacks; LLM should pick the closest match.
ExploitationTechnique = Literal[
    # Injection family
    "injection_sql",
    "injection_nosql",
    "injection_command",
    "injection_ldap",
    "injection_xpath",
    "injection_template",       # SSTI (Jinja, Twig, Freemarker, etc.)
    "injection_header",         # CRLF, host header injection
    "injection_xss_reflected",
    "injection_xss_stored",
    "injection_xss_dom",
    "injection_ssrf",
    "injection_xxe",
    "injection_xinclude",
    "injection_deserialization",  # Python pickle, Java, PHP, Node
    # Auth / Session family
    "broken_auth_credential",
    "broken_auth_session",
    "broken_auth_oauth",
    "broken_auth_jwt",
    "broken_auth_oidc",
    "broken_auth_saml",
    # Access control family
    "broken_access_idor",
    "broken_access_bola",        # Broken Object Level Authorization (API)
    "broken_access_bfla",        # Broken Function Level Authorization
    "broken_access_path_traversal",
    "broken_access_lfi",         # Local File Inclusion
    "broken_access_rfi",         # Remote File Inclusion
    # Crypto family
    "broken_crypto_weak",
    "broken_crypto_known_vuln",
    "broken_crypto_padding_oracle",
    # Misconfig family
    "misconfig_default_creds",
    "misconfig_unprotected_endpoint",
    "misconfig_verbose_error",
    "misconfig_cors",
    "misconfig_open_bucket",
    "misconfig_dangerous_method",  # PUT/DELETE/TRACE enabled
    # Logic family
    "race_condition_toctou",
    "business_logic_skew",       # workflow state machine bypass
    "business_logic_price_manipulation",
    "business_logic_quantity_manipulation",
    # Limits family
    "rate_limit_absent",
    "rate_limit_bypass",
    "resource_exhaustion",
    # Supply chain family
    "supply_chain_typosquat",
    "supply_chain_dep_confusion",
    "vulnerable_component_known_cve",
    # Other
    "info_disclosure_verbose",
    "other",
]


# OWASP Top 10 2021 classification
OwaspTop10 = Literal[
    "A01_broken_access_control",
    "A02_cryptographic_failures",
    "A03_injection",
    "A04_insecure_design",
    "A05_security_misconfiguration",
    "A06_vulnerable_components",
    "A07_identification_auth_failures",
    "A08_software_data_integrity_failures",
    "A09_security_logging_monitoring_failures",
    "A10_ssrf",
    "none",
]


# CVSS 3.1 severity bucket
CVSSSeverity = Literal["none", "low", "medium", "high", "critical"]


# Auth context in the request that triggered the finding
DataExposed = Literal[
    "pii",
    "phi",
    "financial",
    "credentials",
    "secrets",
    "source_code",
    "internal_docs",
    "system_config",
    "session_tokens",
    "pii_financial",
]


# Impact categories (CIA + accountability)
ImpactCategory = Literal["confidentiality", "integrity", "availability", "accountability"]


# Vector class — the kind of entry point
VectorClass = Literal["web", "api", "service", "db", "mgmt", "mobile", "iot", "other"]


# Confidence level
Confidence = Literal["confirmed", "high", "medium", "low"]


# How the finding was discovered
DiscoverySource = Literal[
    "manual_probing",
    "automated_scan",
    "fuzzing",
    "chained_from_prior_finding",
    "intel_collection",
    "recon_followup",
    "ai_hypothesis",
    "leaked_secret_lookalike",
    "cve_database_lookup",
]


# Finding status
FindingStatus = Literal[
    "owned",         # confirmed PoC, access gained
    "confirmed",     # confirmed vulnerable, no PoC achieved
    "partial",       # partial exploitation, partial impact
    "blocked",       # couldn't exploit (WAF, rate-limit, auth, schema mismatch)
    "in_progress",   # actively working
    "fail",          # tried, didn't work, but documented
]


# Sub-track status
SubTrackStatus = Literal[
    "pending",
    "in_progress",
    "owned",         # at least one entry owned (foothold produced)
    "partial",       # some findings, no owned
    "blocked",       # WAF/rate-limit/auth blocked progress
    "fail",          # couldn't make progress
]


# Foothold type — the actual access gained
FootholdType = Literal[
    "rce_shell",            # interactive shell on the target
    "rce_code_exec",        # one-shot code execution (no interactive)
    "credential",           # username:password / token / API key
    "session",              # authenticated session (cookie, JWT, OAuth)
    "file_read",            # arbitrary file read primitive
    "file_write",           # arbitrary file write primitive
    "db_access",            # DB user, can SELECT/INSERT/UPDATE/DELETE
    "ssrf",                 # SSRF primitive (can make requests as server)
    "internal_access",      # pivot into internal network
    "admin_panel",          # access to admin UI/API
    "service_account",      # compromised service-to-service cred
    "cloud_metadata",       # cloud IMDS access (169.254.169.254, etc.)
    "vpn",                  # VPN access
    "remote_desktop",       # RDP/SSH interactive
]


# Persistence level — how stable the access is
PersistenceLevel = Literal[
    "ephemeral",            # gone after process restart / session timeout
    "session",              # lasts the current user session
    "user",                 # tied to a user account
    "system",               # tied to a system account (machine compromise)
    "root",                 # full system control
]


# Cleanup difficulty
CleanupDifficulty = Literal["trivial", "easy", "moderate", "hard", "irreversible"]


# HTTP body type
BodyType = Literal[
    "json", "form", "multipart", "raw", "binary", "graphql", "xml", "soap", "none"
]


# Transport for the exploit request
Transport = Literal[
    "http", "https", "tcp", "udp", "icmp", "smb", "ssh", "ftp", "dns", "smtp", "ldap", "rdp", "other"
]


class AttackClassification(BaseModel):
    """Standard classification: CWE + OWASP Top 10 + MITRE ATT&CK + technique.

    All three (CWE / OWASP / MITRE) are the de-facto industry
    classifications that W8 reporting needs to produce CVE-style
    reports. ``exploitation_technique`` is the granular operational
    category the orchestrator uses to drive W5/W6 (e.g. a
    ``injection_command`` finding directly enables the W5 privesc
    sub-track that looks for SUID binaries on the foothold).
    """

    model_config = ConfigDict(extra="forbid")

    cwe_id: str | None = Field(
        default=None,
        description="CWE identifier, e.g. 'CWE-89' (SQLi) or 'CWE-22' (path traversal).",
    )
    owasp_top10_2021: OwaspTop10 = "none"
    mitre_attack: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs, e.g. ['T1190', 'T1059.004'].",
    )
    exploitation_technique: ExploitationTechnique = "other"


class CVSSScore(BaseModel):
    """CVSS 3.1 base score with full vector.

    The vector string is the canonical form; the decomposed fields
    (av / ac / pr / ui / s / c / i / a) are denormalized for fast
    read. base_score and severity are derived from those metrics —
    we trust the LLM to compute them but the field names are
    standardized so the orchestrator doesn't have to re-parse.
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal["3.0", "3.1"] = "3.1"
    base_score: float = Field(ge=0.0, le=10.0)
    severity: CVSSSeverity = "none"
    vector: str = Field(
        ...,
        description="CVSS 3.1 vector string, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'",
    )
    av: Literal["N", "A", "L", "P"] = "N"
    ac: Literal["L", "H"] = "L"
    pr: Literal["N", "L", "H"] = "N"
    ui: Literal["N", "R"] = "N"
    s: Literal["U", "C"] = "U"
    c: Literal["H", "L", "N"] = "N"
    i: Literal["H", "L", "N"] = "N"
    a: Literal["H", "L", "N"] = "N"


class ExploitRequest(BaseModel):
    """One exploit request, captured verbatim. Critical for evidence preservation
    and reproduction. The LLM MUST fill this with the actual HTTP/TCP/whatever
    request, not paraphrase it.
    """

    model_config = ConfigDict(extra="forbid")

    method: str = Field(default="GET", description="HTTP method or verb (e.g. 'GET', 'POST', 'SMB-Negotiate').")
    url: str = Field(default="", description="Full URL or 'proto://host:port/path' for non-HTTP.")
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Request headers as a flat dict (lowercased keys preferred).",
    )
    body: str | None = Field(
        default=None,
        description="Request body verbatim. Truncate to a reasonable size; long payloads go to input_artifacts.",
    )
    body_type: BodyType = "none"
    transport: Transport = "http"
    # For non-HTTP, the protocol-level details (e.g. SMB tree, gRPC service)
    raw_protocol_fields: dict[str, Any] = Field(default_factory=dict)


class ExploitResponse(BaseModel):
    """The response from the exploit request — proof of impact.

    The ``proof_type`` field is the discriminator for downstream
    consumers: W5 (privesc) only acts on ``rce_shell`` /
    ``service_account`` / ``file_read`` footholds; W6 (lateral) only
    acts on ``session`` / ``credential`` / ``internal_access``;
    W7 (impact) only acts on ``db_access`` / ``data_exfil``.
    """

    model_config = ConfigDict(extra="forbid")

    status_code: int | None = Field(
        default=None,
        description="HTTP status code. None for non-HTTP transports.",
    )
    headers: dict[str, str] = Field(default_factory=dict)
    body_snippet: str | None = Field(
        default=None,
        description="Truncated response body (≤ 4KB). Sensitive values are redacted by the LLM.",
    )
    proof_type: Literal[
        "shell",                 # got RCE / interactive shell
        "code_exec",             # one-shot code execution output
        "credential",            # recovered username:password, token, API key
        "file_read",             # sensitive file contents
        "file_write",            # uploaded file or modified system file
        "db_dump",               # extracted DB rows / schema
        "data_exfil",            # PII / secrets / financial data
        "session_hijack",        # admin session / cookie stolen
        "auth_bypass",           # accessed protected resource w/o valid auth
        "idor_data",             # saw another user's data
        "ssrf_response",         # got internal response via SSRF
        "redirect_chain",        # OAuth / open-redirect exploit
        "deserialization_trigger",  # triggered deserialization
        "info_disclosure",       # leaked config / stack trace / version
        "config_change",         # made a config change (e.g. disabled WAF)
        "none",                  # no proof (e.g. theoretical or blocked)
    ] = "none"
    proof_artifact: str | None = Field(
        default=None,
        description="Optional path to a screenshot / pcap / full response file in the evidence archive.",
    )


class ReproduceStep(BaseModel):
    """One step in a structured reproduction recipe.

    The old ``list[str]`` in the free-text schema was too vague for
    the orchestrator to validate or replay. Each step is now a
    structured tool call with an explicit expected vs observed
    outcome. ``outcome_match`` lets the orchestrator detect
    flaky / time-sensitive PoCs (e.g. a race condition that only
    reproduces 1-in-5) and adjust W5's confidence.
    """

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(ge=1)
    tool: str = Field(
        description=(
            "Tool or technique used in this step. Examples: 'curl', 'sqlmap', "
            "'nuclei', 'burp', 'metasploit', 'ffuf', 'gobuster', 'manual', "
            "'python', 'custom_script'."
        ),
    )
    command: str = Field(
        description=(
            "The actual command / payload / request. Backticks / multi-line "
            "OK; the orchestrator captures this verbatim for the W8 report."
        ),
    )
    expected_outcome: str = Field(
        description=(
            "What the LLM predicted would happen. Used by the W8 report "
            "to show the reader what to look for."
        ),
    )
    observed_outcome: str | None = Field(
        default=None,
        description=(
            "What actually happened. May differ from expected (e.g. timing "
            "differences, WAF variance, race conditions)."
        ),
    )
    outcome_match: bool | None = Field(
        default=None,
        description=(
            "True iff observed matches expected. False / None lowers the "
            "finding's confidence (W8 marks the finding as 'flaky' "
            "and may require manual re-verification)."
        ),
    )
    # 2026-06-08 (hack-deep v3.3, Issue 2): per-step verifier timeout
    # override. The default verifier timeout is 30 seconds; long
    # steps (nuclei templates, masscan, multi-step sqlmap injections)
    # can be hours. A specialist can declare the upper bound for the
    # runtime verifier on a per-step basis. When ``None``, the
    # verifier's default applies.
    verifier_timeout_s: float | None = Field(
        default=None,
        ge=0.1,
        le=3600.0,
        description=(
            "Optional per-step timeout for the executor's "
            "``SubprocessFindingVerifier`` (seconds). When ``None``, "
            "the verifier's default (30s) applies. Specialists should "
            "set this to a realistic upper bound for long-running "
            "tools (e.g. ``600`` for nuclei/masscan). The hard cap is "
            "3600s; longer steps must be split into multiple "
            "ReproduceStep entries."
        ),
    )
    # 2026-06-09 (hack-deep v3.4, Issue 5 — body-content verification).
    # The runtime verifier previously did a substring match of
    # ``expected_outcome`` against the captured stdout/stderr. That
    # matched a 200 OK HTTP status from a curl whose body clearly
    # indicated failure (``{"success":false,"error":"Login failed"}``)
    # whenever the LLM's ``expected_outcome`` was a relaxed token like
    # ``"200"`` or ``"vulnerable"``. Two new fields close the gap:
    #
    # * ``failure_markers`` — case-insensitive substrings whose
    #   presence in the body (combined stdout+stderr) PROVES the
    #   exploit FAILED, regardless of HTTP status. E.g. ``"login
    #   failed"``, ``"access denied"``, ``"invalid credentials"``,
    #   ``"\"success\":false"``. The verifier treats the first match
    #   as a hard fail with ``failure_reason="body_indicates_failure"``
    #   and downgrades the finding to ``partial``.
    #
    # * ``body_required_substrings`` — case-insensitive substrings
    #   that ALL must appear in the body for the exploit to count
    #   as owned. E.g. for an IDOR that returns another user's data,
    #   the LLM must declare the unique field(s) the response
    #   should contain (``"admin@victim.local"``, ``"role\":\"admin"``).
    #   The verifier treats a missing required substring as
    #   ``failure_reason="body_missing_required_marker"`` and
    #   downgrades the finding to ``partial``.
    #
    # Both lists default to empty for backward-compat with old
    # artifacts. Specialists that produce HTTP-based reproduce
    # steps MUST populate them (the W4 brief footer enforces this
    # contract).
    failure_markers: list[str] = Field(
        default_factory=list,
        description=(
            "2026-06-09 (Issue 5). Case-insensitive substrings whose "
            "presence in the captured response PROVES the exploit "
            "FAILED (regardless of HTTP status code). The verifier "
            "scans the combined stdout+stderr for the FIRST match; "
            "on match it downgrades the finding to ``partial`` with "
            "``failure_reason=\"body_indicates_failure\"``. Example "
            "for an auth-bypass PoC: ``[\"login failed\", \"access "
            "denied\", \"invalid credentials\", \"\\\"success\\\":false\"]``."
        ),
    )
    body_required_substrings: list[str] = Field(
        default_factory=list,
        description=(
            "2026-06-09 (Issue 5). Case-insensitive substrings that "
            "ALL must appear in the captured response for the "
            "exploit to count as owned. A missing required substring "
            "downgrades the finding to ``partial`` with "
            "``failure_reason=\"body_missing_required_marker\"``. "
            "Example for an IDOR: ``[\"admin@victim.local\", "
            "\"role\\\":\\\"admin\\\"\"]`` — the response must contain "
            "both, otherwise the verifier rejects the claim."
        ),
    )
    notes: str | None = None


class PenetrationFinding(BaseModel):
    """One penetration finding. Tied to (entry_id, vector_class).

    This is the load-bearing type for the W4 wave. W5/W6/W7/W8 all
    read fields from here. Backward-compat: the old free-text fields
    (status, evidence_ref, impact_summary, reproduce_steps as list[str])
    are kept as optional fallbacks so old callers and existing
    test doubles still construct. New fields are added with defaults.
    """

    model_config = ConfigDict(extra="forbid")

    # Identity
    entry_id: str
    vector_class: VectorClass = "other"
    title: str = Field(default="", description="One-line summary the W8 report will headline.")

    # Status + classification
    status: FindingStatus = "in_progress"
    blocked_reason: str | None = Field(
        default=None,
        description=(
            "When status='blocked', why progress was blocked: WAF / 429 / "
            "auth / schema mismatch / etc. Free text but structured "
            "enumeration of common causes is preferred."
        ),
    )
    confidence: Confidence = "medium"
    classification: AttackClassification = Field(default_factory=AttackClassification)
    cvss: CVSSScore | None = None

    # Authentication context — critical for triage
    auth_context: AuthContext = "anonymous"

    # Evidence: the actual request and response
    request: ExploitRequest | None = None
    response: ExploitResponse | None = None
    # Backward-compat shim: free-text refs for callers that don't have
    # the full request/response. W8 prefers the structured form.
    evidence_ref: str = ""
    impact_summary: str = ""

    # Impact
    impact_categories: list[ImpactCategory] = Field(default_factory=list)
    data_exposed: list[DataExposed] = Field(default_factory=list)

    # Reproduction
    reproduce_steps: list[ReproduceStep] = Field(default_factory=list)
    # Backward-compat shim: list[str] of free-text steps. The LLM
    # should prefer the structured ``reproduce_steps`` above; this is
    # kept for old test doubles and quick hand-offs.
    reproduce_steps_legacy: list[str] = Field(default_factory=list)

    # Tooling attribution
    tool_used: str | None = None
    manual_effort_minutes: int | None = Field(
        default=None,
        ge=0,
        description="Manual time spent on this finding (excludes tool runtime).",
    )

    # Chain metadata
    chain_id: str | None = None
    follows_from: list[str] = Field(
        default_factory=list,
        description="Other entry_ids this finding depends on (e.g. V003 RCE follows from V001 IDOR).",
    )
    enables: list[str] = Field(
        default_factory=list,
        description="Other entry_ids this finding makes possible (next-wave hint).",
    )

    # Out-of-scope guard (ROE compliance)
    roe_violation: bool = False
    roe_violation_detail: str | None = None

    # Origin
    discovered_by: DiscoverySource = "manual_probing"
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Cleanup (drives W8.1)
    leaves_traces: bool = True
    cleanup_required: bool = True
    cleanup_notes: str | None = None

    # ------------------------------------------------------------------
    # 2026-06-08 (hack-deep v3.3, Issue 2): runtime verification.
    # The executor's ``SubprocessFindingVerifier`` re-runs
    # ``reproduce_steps[0].command`` for every finding whose
    # ``verification_required`` is True AND ``status`` is in
    # ``{owned, confirmed}``. The verifier patches the finding's
    # ``verified`` / ``verification_artifact`` /
    # ``verification_failure_reason`` fields and downgrades the
    # status to ``partial`` on failure.
    #
    # Backward-compat: old artifacts (no ``verification_required``
    # field) Pydantic-coerce to True so verification runs by default.
    # This is the "must verify with scripts first" contract the user
    # requested in Issue 2.
    # ------------------------------------------------------------------
    verification_required: bool = Field(
        default=True,
        description=(
            "2026-06-08 (Issue 2). Whether the executor's "
            "``SubprocessFindingVerifier`` should re-run this finding's "
            "first reproduce step. Defaults to True; specialists may set "
            "to False for low-risk info-disclosure findings whose "
            "reproduce is itself a destructive action (e.g. a wipe of "
            "a target file) that should not be replayed."
        ),
    )
    # 2026-06-09 (Issue 5 — body-content verification). When True
    # (default), the verifier additionally enforces
    # ``ReproduceStep.failure_markers`` (substring → fail) and
    # ``ReproduceStep.body_required_substrings`` (substring → must
    # appear) on every owned/confirmed finding. Specialists may set
    # to False for findings whose primary PoC is a non-HTTP primitive
    # (e.g. an RCE shell command where stdout IS the proof and any
    # shell-level error pattern would be a non-issue). HTTP-based
    # findings should ALWAYS leave this True — the 200-OK-with-failed-
    # body false positive is the canonical regression this guards
    # against.
    body_verification_required: bool = Field(
        default=True,
        description=(
            "2026-06-09 (Issue 5). Whether the executor's verifier "
            "should additionally enforce ``failure_markers`` and "
            "``body_required_substrings`` on this finding's "
            "``reproduce_steps[*]``. Defaults to True; set to False "
            "only for non-HTTP primitives where stdout IS the proof."
        ),
    )
    verified: bool | None = Field(
        default=None,
        description=(
            "2026-06-08 (Issue 2). Runtime verification result: True if "
            "the executor re-ran ``reproduce_steps[0].command`` and the "
            "output matched ``expected_outcome``; False on a verifier "
            "failure (timeout, exit-nonzero, match-miss); None when the "
            "verifier has not yet run OR the finding's "
            "``verification_required`` is False."
        ),
    )
    verification_artifact: str | None = Field(
        default=None,
        description=(
            "2026-06-08 (Issue 2). Absolute path to the per-finding "
            "verifier log JSON on disk. The log contains the captured "
            "stdout, stderr, returncode, and the matched-vs-expected "
            "comparison. ``None`` when the verifier has not run."
        ),
    )
    verification_failure_reason: str | None = Field(
        default=None,
        description=(
            "2026-06-08 (Issue 2). Short tag explaining why "
            "``verified`` is False. One of: ``timeout`` / "
            "``exit_nonzero`` / ``match_miss`` / ``no_reproduce_steps`` / "
            "``verifier_disabled``. 2026-06-09 (Issue 5) adds two "
            "body-content failure tags: ``body_indicates_failure`` "
            "(a substring in ``failure_markers`` matched the "
            "response) and ``body_missing_required_marker`` (one or "
            "more substrings in ``body_required_substrings`` were "
            "absent). ``None`` when verified is True or None."
        ),
    )

    # 2026-06-14 (triage-validation adoption): 7-Question Gate.
    # The W4 specialist runs the gate per finding; the W8 reporter
    # reads it to drop findings that fail any "fail" answer. The
    # executor auto-downgrades a finding to ``partial`` when this
    # field is set AND ``seven_question_gate.any_fail()`` returns
    # True. Legacy findings (no field) skip the gate entirely.
    # The gate semantics are documented on ``SevenQuestionGate``.
    seven_question_gate: Optional["SevenQuestionGate"] = Field(
        default=None,
        description=(
            "2026-06-14. The 7-Question Gate verdict set the W4 "
            "specialist applied to this finding. Optional for "
            "backward-compat; when set, the executor auto-"
            "downgrades the finding to ``partial`` on any fail. "
            "Adopted from Claude-BugHunter triage-validation "
            "SKILL.md (the 7-Question Gate section)."
        ),
    )


class Foothold(BaseModel):
    """A concrete access gained by an exploit.

    Required for the privesc (W5), lateral (W6), persist (W7) waves
    — they all read the footholds list to know what's available to
    escalate from. ``type`` is the discriminator (see FootholdType).
    Cleanup metadata is what W8.1 needs to undo.

    ``persistence_level`` drives the W7 sub-track: ``ephemeral`` is
    not worth a persistence sub-track; ``root`` definitely is.
    """

    model_config = ConfigDict(extra="forbid")

    foothold_id: str = Field(description="Stable id, e.g. 'FH-001' or 'FH-V001-1'.")
    parent_finding: str = Field(description="entry_id of the PenetrationFinding that produced it.")
    type: FootholdType
    target_host: str
    target_port: int | None = Field(default=None, ge=1, le=65535)
    target_user: str | None = None
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    persistence_level: PersistenceLevel = "session"
    # Cleanup
    cleanup_difficulty: CleanupDifficulty = "easy"
    cleanup_notes: str | None = None
    # Chaining hint to the next wave
    enables: list[str] = Field(
        default_factory=list,
        description=(
            "Hints to the orchestrator: 'privesc' / 'lateral' / 'persist' / "
            "'impact' / specific entry_ids to try next."
        ),
    )


class SubTrack(BaseModel):
    """One penetration sub-track in the dynamic fan-out.

    Replaces the old ``list[dict]`` sub_tracks. Each sub-track has a
    handoff_id, a vector_class it covers, an entry count, and a
    status. The orchestrator can correlate the sub-track's output
    with the parent wave's specialist fan-out plan (count =
    entry_count // SUB_TRACK_BUCKET_SIZE).
    """

    model_config = ConfigDict(extra="forbid")

    handoff_id: str = Field(description="e.g. 'W4.penetration.1'.")
    vector_class: VectorClass
    entry_count: int = Field(ge=0)
    status: SubTrackStatus = "pending"
    started_at: datetime | None = None
    ended_at: datetime | None = None
    notes: str | None = None
    findings_count: int = Field(default=0, ge=0)
    footholds_count: int = Field(default=0, ge=0)


class PenetrationEvidence(EvidenceBase):
    """W4 penetration output. Dynamic sub-tracks; count = entry_count // 8.

    v3.2 (2026-06-07): complete rewrite to be the strongest possible
    pentest contract. See PenetrationFinding / Foothold / SubTrack /
    AttackClassification / CVSSScore / ReproduceStep docstrings for
    the field rationale. The schema name stays ``pentest-v1`` for
    backward compat; the data shape is fully typed.
    """

    evidence_schema: Literal["pentest-v1"] = "pentest-v1"

    sub_tracks: list[SubTrack] = Field(
        default_factory=list,
        description="Dynamic sub-track breakdown (count = entry_count // 8). fix 3.",
    )
    findings: list[PenetrationFinding] = Field(default_factory=list)
    footholds: list[Foothold] = Field(default_factory=list)

    # Operator guidance for the next wave
    next_agent: str | None = None
    next_actions: list[str] = Field(
        default_factory=list,
        description="Free-text hints to the W5/W6 orchestrator (concrete next steps).",
    )

    # Throttling visibility
    rate_limit_hits: int = Field(
        default=0,
        description="Total times the penetration pass hit a rate-limit / 429 / WAF block.",
    )
    rate_limit_per_vector: dict[VectorClass, int] = Field(
        default_factory=dict,
        description="Rate-limit hits broken down by vector_class so the orchestrator can throttle selectively.",
    )

    # ROE compliance
    out_of_scope_hits: int = Field(
        default=0,
        description="Number of times the LLM tried an action that was out of scope (ROE violation).",
    )
    scope_violations: list[str] = Field(
        default_factory=list,
        description="Free-text list of ROE violations the LLM noticed and rolled back.",
    )

    # Methodology audit (PTES-aligned; required for W8.2 reporting)
    methodology_steps: list[str] = Field(
        default_factory=list,
        description=(
            "The PTES phases executed in this sub-track. Required for "
            "compliance audits: 'pre-engagement' / 'intelligence_gathering' / "
            "'threat_modeling' / 'vulnerability_analysis' / 'exploitation' / "
            "'post_exploitation' / 'reporting'."
        ),
    )

    # Coverage / gap analysis — feeds the W2 drill-in trigger
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description="Areas the LLM didn't cover (e.g. 'mobile app not tested', 'no DB injection attempted').",
    )
    suggested_drill_in: list[str] = Field(
        default_factory=list,
        description="Specific drill-in reasons the LLM recommends the orchestrator open (slot names + reason classes).",
    )

    # ------------------------------------------------------------------
    # 2026-06-08 (hack-deep v3.3, Issue 2): runtime-verification
    # aggregates. ``verifier_version`` records which verifier protocol
    # ran (empty string when verification was skipped).
    # ``unverified_findings`` lists the entry_ids the LLM claimed as
    # owned/confirmed but the verifier rejected — surfaced to W8.2
    # reporting as a confidence penalty.
    # ------------------------------------------------------------------
    verifier_version: str = Field(
        default="",
        description=(
            "2026-06-08 (Issue 2). Protocol version of the executor's "
            "``SubprocessFindingVerifier`` that ran against this "
            "evidence's findings. Empty string when verification was "
            "skipped (verifier disabled, or no owned/confirmed findings)."
        ),
    )
    unverified_findings: list[str] = Field(
        default_factory=list,
        description=(
            "2026-06-08 (Issue 2). entry_ids of findings the LLM claimed "
            "as ``owned`` or ``confirmed`` but the executor's verifier "
            "rejected (match-miss, timeout, exit-nonzero, etc.). These "
            "findings were auto-downgraded to ``status=partial``; the "
            "W8.2 reporting-remediation specialist must surface this "
            "list to the operator and may adjust the engagement's "
            "overall confidence."
        ),
    )


# ---------------------------------------------------------------------------
# W5 privilege-escalation
# ---------------------------------------------------------------------------


class PrivescEvidence(EvidenceBase):
    """W5 output.

    `current_access` is intentionally a `dict[str, Any]` (not a strict
    sub-model) for backward-compatibility with v1 W5 implementations, but
    the 7 expected keys are now documented as `PrivescCurrentAccessKey`:

      - ``os``     — current OS context: user, hostname, kernel, arch
      - ``net``    — current network context: interfaces, IPs, open ports,
                     routing table, ARP/NDP neighbors
      - ``proc``   — running process enumeration: pid, user, cmdline, env
      - ``cron``   — scheduled tasks: crontab entries, systemd timers,
                     launchd plists
      - ``env``    — environment variables (full export dump)
      - ``creds``  — credential material found on-host: ssh keys, .netrc,
                     cloud credential files, browser-stored tokens
      - ``suid``   — SUID / SGID / capability-bearing binaries on host

    All 7 keys are optional. The agent is expected to fill whichever are
    available; missing keys simply mean the agent didn't discover that
    category. Added 2026-06-10 by R3 P0 S17.
    """

    evidence_schema: Literal["privesc-v1"] = "privesc-v1"
    current_access: dict[str, Any] = Field(default_factory=dict)
    escalation_vectors: list[dict[str, Any]] = Field(default_factory=list)
    safe_validation_plan: list[dict[str, Any]] = Field(default_factory=list)
    next_agent: str | None = None
    # 2026-06-11 (v4.0 R5 S4): W4 gate. True iff W4 produced no
    # owned/partial foothold and the executor skipped W5/W6/W7
    # directly to W8 reporting. NOT an error — the operator's
    # W8 report reads this flag to render the "no intrusion path
    # found, surface summarized instead" branch.
    gate_skipped: bool = Field(
        default=False,
        description="2026-06-11 (v4.0). True iff W4 gate skipped this wave.",
    )


# 2026-06-10 R3 P0 S17: documented TypedDict for the 7 expected keys.
# Not enforced at runtime (would break v1 implementations); used by tests
# and SOUL.md documentation to ensure consistent key naming.
PrivescCurrentAccessKey = Literal["os", "net", "proc", "cron", "env", "creds", "suid"]


# ---------------------------------------------------------------------------
# W0.6 resource-checkpoint (R3 S24)
# ---------------------------------------------------------------------------


class ResourceEntry(BaseModel):
    """One resource (skill / bin / wordlist / payload) the agent may need.

    Produced by W0.6 to enumerate the runtime environment before any
    specialist starts work. ``available=False`` triggers a soft warning
    (not a hard failure — W0.6 is fail-open by design).
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    bin_path: Optional[str] = None
    version: Optional[str] = None
    available: bool = True
    source: Literal["skill", "bin", "wordlist", "payload"] = "skill"


class ResourceEvidence(EvidenceBase):
    """W0.6 output. Enumerates what's actually available in the runtime."""

    evidence_schema: Literal["resource-v1"] = "resource-v1"
    available_skills: list[ResourceEntry] = Field(default_factory=list)
    available_bins: list[ResourceEntry] = Field(default_factory=list)
    available_wordlists: list[ResourceEntry] = Field(default_factory=list)
    available_payloads: list[ResourceEntry] = Field(default_factory=list)
    missing: list[ResourceEntry] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# W6 lateral-movement — reads ReconEvidence.infra_sharing
# ---------------------------------------------------------------------------


class LateralEvidence(EvidenceBase):
    """W6 output."""

    evidence_schema: Literal["lateral-v1"] = "lateral-v1"
    pivot_points: list[dict[str, Any]] = Field(default_factory=list)
    discovered_hosts: list[dict[str, Any]] = Field(default_factory=list)
    lateral_steps: list[dict[str, Any]] = Field(default_factory=list)
    risk_rollback_notes: list[str] = Field(default_factory=list)
    next_agent: str | None = None
    # 2026-06-11 (v4.0 R5 S4): see PrivescEvidence.gate_skipped.
    gate_skipped: bool = Field(default=False)


# ---------------------------------------------------------------------------
# W7 persistence-maintenance
#
# 2026-06-08 v2: restructured from a thin ``options: list[dict]`` into
# typed sub-models. The 51ifind.com W7 session optimization report
# (2026-06-08) flagged 10 pain points; the typed models below encode
# the fixes inline so the runtime can validate, the W7 brief can
# point at them by name, and the LLM is structurally pushed to fill
# the right fields (topology map, output target, pass criteria,
# verification timing) before the loop can produce a passing option.
#
# Schema name stays ``persist-v1`` for backward compat; the data shape
# is now fully typed. Old dict-shaped options are still accepted
# (Pydantic coerces dict into the new sub-model) so the migration is
# non-breaking for previously-serialized artifacts.
# ---------------------------------------------------------------------------


class TopologyHop(BaseModel):
    """One hop in the request chain that a persistence vector traverses.

    Forces the specialist to enumerate the layer-by-layer topology
    (client → edge → gateway → backend) BEFORE writing a verification
    script. Fixes pain point #1 (请求链路发现不够系统化).
    """

    model_config = ConfigDict(extra="forbid")

    layer: Literal[
        "client", "edge", "cdn", "waf", "load_balancer", "reverse_proxy",
        "api_gateway", "app_server", "module", "backend", "datastore",
        "sidecar", "filesystem", "kernel", "other",
    ]
    component: str = Field(..., description="Software/component name (e.g. OpenResty, Kong, Apache, mod_lua).")
    version: str | None = None
    config_path: str | None = Field(default=None, description="Where its config lives, e.g. /etc/openresty/nginx.conf.")
    log_path: str | None = Field(default=None, description="Where its log lives, e.g. /var/log/apache2/error.log.")
    reachable_via: str | None = Field(default=None, description="How to reach this layer from the prior hop, e.g. 51ifind.com:8093 HTTPS.")


class OutputTarget(BaseModel):
    """Where the persistence payload's effect actually surfaces.

    Fixes pain point #2 (mod_lua 输出位置判断混乱). The LLM must pick
    the right output target — for mod_lua it's ``error_log``, for
    header injection it's ``response_header``, for a sidecar file
    write it's ``written_file`` (with a verification_timing to avoid
    the read-after-write race, see #6).
    """

    model_config = ConfigDict(extra="forbid")

    location: Literal[
        "response_header", "response_body", "error_log", "access_log",
        "written_file", "jwt_token", "cookie", "database_row",
        "external_artifact", "process_state", "kernel_object",
        "other",
    ]
    path: str | None = Field(default=None, description="File path / URL / header name / DB table, depending on location.")
    expected_marker: str = Field(..., description="Substring expected in the output to confirm a write/read roundtrip worked.")


class PassCriterion(BaseModel):
    """One explicit PASS condition for a persistence verification.

    Multiple criteria can be AND'd. The runtime / report reader
    requires ``pass_criteria`` to be non-empty for an option to count
    as 'owned'; this is what fixes pain point #5 (CONNECT 误判) and
    #7 (JWT token 验证不完整).
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "status_code", "header_present", "body_contains", "file_exists",
        "file_contains", "log_line_present", "token_decode",
        "token_decode_has_claim", "process_running", "db_row_present",
        "antipattern_observed", "other",
    ]
    expected: str = Field(..., description="What the verifier expects to see (e.g. '301', 'X-Kong-Upstream-Latency: 3', '/tmp/p01_test', 'iat <= now').")
    description: str | None = Field(default=None, description="Why this criterion is the right one (e.g. 'CONNECT 403 for RFC1918 is expected isolation, not a fail').")


class VerificationTiming(BaseModel):
    """Read-after-write timing discipline.

    Fixes pain point #6 (文件写入后未等待). The LLM must populate this
    for any option whose OutputTarget is ``written_file`` /
    ``external_artifact`` / ``database_row`` — the runtime will
    refuse to mark such an option as 'pass' if it tried to read the
    artifact before ``read_after_s`` elapsed.
    """

    model_config = ConfigDict(extra="forbid")

    read_after_s: float = Field(default=2.0, ge=0.0, le=60.0, description="Sleep before the first read.")
    poll_attempts: int = Field(default=3, ge=1, le=10, description="Max read attempts before declaring fail.")
    poll_interval_s: float = Field(default=1.0, ge=0.1, le=10.0, description="Sleep between poll attempts.")


class PersistenceOption(BaseModel):
    """One typed persistence vector. Replaces the old ``options: list[dict]``.

    All 10 pain points from the 2026-06-08 W7 session optimization
    report are encoded as required-or-default fields here:

    - #1 topology: ``topology_path`` (list[TopologyHop])
    - #2 output target: ``output_target`` (OutputTarget)
    - #3 single verification script: ``verification_script`` (str)
    - #4 explicit outcome: ``validation_outcome`` (pass|warn|fail|in_progress)
    - #5 CONNECT false negative: ``expected_behavior`` + ``antipatterns`` + ``pass_criteria``
    - #6 write race: ``verification_timing``
    - #7 parallel: ``parallel_verification`` (bool)
    - #8 cache: ``cache_key`` (str)
    - #9 uniform output: ``raw_evidence`` (proof_type + content)
    """

    model_config = ConfigDict(extra="forbid")

    option_id: str = Field(..., description="Stable id used in W7.next_agent and W8.1 cleanup (e.g. P01, P02, P03, P04).")
    title: str = Field(..., description="One-line title the W8 report headlines.")
    target_host: str
    target_port: int = Field(ge=1, le=65535)
    target_user: str | None = None
    mechanism: Literal[
        # File-level
        "cron_job", "systemd_unit", "init_script", "rc_local",
        "shell_profile", "ssh_authorized_keys", "ssh_config",
        "patched_binary", "ld_preload", "module_load",
        # Service-level
        "apache_module", "nginx_module", "lua_module", "cgi_script",
        "fastcgi_script", "sidecar_container", "config_include",
        # Identity-level
        "credential_rotation", "api_key_persist", "jwt_signing_key",
        "oauth_refresh_token", "service_account_token",
        # Network-level
        "iptables_rule", "route_persist", "vpn_tunnel", "port_knock",
        "reverse_tunnel", "ssh_reverse_tunnel",
        # Application-level
        "web_shell", "webhook_persist", "scheduled_task_app",
        "plugin_install", "theme_backdoor",
        # Data-level
        "db_trigger", "db_stored_proc", "git_hook",
        # Meta
        "other",
    ] = "other"
    topology_path: list[TopologyHop] = Field(
        default_factory=list,
        description="Layer-by-layer request chain this persistence touches. Empty = no infra-level involvement.",
    )
    output_target: OutputTarget = Field(..., description="Where the persistence effect surfaces (the verification reads from here).")
    expected_behavior: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Map of expected behaviors keyed by access mode. E.g. "
            "``{'connect': 403, 'http_proxy': 301}`` for a Squid-style "
            "gateway where CONNECT to internal IP returns 403 (expected "
            "isolation, NOT a fail) and HTTP proxy mode returns 301. "
            "Fixes pain point #5."
        ),
    )
    antipatterns: list[str] = Field(
        default_factory=list,
        description=(
            "Things that LOOK like failures but are not. E.g. "
            "``['CONNECT 403 on RFC1918 = expected isolation', "
            "'Apache 200 + 0-byte body = mod_lua loaded but no write yet']``. "
            "The verifier MUST check antipatterns before declaring fail."
        ),
    )
    pass_criteria: list[PassCriterion] = Field(
        default_factory=list,
        description="At least one PASS criterion required for an option to be 'owned'.",
    )
    verification_script: str = Field(
        default="",
        description=(
            "ONE complete verification script (shell / curl / python) that "
            "prints a structured PASS / WARN / FAIL line. Replaces the "
            "v1→v2→v3→v4 iteration pattern. Fixes pain points #3 + #4."
        ),
    )
    validation_outcome: Literal["pass", "warn", "fail", "in_progress", "blocked"] = Field(
        default="in_progress",
        description=(
            "Result of running verification_script. Must be set to "
            "pass/warn/fail by the LLM after ONE script run, not after "
            "iterating the script. Fixes pain point #4."
        ),
    )
    verification_timing: VerificationTiming | None = Field(
        default=None,
        description="Read-after-write discipline. Required when output_target.location is written_file / database_row / external_artifact. Fixes pain point #6.",
    )
    parallel_verification: bool = Field(
        default=True,
        description="If true, this option's verification can run concurrently with other options' verifications. Fixes pain point #7 (未使用批量验证).",
    )
    cache_key: str | None = Field(
        default=None,
        description=(
            "Stable cache key (e.g. '51ifind:80+8093+mod_lua+file_write'). "
            "On re-runs the executor can short-circuit the curl roundtrip "
            "by re-using the cached raw_evidence. Fixes pain point #8 "
            "(缺乏结果缓存)."
        ),
    )
    raw_evidence: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured proof, NOT a free-text blob. Must include "
            "``proof_type`` (one of OutputTarget.location), "
            "``proof_content`` (the actual marker/header/body), and "
            "``captured_at`` (ISO-8601). Replaces ad-hoc ``grep -o | "
            "head`` mixing. Fixes pain point #9."
        ),
    )
    cleanup_difficulty: Literal["trivial", "easy", "moderate", "hard", "irreversible"] = "moderate"
    cleanup_notes: list[str] = Field(default_factory=list)
    discovered_by: str = Field(default="manual_probing", description="manual_probing / chained_from_prior_finding / automated_scan / fuzzing / intel_collection / ...")
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    manual_effort_minutes: int = Field(default=0, ge=0)
    depends_on_foothold: str | None = Field(default=None, description="foothold_id from pentest-v1 evidence; this persistence rides on that foothold.")


class PersistEvidence(EvidenceBase):
    """W7.1 output. v2 (2026-06-08) — fully typed options.

    Schema name stays ``persist-v1``; data shape is now structured.
    The 10 pain points from the W7 session optimization report are
    encoded as fields on ``PersistenceOption`` + the new top-level
    ``topology_map`` / ``antipattern_log`` fields below.
    """

    evidence_schema: Literal["persist-v1"] = "persist-v1"
    # Map of the request chain as understood by the W7 specialist.
    # Built BEFORE writing any verification script. The runtime
    # validates that every option's ``topology_path`` is a contiguous
    # suffix of this map (you can't claim to write to a layer you
    # didn't enumerate).
    topology_map: list[TopologyHop] = Field(
        default_factory=list,
        description=(
            "Layer-by-layer request chain (client → edge → ... → "
            "backend) the W7 specialist derived from W6 evidence. "
            "Every option's topology_path MUST be a contiguous suffix "
            "of this map. Fixes pain point #1."
        ),
    )
    options: list[PersistenceOption] = Field(default_factory=list)
    # 2026-06-11 (v4.0 R5 S4): see PrivescEvidence.gate_skipped.
    gate_skipped: bool = Field(default=False)
    antipattern_log: list[str] = Field(
        default_factory=list,
        description=(
            "Cross-option log of things that LOOKED like failures but "
            "were actually expected (CONNECT 403 on internal IP, "
            "Apache 200 with empty body, etc.). Drives W8.2 narrative."
        ),
    )
    parallel_verification_used: bool = Field(
        default=True,
        description=(
            "True iff the W7 specialist ran the 4 persistence "
            "verifications in parallel. False = the specialist fell "
            "back to serial and lost context-window savings. Fixes "
            "pain point #7."
        ),
    )
    cache_keys_emitted: list[str] = Field(
        default_factory=list,
        description=(
            "List of cache_key values the W7 specialist wrote into "
            "options[]. Re-run the executor with these to skip "
            "duplicate curl roundtrips. Fixes pain point #8."
        ),
    )
    rollback_plan: list[str] = Field(default_factory=list)
    next_agent: str | None = None


# ---------------------------------------------------------------------------
# W7 impact-exfiltration
# ---------------------------------------------------------------------------


class ImpactEvidence(EvidenceBase):
    """W7.2 output."""

    evidence_schema: Literal["impact-v1"] = "impact-v1"
    impact_model: list[dict[str, Any]] = Field(default_factory=list)
    exfil_steps: list[dict[str, Any]] = Field(default_factory=list)
    data_handling: list[str] = Field(default_factory=list)
    next_agent: str | None = None
    # 2026-06-11 (v4.0 R5 S4): see PrivescEvidence.gate_skipped.
    gate_skipped: bool = Field(default=False)


# ---------------------------------------------------------------------------
# W8.1 cleanup-rollback
# ---------------------------------------------------------------------------


class CleanupEvidence(EvidenceBase):
    """W8.1 output."""

    evidence_schema: Literal["cleanup-v1"] = "cleanup-v1"
    cleanup_checklist: list[dict[str, Any]] = Field(default_factory=list)
    evidence_of_cleanup: list[dict[str, Any]] = Field(default_factory=list)
    risk_residual: list[str] = Field(default_factory=list)
    handoff_to_reporting: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# fix 6: W8.2 reporting-remediation — per_target_finding
# ---------------------------------------------------------------------------


class PerTargetFinding(BaseModel):
    """One per-target report row. Primary index of W8 output."""

    model_config = ConfigDict(extra="forbid")

    entry_id: str
    status: Literal["owned", "partial", "blocked", "fail", "untested"] = "untested"
    evidence_ref: str
    impact_ref: str | None = None
    # 2026-06-09 (Issue 10 — reachability reporting).
    # The complete reachable URL the W8 report surfaces
    # verbatim to the operator. E.g.
    # ``http://10.0.0.5:9090/metrics``,
    # ``https://api.target.com:443/v1/health``. Required
    # when the finding is on a reachable service; the
    # reporting-remediation specialist MUST copy this
    # from the upstream ``ServiceEntry.url`` (or
    # build it from ``ServiceEntry.host_port`` for
    # non-HTTP services). The operator-facing W8 UI
    # renders this as a clickable link.
    reachability_url: str | None = Field(
        default=None,
        description=(
            "2026-06-09 (Issue 10). Complete reachable URL "
            "for the finding. Mirrors the upstream "
            "``ServiceEntry.url`` from the W1 recon "
            "evidence (or is built from "
            "``ServiceEntry.host_port`` for non-HTTP "
            "services). Surfaced verbatim in the W8 "
            "report's per_target_finding row."
        ),
    )
    # 2026-06-09 (Issue 10). Canonical ``host:port`` form
    # for non-URL protocols. When ``reachability_url`` is
    # None (e.g. raw TCP / UDP service) the W8 report
    # falls back to this for the operator-facing row.
    reachability_host_port: str | None = Field(
        default=None,
        description=(
            "2026-06-09 (Issue 10). Canonical "
            "``host:port`` form (e.g. ``10.0.0.5:9090``). "
            "Mirrors the upstream ``ServiceEntry.host_port``."
        ),
    )

    @model_validator(mode="after")
    def _reachable_owned_finding_requires_address(self) -> "PerTargetFinding":
        """2026-06-09 (Issue 10). When the W8 reporting
        specialist marks a finding ``status="owned"`` or
        ``status="partial"`` (i.e. the recon service WAS
        reachable and the finding IS actionable), the
        schema REQUIRES at least one of
        ``reachability_url`` or ``reachability_host_port``
        to be set.

        The 51ifind.com W8 report repeatedly surfaced rows
        like "V001 — IDOR — owned — confidence high"
        without a copy-paste-able target. Forcing the
        reporting specialist to copy the upstream
        ``ServiceEntry.url`` (or build ``host_port`` for
        non-HTTP) closes the gap.

        ``untested`` / ``fail`` findings don't need an
        address (the operator can't act on them anyway).
        """
        if self.status in ("owned", "partial"):
            if not self.reachability_url and not self.reachability_host_port:
                raise ValueError(
                    "PerTargetFinding with status in {owned, partial} "
                    "MUST set at least one of `reachability_url` (e.g. "
                    "'http://target:9090/metrics') or "
                    "`reachability_host_port` (e.g. 'target:9090'). "
                    "Reporting an owned/partial finding without a "
                    "complete address makes the W8 report "
                    "un-actionable; see Issue 10."
                )
        return self


class GlobalFinding(BaseModel):
    """One cross-target finding row in W8 global_finding_index.

    Aggregates the same vulnerability across multiple subdomains / ports so
    the orchestrator / report reader can see "this CVE affects N targets"
    at a glance — complementary to per_target_finding (which is indexed by
    target, not by finding).
    """

    model_config = ConfigDict(extra="forbid")

    entry_id: str
    cvss: float = Field(default=0.0, ge=0.0, le=10.0)
    cve: str | None = None
    affected_targets: list[str] = Field(default_factory=list)
    fix_priority: Literal["P0", "P1", "P2", "P3"] = "P3"


class ReportEvidence(EvidenceBase):
    """W8.2 output. Primary index = per_target_finding, not vuln type. fix 6."""

    evidence_schema: Literal["report-v1"] = "report-v1"
    executive_summary: str
    per_target_finding: list[PerTargetFinding] = Field(
        default_factory=list,
        description="fix 6: report is indexed by entry_id, not by vulnerability type.",
    )
    global_finding_index: list[GlobalFinding] = Field(
        default_factory=list,
        description=(
            "2026-06-07: cross-target view — same vuln across multiple "
            "subdomains collapsed into one row, with affected_targets list."
        ),
    )
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    remediation_roadmap: list[dict[str, Any]] = Field(default_factory=list)
    appendix: dict[str, Any] = Field(default_factory=dict)

    # 2026-06-14 (triage-validation adoption): aggregate 7-Question
    # Gate results. The W8 specialist runs the gate per-finding and
    # writes the summary here so the report's header can render
    # pass/fail rates. Mirrors the ``bb-methodology``-style
    # "submission gate" that bug-bounty platforms apply to incoming
    # reports. The CLI / PDF exporter reads these fields to render
    # the gate section without re-walking every per_target_finding.
    #
    # Field semantics:
    #   gate_engagement_type : mirrors ROEEvidence.engagement_type
    #                          so the W8 header can show the right
    #                          gate policy (bug_bounty / red_team /
    #                          pentest / internal_audit).
    #   gate_total_findings  : count of per_target_finding rows.
    #   gate_passed_findings : count where status is "owned" AND
    #                          seven_question_gate is set AND no fail.
    #                          Status of "partial" or "blocked" is
    #                          NOT counted as pass.
    #   gate_failed_findings : count where seven_question_gate is
    #                          set AND any_fail() is True. Surfaced
    #                          in the report's "Submission Gate
    #                          Failures" section with the entry_ids
    #                          + failed-question ids.
    #   gate_skipped_findings: count where seven_question_gate is
    #                          NOT set (legacy / opt-in findings).
    #                          Surfaced as informational, NOT a fail.
    #   gate_pass_rate       : pass / (pass + fail) float in [0, 1].
    #                          When pass + fail == 0, returns 1.0
    #                          (no gated findings = 100% pass).
    #   gate_failed_entry_ids: list of entry_ids that failed. Sorted
    #                          for stable output.
    gate_engagement_type: Optional[str] = Field(
        default=None,
        description=(
            "2026-06-14. The engagement_type whose gate policy the "
            "W8 specialist applied. Mirrors "
            "ROEEvidence.engagement_type. One of: bug_bounty, "
            "red_team, pentest, internal_audit."
        ),
    )
    gate_total_findings: int = Field(default=0, ge=0)
    gate_passed_findings: int = Field(default=0, ge=0)
    gate_failed_findings: int = Field(default=0, ge=0)
    gate_skipped_findings: int = Field(default=0, ge=0)
    gate_pass_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    gate_failed_entry_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# W0.5 target-expansion (2026-06-07)
# ---------------------------------------------------------------------------


class SubTargetHandleList(EvidenceBase):
    """W0.5 output. Per-subdomain handles + extracted target_queue.

    ``handles`` is the full structured list; ``target_queue`` is the
    flat subdomain list the executor reads for W1.5 fan-out. The
    validator dedupes ``handles`` by ``subdomain`` (first occurrence
    wins) and rebuilds ``target_queue`` from the deduped list so the
    two fields never drift — this makes the schema robust to W0.5's
    3-fanout merge, where the same subdomain can show up in all three
    specialist outputs.
    """

    evidence_schema: Literal["sub_target_handle-v1"] = "sub_target_handle-v1"
    handles: list[SubTargetHandle] = Field(default_factory=list)
    target_queue: list[str] = Field(
        default_factory=list,
        description=(
            "Flat list of subdomains extracted from handles[].subdomain. "
            "Rebuilt by the validator so it stays in sync with handles."
        ),
    )

    @model_validator(mode="after")
    def _dedupe_handles_and_rebuild_target_queue(self) -> "SubTargetHandleList":
        seen: set[str] = set()
        deduped: list[SubTargetHandle] = []
        for h in self.handles:
            if h.subdomain in seen:
                continue
            seen.add(h.subdomain)
            deduped.append(h)
        object.__setattr__(self, "handles", deduped)
        object.__setattr__(self, "target_queue", [h.subdomain for h in deduped])
        return self


# ---------------------------------------------------------------------------
# 2026-06-09 (Issue 11 — phase quality scoring). After every
# wave, the executor's RulesBasedQualityScorer (or an LLM-based
# scoring agent) inspects the evidence against an explicit
# criteria list and returns a 0-100 score with itemized
# deductions. Scores below the threshold (default 90) cause
# the executor to re-spawn the specialist with the score
# report attached, up to 3 retries per wave. This closes the
# "fake vuln / incomplete URL / missing host:port / no PoC
# verification / 200 OK with failed body" class of regressions
# that the LLM specialists otherwise let through.
# ---------------------------------------------------------------------------


class QualityDeduction(BaseModel):
    """One deduction in a phase quality score report.

    Each deduction carries:
    - ``criterion_id``: the canonical C-code (C1..C4 plus
      future additions)
    - ``criterion_name``: short human-readable name
    - ``points_deducted``: how many points this hit cost the
      phase (sum of all deductions + base 100 = final score)
    - ``detail``: free-text explanation; the executor
      re-spawns the specialist with this detail inline so
      the LLM knows exactly what to fix
    - ``affected_field``: dotted path into the evidence
      record (e.g. ``services[2]``, ``findings[0].reproduce_steps``,
      ``per_target_finding[1]``); the LLM can use this to
      pinpoint the problem
    - ``recommendation``: concrete next step (e.g. "Set
      ServiceEntry.url to http://10.0.0.5:9090/metrics and
      re-run")

    The deduction is intentionally verbose — the LLM needs
    enough context to self-correct on the retry.
    """

    model_config = ConfigDict(extra="forbid")

    criterion_id: str
    criterion_name: str
    points_deducted: int = Field(ge=0, le=100)
    detail: str
    affected_field: str | None = None
    recommendation: str | None = None


class PhaseQualityScore(EvidenceBase):
    """The scoring agent's verdict on one wave's evidence.

    ``score`` is the final 0-100 integer (100 - sum of
    deductions, clamped at 0). ``threshold`` is the
    pass-bar; ``passed`` is ``score >= threshold``. When
    ``passed=False`` the executor re-spawns the specialist
    with the score report attached (see executor.py
    ``_score_phase_quality``).

    The 4 explicit criteria the user named (C1..C4) are
    encoded as ``QualityDeduction`` rows; the scorer also
    adds its own observations (e.g. a C5 for missing
    evidence fields). The ``strengths`` list captures what
    the specialist got right so the retry can preserve the
    good parts.

    ``target`` mirrors the parent wave's evidence ``target``
    so the W8 reporting specialist can render the score
    ledger per target.
    """

    evidence_schema: Literal["quality-score-v1"] = "quality-score-v1"
    wave: str = Field(
        ...,
        description=(
            "The wave id this score is for (e.g. 'W1', 'W4', "
            "'W8'). Drives the W8 report's score ledger."
        ),
    )
    handoff_id: str = Field(
        ...,
        description=(
            "The handoff_id of the wave's primary specialist "
            "(e.g. 'W4.penetration.1'). Helps the operator "
            "trace a low score back to the specific sub-track."
        ),
    )
    score: int = Field(
        ge=0,
        le=100,
        description="0-100 integer. 100 - sum of deductions (clamped).",
    )
    threshold: int = Field(
        default=90,
        ge=0,
        le=100,
        description=(
            "Pass-bar. Default 90 (operator-tunable). When "
            "score >= threshold, the wave's evidence is "
            "accepted and the next wave runs."
        ),
    )
    passed: bool = Field(
        ...,
        description=(
            "True iff score >= threshold. The executor reads "
            "this to decide whether to retry the specialist."
        ),
    )
    deductions: list[QualityDeduction] = Field(
        default_factory=list,
        description=(
            "Itemized deductions. Sum of points_deducted = "
            "100 - score (clamped at 0)."
        ),
    )
    strengths: list[str] = Field(
        default_factory=list,
        description=(
            "What the specialist got right. The retry "
            "specialist is told to preserve these in the "
            "next attempt."
        ),
    )
    recommendation: str | None = Field(
        default=None,
        description=(
            "Concrete next step for the specialist on "
            "retry. E.g. 'Re-run with each reachable "
            "service's full URL populated; remove the "
            "host-port-only entries.' The executor copies "
            "this into the retry brief verbatim."
        ),
    )
    retry_count: int = Field(
        default=0,
        ge=0,
        description=(
            "How many times this wave has been retried. The "
            "executor caps retries at 3; after that the "
            "wave's evidence is force-accepted with an "
            "audit marker."
        ),
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the scoring agent ran.",
    )


# ---------------------------------------------------------------------------
# 2026-06-14 — hack-deep-find → hack-deep handoff (v2 redesign Phase 3)
# ---------------------------------------------------------------------------


class FindFrontierNode(BaseModel):
    """One-line summary of an UNSEEN / frontier node in the AssetTree.

    Carried in ``FindCompleteEvidence.frontier_summary`` so the receiving
    hack-deep LLM gets an at-a-glance view of what still needs triaging
    without having to re-read the full AssetTree JSON.
    """

    node_id: str
    asset_type: str
    value: str
    state: str
    parent_value: str | None = None


class FindCompleteEvidence(EvidenceBase):
    """hack-deep-find → hack-deep handoff.

    Emitted by the find LLM-coordinator after ``asset_tree_find_unseen``
    returns empty. Wraps the persisted AssetTree path so hack-deep's W0
    (or a soft-reference W0.4 wave) can pre-load it instead of running
    its own W0.5 recon.
    """

    evidence_schema: Literal["find-complete-v1"] = "find-complete-v1"
    # ``target`` is inherited from EvidenceBase; we set it to the root
    # domain so the executor's evidence-path index is human-friendly.
    tree_id: str
    root_domain: str
    tree_path: str = Field(
        description=(
            "Absolute path to the persisted AssetTree JSON "
            "(~/.opensquilla/state/asset_trees/<tree_id>.json). "
            "hack-deep re-loads via AssetTree.from_json."
        ),
    )
    tree_stats: dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of AssetTree.stats() at handoff time.",
    )
    frontier_summary: list[FindFrontierNode] = Field(
        default_factory=list,
        description=(
            "One entry per UNSEEN / frontier node so hack-deep can "
            "prioritize without a second read of the AssetTree."
        ),
    )
    duration_s: int = Field(
        default=0,
        description="Total find-run duration in seconds (for budget tracking).",
    )
    specialists_invoked: list[str] = Field(
        default_factory=list,
        description=(
            "Specialist agent_ids that ran during this find. Helps "
            "hack-deep reason about coverage gaps."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _set_target_from_root_domain(cls, data: Any) -> Any:
        """Fill `target` from `root_domain` so EvidenceBase invariant holds."""
        if isinstance(data, dict) and "target" not in data and "root_domain" in data:
            data = {**data, "target": data["root_domain"]}
        return data


# ---------------------------------------------------------------------------
# 3-harness cross-owner dispatch (2026-06-16, hack-deep-find v2)
# ---------------------------------------------------------------------------


class W25DispatchEvidence(EvidenceBase):
    """hack-deep-find → hack-deep W2.5 cross-owner dispatch.

    The W2.5 wave (per-port attack plan) is registered with
    ``owner_agent="hack-deep-find"`` in ``attack_dispatch.waves`` because
    the orchestration logic is find-side, BUT the actual
    ``vulnerability-triage`` specialist lives in hack-deep's allow_agents
    list (and is intentionally NOT in find's allow_agents, since find
    never runs triage directly).

    This evidence is the bridge: the find orchestrator plans the W2.5
    sub-track fan-out and emits this envelope to hack-deep, which then
    issues the actual ``sessions_spawn(vulnerability-triage, ...)`` calls
    on the per-port basis. The receiving side reads the dispatch plan
    from the persisted evidence JSON.

    Returned by find, NOT consumed by a specialist. The Typed Envelope
    envelope header on the spawn still lists ``schema="w2.5-dispatch-v1"``
    so the executor's evidence path index is uniform across waves.
    """

    evidence_schema: Literal["w2.5-dispatch-v1"] = "w2.5-dispatch-v1"
    sub_tracks: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Per-port sub-track plan. Each entry: ``track_id`` (S###), "
            "``ports`` (list of ip:port strings), ``vector_class`` "
            "(e.g. ``http_sqli``), ``eta_s`` (int seconds). The receiving "
            "hack-deep orchestrator spawns one vulnerability-triage "
            "specialist per track."
        ),
    )
    trigger_wave: str = Field(
        default="W2.5",
        description="Source wave for this dispatch (always W2.5 today).",
    )
    recon_evidence_path: str | None = Field(
        default=None,
        description=(
            "Path to the ReconEvidence file this plan was derived from. "
            "The receiving hack-deep may load it for vector prioritization."
        ),
    )
    triage_evidence_path: str | None = Field(
        default=None,
        description=(
            "Path to the upstream TriageEvidence (W2 output from "
            "hack-deep's own vulnerability-triage specialist). W2.5 reads "
            "this to bucket services into 6-port sub-tracks."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _default_target(cls, data: Any) -> Any:
        if isinstance(data, dict) and "target" not in data:
            data = {**data, "target": "cross-owner-w2.5-dispatch"}
        return data


class DrillInRequestEvidence(EvidenceBase):
    """hack-deep-find → hack-deep drill-in declaration.

    When the find orchestrator's W1 evidence shows that the main recon
    was incomplete (port_scan_complete == false, dir_bust_evidence
    missing or thin, no wayback / katana pass, etc.), the find LLM
    DOES NOT spawn the W1.6* drill-in directly — those slots are owned
    by hack-deep. Instead, it emits this evidence in the find-complete-v1
    artifacts so hack-deep can decide whether to issue W1.6a/b/c in the
    W0/W2 gap.

    This evidence is purely declarative; it is never a child of
    sessions_spawn. The Typed Envelope for the find-complete handoff
    embeds it as an ``artifacts`` field entry.
    """

    evidence_schema: Literal["drill-in-request-v1"] = "drill-in-request-v1"
    requested_slots: list[str] = Field(
        default_factory=list,
        description=(
            "Drill-in slot names the find LLM recommends opening. Each "
            "must be a member of ``DRILL_IN_SLOTS['W1']`` in "
            "attack_dispatch.waves. Today the valid set is "
            "``['W1.6a', 'W1.6b', 'W1.6c']``."
        ),
    )
    reasons: list[str] = Field(
        default_factory=list,
        description=(
            "Free-form justification per slot, e.g. "
            "``['W1.6c: port_scan_complete=false on 4 hosts']``. The "
            "receiving hack-deep LLM may downgrade any request based on "
            "its own judgement, but a populated reason is a strong "
            "signal to honour the request."
        ),
    )
    evidence_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Paths to the W1 evidence files the recommendation is based "
            "on. hack-deep may re-read these before deciding."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _default_target(cls, data: Any) -> Any:
        if isinstance(data, dict) and "target" not in data:
            data = {**data, "target": "cross-owner-drill-in-request"}
        return data


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


EVIDENCE_SCHEMAS: dict[str, type[EvidenceBase]] = {
    "roe-v1": ROEEvidence,
    "recon-v1": ReconEvidence,
    "intel-v1": IntelEvidence,
    "surface-v1": SurfaceEvidence,
    "triage-v1": TriageEvidence,
    "opsec-v1": OPSECEvidence,
    "pentest-v1": PenetrationEvidence,
    "privesc-v1": PrivescEvidence,
    "lateral-v1": LateralEvidence,
    "persist-v1": PersistEvidence,
    "impact-v1": ImpactEvidence,
    "cleanup-v1": CleanupEvidence,
    "report-v1": ReportEvidence,
    "sub_target_handle-v1": SubTargetHandleList,  # 2026-06-07 W0.5 output
    "quality-score-v1": PhaseQualityScore,  # 2026-06-09 (Issue 11)
    "resource-v1": ResourceEvidence,  # 2026-06-10 R3 P0 S24 (W0.6 output)
    "port-attack-plan-v1": PortAttackPlanEvidence,  # 2026-06-11 v4.0 R3 (W2.5 output)
    "web-crawl-v1": WebCrawlEvidence,  # 2026-06-11 v4.0 R4 (W3.5 output)
    "find-complete-v1": FindCompleteEvidence,  # 2026-06-14 hack-deep-find handoff
    "w2.5-dispatch-v1": W25DispatchEvidence,  # 2026-06-16 hack-deep-find v2 cross-owner
    "drill-in-request-v1": DrillInRequestEvidence,  # 2026-06-16 hack-deep-find v2 cross-owner
}

EVIDENCE_SCHEMA_NAMES: tuple[str, ...] = tuple(EVIDENCE_SCHEMAS.keys())
assert len(EVIDENCE_SCHEMA_NAMES) == 21, (
    "expected 21 evidence schemas (19 + 2 cross-owner)"
)


def make_evidence(schema: str, **fields: Any) -> EvidenceBase:
    """Construct a typed evidence record by schema name. Validates the name."""
    if schema not in EVIDENCE_SCHEMAS:
        raise ValueError(
            f"unknown evidence_schema {schema!r}; "
            f"valid: {sorted(EVIDENCE_SCHEMAS)}"
        )
    model = EVIDENCE_SCHEMAS[schema]
    return model(**fields)
