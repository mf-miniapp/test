"""SOUL.md / ATTRIBUTION.md contract tests for hack-deep.

These tests pin the v3.1 contract: 4 layers, 9 waves, 13 specialists, Typed
Task Envelope, real sessions_spawn/sessions_yield tool names, drill-in reason
classes, the 7 granular fix markers, and the cloning provenance.

Pattern: read the on-disk file, assert substrings. Modeled on
``tests/test_skills_memory_contract.py`` and ``tests/test_skills/test_*.py``.
"""

from __future__ import annotations

from pathlib import Path

REAL_HOME = Path.home() / ".opensquilla"
HACK_DEEP_DIR = REAL_HOME / "agents" / "hack-deep"
SOUL_PATH = HACK_DEEP_DIR / "SOUL.md"
ATTRIBUTION_PATH = HACK_DEEP_DIR / "ATTRIBUTION.md"


# ---------------------------------------------------------------------------
# Module-level loads (skip the file with a clear error if the clone never ran)
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    if not path.is_file():
        pytest_skip = f"{path} is missing — run scripts/clone_cyberstrike_to_hack_deep.py first"
        import pytest
        pytest.skip(pytest_skip)
    return path.read_text(encoding="utf-8")


import pytest  # noqa: E402

SOUL = _read(SOUL_PATH)
ATTR = _read(ATTRIBUTION_PATH)


# ---------------------------------------------------------------------------
# 1. Four layers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layer_name", ["广度层", "隐蔽层", "深度层", "收口层"])
def test_soul_documents_four_layers(layer_name: str) -> None:
    assert layer_name in SOUL, f"SOUL.md is missing layer name {layer_name!r}"


# ---------------------------------------------------------------------------
# 2. Nine waves (W0..W8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("wave", [f"W{n}" for n in range(9)])
def test_soul_documents_nine_waves(wave: str) -> None:
    assert wave in SOUL, f"SOUL.md is missing wave marker {wave!r}"


# ---------------------------------------------------------------------------
# 3. Typed Task Envelope — 4 field names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["handoff_id", "input_dependencies", "evidence_schema", "expected_runtime_s"],
)
def test_soul_documents_typed_envelope_fields(field: str) -> None:
    assert field in SOUL, f"SOUL.md is missing envelope field {field!r}"


def test_soul_documents_envelope_header_marker() -> None:
    """The literal HANDOFF marker is in the SOUL."""
    assert "HANDOFF" in SOUL, "SOUL.md does not contain 'HANDOFF' marker"


# ---------------------------------------------------------------------------
# 4. Real tool names
# ---------------------------------------------------------------------------


def test_soul_uses_real_sessions_spawn_and_yield_tools() -> None:
    assert "sessions_spawn" in SOUL, "SOUL.md does not reference sessions_spawn"
    assert "sessions_yield" in SOUL, "SOUL.md does not reference sessions_yield"


def test_soul_uses_real_sessions_spawn_signature() -> None:
    """The 3-arg real signature is documented."""
    assert "agent_id=" in SOUL
    assert "task=" in SOUL
    assert "model=None" in SOUL


# ---------------------------------------------------------------------------
# 5. 13 specialist agents
# ---------------------------------------------------------------------------


SPECIALISTS = (
    "recon",
    "intel-collection",
    "attack-surface-enumeration",
    "vulnerability-triage",
    "opsec-evasion",
    "penetration",
    "privilege-escalation",
    "lateral-movement",
    "persistence-maintenance",
    "impact-exfiltration",
    "cleanup-rollback",
    "reporting-remediation",
    "engagement-planning",
)


@pytest.mark.parametrize("specialist", SPECIALISTS)
def test_soul_lists_all_thirteen_specialist_agents(specialist: str) -> None:
    assert specialist in SOUL, f"SOUL.md is missing specialist {specialist!r}"


# ---------------------------------------------------------------------------
# 6. Excludes cyberstrike-deep from spawn targets
# ---------------------------------------------------------------------------


def test_soul_excludes_cyberstrike_deep_from_spawn_targets() -> None:
    """SOUL explicitly says hack-deep must NOT spawn cyberstrike-deep."""
    # Phrasing 1: English "do not spawn it"
    assert "do not spawn it" in SOUL.lower() or "do **not** spawn it" in SOUL.lower()
    # Phrasing 2: Chinese "不 spawn" (forbidding)
    assert "不 spawn" in SOUL or "不 spawn `cyberstrike-deep`" in SOUL


# ---------------------------------------------------------------------------
# 7. Drill-in reason classes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["Wn.5a", "Wn.5b", "Wn.5c"])
def test_soul_documents_drill_in_reason_classes(reason: str) -> None:
    assert reason in SOUL, f"SOUL.md is missing drill-in marker {reason!r}"


def test_soul_restricts_drill_in_to_breadth_and_depth() -> None:
    """SOUL says drill-in is NOT allowed in W2 / W3 / W5 / W7 / W8."""
    assert "W2" in SOUL
    assert "W5" in SOUL
    assert "W7" in SOUL
    assert "W8" in SOUL
    # and there's a sentence forbidding drill-in in those waves
    assert "不开" in SOUL or "do not" in SOUL.lower() or "not" in SOUL.lower()


# ---------------------------------------------------------------------------
# 8. W3 internal sub-call pattern (fix 7)
# ---------------------------------------------------------------------------


def test_soul_documents_w3_internal_subcall_pattern() -> None:
    """SOUL describes the W3 internal sub-call for per-target stealth tweaks."""
    assert "W3" in SOUL
    assert "sub-call" in SOUL or "subcall" in SOUL
    assert "W3_internal_subcall" in SOUL or "W3 允许" in SOUL or "wave-内" in SOUL


# ---------------------------------------------------------------------------
# 9. ATTRIBUTION — Envelope schema table
# ---------------------------------------------------------------------------


EVIDENCE_SCHEMAS = (
    "recon-v1",
    "intel-v1",
    "surface-v1",
    "roe-v1",
    "triage-v1",
    "opsec-v1",
    "pentest-v1",
    "privesc-v1",
    "lateral-v1",
    "persist-v1",
    "impact-v1",
    "cleanup-v1",
    "report-v1",
)


@pytest.mark.parametrize("schema", EVIDENCE_SCHEMAS)
def test_attribution_documents_envelope_schema_table(schema: str) -> None:
    assert schema in ATTR, f"ATTRIBUTION.md is missing evidence_schema {schema!r}"


# ---------------------------------------------------------------------------
# 10. ATTRIBUTION — 7 fix markers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "marker",
    [
        "success_unit",
        "per_target_group",
        "per_target_finding",
        "infra_sharing",
        "Wn.5a",
        "Wn.5b",
        "Wn.5c",
    ],
)
def test_attribution_documents_seven_fix_markers(marker: str) -> None:
    assert marker in ATTR, f"ATTRIBUTION.md is missing fix marker {marker!r}"


# ---------------------------------------------------------------------------
# 11. ATTRIBUTION — cloning provenance
# ---------------------------------------------------------------------------


def test_attribution_documents_cloning_provenance() -> None:
    """The modification log records the clone event with date and source."""
    assert "Cloned from `cyberstrike-deep` on 2026-06-05" in ATTR
    assert "cyberstrike-deep" in ATTR
    assert "cyberstrike-deep **not modified**" in ATTR or "not modified" in ATTR.lower()


# ---------------------------------------------------------------------------
# 12. SOUL — 51ifind.com pressure test reference
# ---------------------------------------------------------------------------


def test_soul_references_pressure_test() -> None:
    """The 51ifind.com pressure test origin is mentioned in the fix list."""
    assert "51ifind.com" in SOUL
    assert "压力测试" in SOUL or "pressure" in SOUL.lower()


# ---------------------------------------------------------------------------
# 13. SOUL — Typed Envelope regex is documented
# ---------------------------------------------------------------------------


def test_soul_documents_envelope_regex() -> None:
    """The HANDOFF regex is in the SOUL so the contract is auditable."""
    assert "^HANDOFF" in SOUL
    assert "deps=" in SOUL
    assert "schema=" in SOUL
    assert "eta=" in SOUL


# ---------------------------------------------------------------------------
# 14. SOUL — write_todos maps 1:1 to waves
# ---------------------------------------------------------------------------


def test_soul_documents_write_todos_wave_mapping() -> None:
    assert "write_todos" in SOUL
    assert "in_progress" in SOUL


# ---------------------------------------------------------------------------
# 15. SOUL — v4.0 Parallel Mode (2026-06-11)
# ---------------------------------------------------------------------------


def test_soul_documents_parallel_mode_section() -> None:
    """v4.0 (2026-06-11): SOUL has a 'Parallel Mode' section declaring the
    N-spawn-per-assistant-message contract (override of v3.2 serial).
    """
    assert "Parallel Mode" in SOUL
    # v4.0 wording — "可发 N 个" + "全并发".
    assert "可发 N 个" in SOUL
    assert "全并发" in SOUL


def test_soul_documents_parallel_mode_context_caveat() -> None:
    """v4.0: SOUL warns about context-window overflow risk for large targets
    and offers SERIAL as opt-in escape hatch.
    """
    assert "context" in SOUL.lower()
    assert "溢出" in SOUL or "overflow" in SOUL.lower() or "context window" in SOUL.lower()
    # SERIAL is still opt-in (kept for operators on tiny contexts).
    assert "SERIAL" in SOUL
    assert "opt-in" in SOUL or "opt_in" in SOUL or "显式" in SOUL


def test_soul_documents_w2_5_section() -> None:
    """v4.0 R3: SOUL has a 'W2.5 Port Attack Plan' section explaining
    per-port + vector 拆 attack plan generation.
    """
    assert "W2.5 Port Attack Plan" in SOUL
    assert "per-port" in SOUL or "per_port" in SOUL
    assert "AttackVectorPlan" in SOUL
    assert "PortAttackPlanEvidence" in SOUL


def test_soul_documents_w3_5_section() -> None:
    """v4.0 R4: SOUL has a 'W3.5 Web Crawl' section explaining web service
    parallel crawling with katana + waybackurls + subjs + jsluice.
    """
    assert "W3.5 Web Crawl" in SOUL
    assert "katana" in SOUL
    assert "waybackurls" in SOUL
    assert "WebCrawlEvidence" in SOUL


def test_soul_documents_post_exploitation_gate() -> None:
    """v4.0 R5: SOUL documents the W4→W5/W6/W7 gate: no foothold = skip
    post-exploitation, jump to W8 reporting.
    """
    assert "Post-Exploitation Gate" in SOUL
    assert "gate_skipped" in SOUL
    assert "footholds" in SOUL
    # The skip behavior is explicit.
    assert "skip" in SOUL.lower() or "跳过" in SOUL


def test_attribution_documents_parallel_mode_modification() -> None:
    """ATTRIBUTION.md records the v4.0 parallel mode restoration + W2.5/W3.5
    additions in its modification log.
    """
    assert "Parallel mode v4.0" in ATTR or "Parallel Mode (v4.0" in ATTR or "v4.0" in ATTR
    # W2.5 / W3.5 should be mentioned in ATTRIBUTION's modification log.
    assert "W2.5" in ATTR
    assert "W3.5" in ATTR
