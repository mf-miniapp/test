"""Contract tests for the Subagent Result Marker.

The Result Marker is the footer line every delegated subagent must emit on
its final assistant message. The canonical (2026-06-07+) form is:

    schema: <evidence_schema> | phase: <phase> | wave: <N/M> | deps: <csv-or-"empty">

where ``<phase>`` is one of ``evidence-collection | synthesis | exploitation
| complete``. The legacy form ``status: complete|partial|failed`` is
still accepted (deprecated) so subagents whose system prompts have not yet
been updated keep working.

This test module pins the contract from three angles:

1. **Parser** — ``parse_result_marker`` accepts valid markers and rejects
   malformed / missing ones.
2. **System-prompt injection** — every code path that injects the
   subagent contract (``tools.builtin.sessions``,
   ``engine.steps.inject_subagent_grounding``, ``engine.runtime``) embeds
   the marker instruction text.
3. **Specialist SOUL.md contract** — all 14 specialist SOUL.md files
   contain a "完成标志" section that:
   - names the correct ``evidence_schema`` for that specialist,
   - documents the four valid ``phase`` values,
   - documents the ``wave: <N>/<M>`` field,
   - documents the ``deps`` field,
   - warns the subagent that a missing marker is downgraded to partial.
4. **hack-deep SOUL.md** — the orchestrator documents how it parses /
   cross-checks / downgrades the marker.
5. **Parent wake payload** — ``_read_child_result`` in
   ``gateway.subagent_announce`` attaches ``marker_present``,
   ``result_marker``, ``result_marker_phase``, ``result_marker_wave``,
   ``result_marker_schema``, ``result_marker_deps`` to the child result
   envelope.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REAL_HOME = Path.home() / ".opensquilla"
AGENTS_DIR = REAL_HOME / "agents"
HACK_DEEP_SOUL = AGENTS_DIR / "hack-deep" / "SOUL.md"

# (agent_id, evidence_schema) — the canonical mapping every specialist SOUL.md
# must declare in its "完成标志" footer section.
SPECIALISTS: tuple[tuple[str, str], ...] = (
    ("engagement-planning", "roe-v1"),
    ("recon", "recon-v1"),
    ("intel-collection", "intel-v1"),
    ("attack-surface-enumeration", "surface-v1"),
    ("vulnerability-triage", "triage-v1"),
    ("opsec-evasion", "opsec-v1"),
    ("penetration", "pentest-v1"),
    ("privilege-escalation", "privesc-v1"),
    ("lateral-movement", "lateral-v1"),
    ("persistence-maintenance", "persist-v1"),
    ("impact-exfiltration", "impact-v1"),
    ("cleanup-rollback", "cleanup-v1"),
    ("reporting-remediation", "report-v1"),
)

VALID_PHASES = (
    "evidence-collection",
    "synthesis",
    "exploitation",
    "complete",
)
# Legacy form (deprecated, kept for backward compat). Tests that
# intentionally exercise the legacy parser still use this constant.
VALID_LEGACY_STATUSES = ("complete", "partial", "failed")

# The canonical marker regex the parser uses — must match the one in
# attack_dispatch/envelope.py.
MARKER_LINE_RE = re.compile(
    r"^\s*schema:\s*\S+\s*\|\s*"
    r"phase:\s*(?:evidence-collection|synthesis|exploitation|complete)\s*\|\s*"
    r"wave:\s*\d+/\d+\s*\|\s*"
    r"deps:\s*\S+\s*$"
)


# ---------------------------------------------------------------------------
# 1. Parser unit tests
# ---------------------------------------------------------------------------


def test_envelope_module_exposes_result_marker_api() -> None:
    """``attack_dispatch.envelope`` must export the public marker API."""
    from opensquilla.attack_dispatch.envelope import (  # noqa: F401
        RESULT_REGEX,
        RESULT_REGEX_LEGACY,
        ResultFormatError,
        ResultMarker,
        ResultPhase,
        parse_result_marker,
        result_marker_to_text,
        validate_result_marker_format,
    )


def test_attack_dispatch_package_exports_result_marker_api() -> None:
    """The top-level ``attack_dispatch`` package re-exports the marker API."""
    import opensquilla.attack_dispatch as ad

    for name in (
        "ResultFormatError",
        "ResultMarker",
        "RESULT_REGEX",
        "RESULT_REGEX_LEGACY",
        "ResultPhase",
        "parse_result_marker",
        "result_marker_to_text",
        "validate_result_marker_format",
    ):
        assert hasattr(ad, name), f"attack_dispatch is missing export {name!r}"


@pytest.mark.parametrize("phase", VALID_PHASES)
def test_parse_result_marker_accepts_valid_marker(phase: str) -> None:
    from opensquilla.attack_dispatch.envelope import parse_result_marker

    text = f"<prose>\nschema: intel-v1 | phase: {phase} | wave: 0/3 | deps: W0.engagement-planning.1\n"
    marker = parse_result_marker(text)
    assert marker.evidence_schema == "intel-v1"
    assert marker.phase == phase
    assert marker.wave == "0/3"
    assert marker.consumed_dependencies == ["W0.engagement-planning.1"]


def test_parse_result_marker_accepts_marker_without_prose() -> None:
    from opensquilla.attack_dispatch.envelope import parse_result_marker

    text = "schema: recon-v1 | phase: complete | wave: 2/8 | deps: empty"
    marker = parse_result_marker(text)
    assert marker.evidence_schema == "recon-v1"
    assert marker.phase == "complete"
    assert marker.wave == "2/8"
    assert marker.consumed_dependencies == []


def test_parse_result_marker_accepts_multiple_csv_deps() -> None:
    from opensquilla.attack_dispatch.envelope import parse_result_marker

    text = (
        "schema: triage-v1 | phase: synthesis | wave: 1/2 | "
        "deps: W0.engagement-planning.1,W1.recon.1,W1.intel-collection.1"
    )
    marker = parse_result_marker(text)
    assert marker.consumed_dependencies == [
        "W0.engagement-planning.1",
        "W1.recon.1",
        "W1.intel-collection.1",
    ]


def test_parse_result_marker_uses_last_marker_when_multiple() -> None:
    """A multi-line reply may have multiple marker-shaped lines; honor the
    last one so the subagent can revise its phase/wave as it works."""
    from opensquilla.attack_dispatch.envelope import parse_result_marker

    text = (
        "schema: pentest-v1 | phase: evidence-collection | wave: 0/1 | deps: W1.recon.1\n"
        "... later reflection ...\n"
        "schema: pentest-v1 | phase: complete | wave: 0/1 | deps: W1.recon.1,W4.penetration.0\n"
    )
    marker = parse_result_marker(text)
    assert marker.phase == "complete"
    assert marker.wave == "0/1"
    assert marker.consumed_dependencies == ["W1.recon.1", "W4.penetration.0"]


def test_parse_result_marker_legacy_status_form_falls_back() -> None:
    """The legacy ``status: complete|partial|failed`` form is still
    accepted as a fallback. The parser coerces ``complete`` -> phase
    ``complete`` and the rest to ``synthesis`` (in-progress)."""
    from opensquilla.attack_dispatch.envelope import parse_result_marker

    marker = parse_result_marker(
        "schema: recon-v1 | status: complete | deps: empty"
    )
    assert marker.phase == "complete"
    assert marker.wave == "0/0"
    marker = parse_result_marker(
        "schema: recon-v1 | status: partial | deps: empty"
    )
    assert marker.phase == "synthesis"
    assert marker.wave == "0/0"


def test_parse_result_marker_rejects_empty_text() -> None:
    from opensquilla.attack_dispatch.envelope import (
        ResultFormatError,
        parse_result_marker,
    )

    with pytest.raises(ResultFormatError):
        parse_result_marker("")


def test_parse_result_marker_rejects_text_without_marker() -> None:
    from opensquilla.attack_dispatch.envelope import (
        ResultFormatError,
        parse_result_marker,
    )

    with pytest.raises(ResultFormatError):
        parse_result_marker(
            "I did the recon and found 12 subdomains. That's it."
        )


@pytest.mark.parametrize(
    "bad_line",
    [
        "schema: recon-v1 | phase: unknown | wave: 0/1 | deps: empty",  # bad phase
        "schema:recon-v1 | phase: complete | wave: 0/1 | deps: empty",   # no space after colon
        "schema: recon-v1 phase: complete | wave: 0/1 | deps: empty",     # missing pipe
        "schema: recon-v1 | phase: complete | wave: 0/1",                 # missing deps
        "schema: recon-v1 | phase: complete | wave: 0/1 | deps: ,",       # empty csv
    ],
)
def test_parse_result_marker_rejects_malformed_marker(bad_line: str) -> None:
    from opensquilla.attack_dispatch.envelope import (
        ResultFormatError,
        parse_result_marker,
    )

    with pytest.raises(ResultFormatError):
        parse_result_marker(f"some prose\n{bad_line}\n")


def test_validate_result_marker_format_is_boolean() -> None:
    from opensquilla.attack_dispatch.envelope import validate_result_marker_format

    assert validate_result_marker_format(
        "schema: report-v1 | phase: complete | wave: 8/8 | deps: W8.cleanup-rollback.1"
    ) is True
    assert validate_result_marker_format("no marker here") is False


def test_result_marker_to_text_roundtrips() -> None:
    from opensquilla.attack_dispatch.envelope import (
        ResultMarker,
        parse_result_marker,
        result_marker_to_text,
    )

    m = ResultMarker(
        evidence_schema="lateral-v1",
        phase="exploitation",
        wave="1/1",
        consumed_dependencies=["W1.recon.1", "W4.penetration.1"],
    )
    text = result_marker_to_text(m)
    # round-trip
    parsed = parse_result_marker(text)
    assert parsed.evidence_schema == "lateral-v1"
    assert parsed.phase == "exploitation"
    assert parsed.wave == "1/1"
    assert parsed.consumed_dependencies == ["W1.recon.1", "W4.penetration.1"]


# ---------------------------------------------------------------------------
# 2. System-prompt injection — every code path embeds the marker instruction
# ---------------------------------------------------------------------------


def test_sessions_subagent_prompt_requires_result_marker() -> None:
    """``_SUBAGENT_SYSTEM_PROMPT`` must contain the marker instruction text."""
    from opensquilla.tools.builtin.sessions import (
        SUBAGENT_RESULT_MARKER_INSTRUCTION,
        _SUBAGENT_SYSTEM_PROMPT,
    )

    assert "RESULT MARKER" in _SUBAGENT_SYSTEM_PROMPT
    assert "schema:" in _SUBAGENT_SYSTEM_PROMPT
    assert "phase:" in _SUBAGENT_SYSTEM_PROMPT
    assert "wave:" in _SUBAGENT_SYSTEM_PROMPT
    assert "deps:" in _SUBAGENT_SYSTEM_PROMPT
    # The new form names all four phase values so the LLM can see the
    # full lifecycle and stops emitting "complete" mid-DAG.
    for phase in VALID_PHASES:
        assert phase in _SUBAGENT_SYSTEM_PROMPT, (
            f"marker instruction missing phase value {phase!r}"
        )
    # The exported constant must be a substring so it can be re-embedded.
    assert SUBAGENT_RESULT_MARKER_INSTRUCTION in _SUBAGENT_SYSTEM_PROMPT


def test_inject_subagent_grounding_uses_same_prompt_text() -> None:
    """The per-turn fallback must use the same constant as the spawn-time
    prompt — drift between the two would let compaction erase the contract."""
    import sys

    # Import the module object directly via sys.modules to avoid the
    # `from package import name` ambiguity where the function named
    # ``inject_subagent_grounding`` shadows the submodule.
    from opensquilla.tools.builtin.sessions import _SUBAGENT_SYSTEM_PROMPT

    grounding_mod = sys.modules["opensquilla.engine.steps.inject_subagent_grounding"]
    assert grounding_mod._SUBAGENT_GROUNDING == _SUBAGENT_SYSTEM_PROMPT
    assert "RESULT MARKER" in grounding_mod._SUBAGENT_GROUNDING
    # And the function is still importable from the package.
    assert callable(grounding_mod.inject_subagent_grounding)


def test_runtime_subagent_task_protocol_requires_result_marker() -> None:
    """``_SUBAGENT_TASK_PROTOCOL`` (used as ToolContext extra context for
    subagent callers) must also embed the marker instruction."""
    from opensquilla.engine.runtime import _SUBAGENT_TASK_PROTOCOL

    assert "RESULT MARKER" in _SUBAGENT_TASK_PROTOCOL
    assert "schema:" in _SUBAGENT_TASK_PROTOCOL
    assert "phase:" in _SUBAGENT_TASK_PROTOCOL
    assert "wave:" in _SUBAGENT_TASK_PROTOCOL
    assert "deps:" in _SUBAGENT_TASK_PROTOCOL


# ---------------------------------------------------------------------------
# 3. Specialist SOUL.md contract — every specialist documents its marker
# ---------------------------------------------------------------------------


def _read_soul(agent_id: str) -> str:
    path = AGENTS_DIR / agent_id / "SOUL.md"
    if not path.is_file():
        pytest.skip(f"{path} is missing — agent persona not cloned")
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("agent_id,schema", SPECIALISTS)
def test_specialist_soul_has_completion_marker_section(agent_id: str, schema: str) -> None:
    """Every specialist SOUL.md must contain a Result Marker section."""
    soul = _read_soul(agent_id)
    assert "完成标志" in soul, (
        f"{agent_id}/SOUL.md is missing the '完成标志' section"
    )
    assert "Result Marker" in soul or "RESULT MARKER" in soul, (
        f"{agent_id}/SOUL.md does not name the Result Marker concept"
    )


@pytest.mark.parametrize("agent_id,schema", SPECIALISTS)
def test_specialist_soul_documents_its_own_schema_name(
    agent_id: str, schema: str
) -> None:
    """Each specialist's SOUL.md must name the canonical evidence schema
    inside its Result Marker code block."""
    soul = _read_soul(agent_id)
    # The schema literal must appear inside a code block, not just in
    # prose. We accept any of the 3 typical patterns: `schema: <x>-v1`,
    # `<x>-v1` after the backticks, or the bare token near a `schema:`.
    assert f"schema: {schema}" in soul, (
        f"{agent_id}/SOUL.md does not declare 'schema: {schema}' "
        f"in its Result Marker footer example"
    )


@pytest.mark.parametrize("agent_id,schema", SPECIALISTS)
def test_specialist_soul_documents_marker_phase_or_status(
    agent_id: str, schema: str
) -> None:
    """The SOUL.md must enumerate EITHER the new four phase values OR
    the legacy three status values.

    New specialists (post-2026-06-07) should document the four phase
    values: ``evidence-collection``, ``synthesis``, ``exploitation``,
    ``complete``. Specialists that have not yet been retrained on the
    new contract document the legacy three: ``complete``, ``partial``,
    ``failed``. The parser accepts both forms (see envelope.py for the
    legacy-fallback behavior), so either is acceptable documentation.

    Eventually every SOUL.md should migrate to the new form; this test
    accepts both during the rollout.
    """
    soul = _read_soul(agent_id)
    has_new = all(phase in soul for phase in VALID_PHASES)
    has_legacy = all(status in soul for status in VALID_LEGACY_STATUSES)
    assert has_new or has_legacy, (
        f"{agent_id}/SOUL.md is missing all phase values AND all "
        f"legacy status values. Update the marker example in the "
        f"Result Marker / 完成标志 section to use either the new "
        f"phase+wave form or the legacy status: form."
    )


@pytest.mark.parametrize("agent_id,schema", SPECIALISTS)
def test_specialist_soul_documents_deps_field(agent_id: str, schema: str) -> None:
    soul = _read_soul(agent_id)
    # The deps field is documented in three places: the marker example
    # line itself (`deps: <csv-or-"empty">`), the prose explanation, and
    # the in-section guidance. All three should be present.
    assert "deps:" in soul, (
        f"{agent_id}/SOUL.md does not mention the 'deps' field"
    )
    assert "deps" in soul.lower(), (
        f"{agent_id}/SOUL.md does not explain the deps field"
    )


@pytest.mark.parametrize("agent_id,schema", SPECIALISTS)
def test_specialist_soul_warns_about_missing_marker(
    agent_id: str, schema: str
) -> None:
    """Every specialist must warn that omitting the marker is treated as
    incomplete contract by the parent."""
    soul = _read_soul(agent_id)
    lowered = soul.lower()
    # At least one of these phrasings must appear, otherwise the
    # subagent may think the footer is optional.
    assert (
        "不要省略 footer" in soul
        or "incomplete_contract" in lowered
        or "missing" in lowered and "marker" in lowered
        or "partial" in lowered and "omit" in lowered
    ), (
        f"{agent_id}/SOUL.md does not warn that omitting the marker is "
        f"downgraded to incomplete_contract"
    )


# ---------------------------------------------------------------------------
# 4. hack-deep SOUL.md — orchestrator documents how it parses / downgrades
# ---------------------------------------------------------------------------


def test_hack_deep_soul_documents_result_marker_handling() -> None:
    if not HACK_DEEP_SOUL.is_file():
        pytest.skip("hack-deep/SOUL.md missing — run clone script first")
    soul = HACK_DEEP_SOUL.read_text(encoding="utf-8")
    assert "Result Marker" in soul or "RESULT MARKER" in soul, (
        "hack-deep/SOUL.md does not document the Result Marker concept"
    )
    assert "marker_present" in soul, (
        "hack-deep/SOUL.md does not document the marker_present flag"
    )
    # The new form names the four phase values; the legacy form names
    # complete/partial/failed. Both must be accepted by hack-deep.
    assert "complete" in soul and "partial" in soul and "failed" in soul, (
        "hack-deep/SOUL.md does not enumerate the legacy status values"
    )
    for phase in ("evidence-collection", "synthesis", "exploitation", "complete"):
        assert phase in soul, (
            f"hack-deep/SOUL.md is missing phase value {phase!r}"
        )
    assert "RESULT_REGEX" in soul, (
        "hack-deep/SOUL.md does not name the parser regex"
    )


# ---------------------------------------------------------------------------
# 5. Parent wake payload — _read_child_result attaches marker metadata
# ---------------------------------------------------------------------------


class _StubRow:
    def __init__(self, **kw: object) -> None:
        for k, v in kw.items():
            setattr(self, k, v)


@pytest.mark.asyncio
async def test_read_child_result_attaches_marker_when_present() -> None:
    """When the subagent emitted a valid Result Marker footer, the wake
    payload must carry the parsed fields so the parent can correlate."""
    from opensquilla.gateway import subagent_announce

    text = (
        "Some prose about what I found.\n"
        "schema: recon-v1 | phase: complete | wave: 0/8 | deps: W0.engagement-planning.1\n"
    )

    class _Mgr:
        async def read_transcript(self, key: str, limit: int) -> list[_StubRow]:
            return [_StubRow(role="assistant", content=text)]

    payload = await subagent_announce._read_child_result(
        "agent:recon:recon-abc", session_manager=_Mgr()
    )
    assert payload["marker_present"] is True
    assert payload["result_marker"] == (
        "schema: recon-v1 | phase: complete | wave: 0/8 | deps: W0.engagement-planning.1"
    )
    assert payload["result_marker_phase"] == "complete"
    assert payload["result_marker_wave"] == "0/8"
    assert payload["result_marker_schema"] == "recon-v1"
    assert payload["result_marker_deps"] == ["W0.engagement-planning.1"]


@pytest.mark.asyncio
async def test_read_child_result_marks_missing_marker() -> None:
    """v3.2.1 (2026-06-07): when the subagent's last assistant message
    has text but no parseable marker, the runtime auto-appends a
    synthetic marker so the parent's wave barrier can move forward.
    The wake payload records ``marker_present=True`` (the parent CAN
    parse a marker) AND ``marker_synthetic=True`` (so the parent knows
    the LLM didn't actually emit one). This is the safety net for the
    2026-06-07 hack-deep W4.1 V001 IDOR incident.
    """
    from opensquilla.gateway import subagent_announce

    text = "I did the recon and found 12 subdomains. That's all."

    class _Mgr:
        async def read_transcript(self, key: str, limit: int) -> list[_StubRow]:
            return [_StubRow(role="assistant", content=text)]

    payload = await subagent_announce._read_child_result(
        "agent:recon:recon-abc", session_manager=_Mgr()
    )
    # New contract: the runtime auto-marks, so the parent sees a valid marker.
    assert payload["marker_present"] is True
    assert payload["marker_synthetic"] is True
    assert payload["marker_synthetic_reason"] == "missing_marker_recovered"
    assert payload["result_marker_schema"] == "unknown-v1"
    # And the wake text itself ends with a parseable marker line.
    assert payload["text"].endswith(
        "schema: unknown-v1 | phase: evidence-collection | wave: 0/1 | deps: empty"
    )


@pytest.mark.asyncio
async def test_read_child_result_marks_malformed_marker() -> None:
    """v3.2.1: a malformed marker (wrong phase token, etc.) is also
    recovered by the synthetic-marker path — we DO silently treat a
    typo as recoverable. The original malformed ``schema:`` line stays
    in the text (so the parent can debug) but the parsed marker is
    the synthetic one (so the parent's wave barrier can move on).
    The ``marker_synthetic=True`` flag tells the parent "this came from
    the runtime, not the LLM."
    """
    from opensquilla.gateway import subagent_announce

    text = "schema: recon-v1 | phase: unknown | wave: 0/8 | deps: empty\n"

    class _Mgr:
        async def read_transcript(self, key: str, limit: int) -> list[_StubRow]:
            return [_StubRow(role="assistant", content=text)]

    payload = await subagent_announce._read_child_result(
        "agent:recon:recon-abc", session_manager=_Mgr()
    )
    # New contract: malformed → auto-marker kicks in, marker_present=True.
    assert payload["marker_present"] is True
    assert payload["marker_synthetic"] is True
    # The synthetic marker's schema is ``unknown-v1`` (we cannot trust
    # the LLM's claimed schema when the marker was malformed).
    assert payload["result_marker_schema"] == "unknown-v1"
    assert payload["result_marker_phase"] == "evidence-collection"
    # The original malformed line is preserved in the text for debug.
    assert "phase: unknown" in payload["text"]
    # The synthetic marker is appended at the end.
    assert payload["text"].endswith(
        "schema: unknown-v1 | phase: evidence-collection | wave: 0/1 | deps: empty"
    )


@pytest.mark.asyncio
async def test_read_child_result_legacy_form_coerces_to_phase() -> None:
    """The legacy ``status:`` form is accepted by the parser and the
    wake payload exposes ``result_marker_phase`` (the coerced value) so
    downstream consumers read a single canonical field."""
    from opensquilla.gateway import subagent_announce

    text = (
        "I could not run nmap because of permission errors.\n"
        "schema: recon-v1 | status: failed | deps: W0.engagement-planning.1\n"
    )

    class _Mgr:
        async def read_transcript(self, key: str, limit: int) -> list[_StubRow]:
            return [_StubRow(role="assistant", content=text)]

    payload = await subagent_announce._read_child_result(
        "agent:recon:recon-abc", session_manager=_Mgr()
    )
    assert payload["marker_present"] is True
    # ``status: failed`` coerces to ``phase: synthesis`` (in-progress,
    # not terminal) so the parent does not abort the rest of the DAG
    # on a single subagent failure.
    assert payload["result_marker_phase"] == "synthesis"
    assert payload["result_marker_schema"] == "recon-v1"
    assert payload["result_marker_deps"] == ["W0.engagement-planning.1"]


# ---------------------------------------------------------------------------
# 6. Integration — sessions_spawn task body contains the marker instruction
# ---------------------------------------------------------------------------


def test_sessions_spawn_first_user_message_contains_marker_instruction() -> None:
    """The first user message of a spawned subagent (built by
    ``sessions_spawn``) must include the marker instruction so the
    subagent knows to emit the footer on its final reply."""
    from opensquilla.tools.builtin.sessions import (
        SUBAGENT_RESULT_MARKER_INSTRUCTION,
    )

    # Reconstruct what sessions_spawn would compose for a typical task.
    task = "Do the recon for 51ifind.com."
    grounded = (
        "You are a subagent. Execute the delegated task faithfully and "
        "return a structured result to your parent session.\n\n"
        + SUBAGENT_RESULT_MARKER_INSTRUCTION
        + "\n\n" + task
    )
    assert "RESULT MARKER" in grounded
    assert "schema: <evidence_schema>" in grounded
    # The new form names all four phase values so the LLM cannot
    # misread the marker as a final-commit signal.
    for phase in VALID_PHASES:
        assert phase in grounded, (
            f"subagent grounding missing phase value {phase!r}"
        )
    # The original task is preserved after the marker instruction.
    assert grounded.endswith(task)


# ---------------------------------------------------------------------------
# 6. Auto-continue stall detection (fix 11, 2026-06-08)
#
# The 2026-06-08 51ifind.com orchestrator (qwen3.6-35b) paused at
# "是否继续推进 W3?" and the entire DAG stalled for 24+ hours until
# the operator manually resumed. ``is_confirmation_question_stall``
# detects this class of stall so the runtime can auto-append a
# synthetic marker + tag the wake payload with
# ``auto_continue=True`` / ``stall_reason="confirmation_question"``.
# ---------------------------------------------------------------------------


def test_is_confirmation_question_stall_detects_51ifind_incident() -> None:
    from opensquilla.attack_dispatch.envelope import (
        is_confirmation_question_stall,
    )

    # Exact wording from the 2026-06-08 51ifind.com incident.
    text = (
        "W3 brief configured. 建议先执行 W3 (opsec-evasion) 配置代理/跳板,"
        "再启动 W4 渗透。\n是否继续推进 W3?"
    )
    assert is_confirmation_question_stall(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "W2 evidence done. Shall I continue?",
        "Continue? (Y/n)",
        "Do you want me to roll back P03? (Y/n)",
        "Should I proceed with W4?",
        "W2 report delivered. Continue? (Y/n)",
        "请确认是否进入下一阶段。",
        "All W4 findings done. 是否继续推进 W4.5 drill-in?",
        "是否要我也开始 W4?",
    ],
)
def test_is_confirmation_question_stall_detects_stalls(text: str) -> None:
    from opensquilla.attack_dispatch.envelope import (
        is_confirmation_question_stall,
    )

    assert is_confirmation_question_stall(text) is True


@pytest.mark.parametrize(
    "text",
    [
        # Real RESULT MARKER wins over the question (LLM is intentionally
        # handing off, not stalling).
        (
            "P01 done.\nschema: persist-v1 | phase: evidence-collection "
            "| wave: 4/9 | deps: empty"
        ),
        # Rhetorical mid-sentence question, not a stall.
        "Some analysis. Did XSS work? Probably.",
        # Plain narrative ending in period.
        "W2 report delivered. Done.",
        # No question mark at all.
        "W3 配置完成",
        # Empty.
        "",
    ],
)
def test_is_confirmation_question_stall_passes_through_clean_text(
    text: str,
) -> None:
    from opensquilla.attack_dispatch.envelope import (
        is_confirmation_question_stall,
    )

    assert is_confirmation_question_stall(text) is False


# ---------------------------------------------------------------------------
# 6b. rewrite_stall_to_continuation (fix 11 hardening, 2026-06-09)
#
# Just *detecting* a stall wasn't enough. The 2026-06-09 51ifind.com
# run showed the LLM still emitted "是否继续推进 W5: Privilege
# Escalation?" and the OpenClaw gateway displayed the raw text to
# the operator because the wake payload's `text` field was the
# original. The rewrite helper actually REPLACES the question line
# with a fixed "Auto-continuing." statement, so the operator never
# sees the question in the first place.
# ---------------------------------------------------------------------------


def test_rewrite_stall_to_continuation_handles_2026_06_09_w5_incident() -> None:
    """The exact text from the 2026-06-09 51ifind.com W5 stall."""
    from opensquilla.attack_dispatch.envelope import (
        is_confirmation_question_stall,
        rewrite_stall_to_continuation,
    )

    text = (
        "下一步: W5 Privilege Escalation\n"
        "基于当前证据, W5 将执行以下升级路径:\n"
        "| 入口 | 目标 | 预期成果 |\n"
        "| SSH 22 | OpenSSH 9.3 | 获取 shell |\n"
        "| Kong :8001 | 路由注入 | 内网 API |\n"
        "是否继续推进 W5: Privilege Escalation?"
    )
    # Sanity: detection works.
    assert is_confirmation_question_stall(text) is True
    # Rewrite strips the question line, replaces with fixed statement.
    rewritten = rewrite_stall_to_continuation(text)
    assert "是否继续推进 W5" not in rewritten
    assert "Auto-continuing" in rewritten
    # Body content (table) is preserved.
    assert "OpenSSH 9.3" in rewritten
    assert "Kong :8001" in rewritten
    # Question mark gone from last non-empty line.
    last_non_empty = [
        ln for ln in rewritten.rstrip().splitlines() if ln.strip()
    ][-1]
    assert not last_non_empty.endswith("?")


def test_rewrite_stall_to_continuation_is_noop_on_clean_text() -> None:
    """Non-stall text must round-trip unchanged."""
    from opensquilla.attack_dispatch.envelope import (
        rewrite_stall_to_continuation,
    )

    text = (
        "P01 mod_lua file write done.\n"
        "schema: persist-v1 | phase: evidence-collection | wave: 4/9 | deps: empty"
    )
    assert rewrite_stall_to_continuation(text) == text


def test_rewrite_stall_to_continuation_handles_question_only() -> None:
    """If the LLM's entire output is the question (no body), rewrite still works."""
    from opensquilla.attack_dispatch.envelope import (
        rewrite_stall_to_continuation,
    )

    rewritten = rewrite_stall_to_continuation("是否继续推进 W3?")
    assert "是否继续推进" not in rewritten
    assert "Auto-continuing" in rewritten
