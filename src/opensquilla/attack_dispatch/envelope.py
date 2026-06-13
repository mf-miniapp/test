"""Typed Task Envelope — the contract for every wave handoff.

Every ``sessions_spawn`` call from a wave-orchestrator MUST start its ``task``
argument with a HANDOFF Envelope header line:

    HANDOFF <handoff_id> | deps=<csv-or-"empty"> | schema=<evidence_schema> | eta=<seconds>
            [ | artifacts=<urlencoded-json> ]
            [ | mode=parallel|serial ]
            [ | auto_approve=true|false ]
    <blank line>
    <natural-language brief>

The first four fields are **mandatory and order-fixed**:
- ``handoff_id``  — wave + agent + sub-index, e.g. ``W1.recon.1``
- ``input_dependencies`` — comma-separated upstream handoff_ids, or literal ``empty``
- ``evidence_schema`` — name of the evidence schema the specialist must produce
- ``expected_runtime_s`` — int seconds, the orchestrator's budget for this call

The last three fields are **optional** (2026-06-08, hack-deep v3.3):
- ``artifacts`` — urlencoded JSON map of upstream handoff_id → artifact file path
- ``mode`` — ``parallel`` or ``serial``; per-wave override of the session-level
  ``DispatchMode`` (2026-06-08, Issue 4)
- ``auto_approve`` — ``true`` or ``false``; when true, the spawn path sets
  ``ToolContext.auto_approve_specialists=True`` on the child so the shell
  approval pipeline returns a synthetic ``approval_denied`` envelope instead
  of raising the ``UnsupportedSurfaceError`` that would otherwise block the
  W4 / W8 specialist (2026-06-08, Issue 1)

This module is the canonical parser/validator. The same regex appears in the
``hack-deep`` SOUL and in the public tests.

Result Marker — the contract for every subagent's final reply
-------------------------------------------------------------

Every delegated subagent MUST end its final assistant message with **exactly
one** Result Marker line. The current canonical form is:

    schema: <evidence_schema> | phase: <phase> | wave: <N/M> | deps: <csv-or-"empty">

The four fields are **mandatory and order-fixed**:
- ``evidence_schema`` — name of the evidence schema the specialist produced
  (e.g. ``recon-v1``, ``intel-v1``). Must be one of
  ``EVIDENCE_SCHEMA_NAMES`` (validated at parse time).
- ``phase`` — one of ``evidence-collection`` (raw recon / intel / vuln
  enumeration), ``synthesis`` (cross-wave aggregation / prioritization /
  scoring), ``exploitation`` (active probing / payload delivery), or
  ``complete`` (ONLY on the final wave of the final layer). The mid-DAG
  output of ``phase: complete`` is the trigger that makes the parent
  orchestrator stop spawning the remaining waves.
- ``wave`` — ``<N>/<M>`` zero-based index and total. Lets the parent
  know how many waves remain.
- ``consumed_dependencies`` — comma-separated handoff_ids the subagent
  actually consumed from the input, or literal ``empty``. Lets the parent
  correlate the marker with the HANDOFF envelope it sent.

The old ``status: complete|partial|failed`` form is still accepted
(deprecated) for backward compatibility with subagents that have not yet
been retrained on the new contract. The two forms are NOT mixed on the
same line — exactly one of ``phase:`` or ``status:`` is expected.

The same regex appears in all 14 specialist SOUL.md files, in hack-deep's
SOUL, and in ``tests/test_subagent_result_marker.py``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal
from urllib.parse import quote, unquote

from pydantic import BaseModel, Field, field_validator

# Regex derived from the SOUL contract. Anchor at start of line, allow leading
# whitespace, require all 4 mandatory fields in order. The optional
# ``artifacts=`` field is captured separately and only matched when present
# — existing envelopes without artifacts continue to parse unchanged.
ENVELOPE_REGEX = re.compile(
    r"^\s*HANDOFF\s+(?P<handoff_id>\S+)\s*\|\s*"
    r"deps=(?P<deps>\S+)\s*\|\s*"
    r"schema=(?P<schema>\S+)\s*\|\s*"
    r"eta=(?P<eta>\d+)"
    r"(?:\s*\|\s*artifacts=(?P<artifacts>\S+))?"
    r"(?:\s*\|\s*mode=(?P<mode>parallel|serial))?"
    r"(?:\s*\|\s*auto_approve=(?P<auto_approve>true|false|1|0))?"
    r"\s*$"
)

# 2026-06-08: validated values for the new optional fields. The regex
# above already constrains the captured strings, but exposing these as
# module-level constants lets :func:`parse_envelope` and tests assert
# without re-typing the literals.
VALID_DISPATCH_MODES: tuple[str, ...] = ("parallel", "serial")
_VALID_AUTO_APPROVE_TRUE: tuple[str, ...] = ("true", "1")
_VALID_AUTO_APPROVE_FALSE: tuple[str, ...] = ("false", "0")

# Result Marker regex. Allows leading whitespace, requires the four fields
# in the fixed order `schema: ... | phase: ... | wave: ... | deps: ...`.
# Matches anywhere in a multi-line assistant text (anchored at start of
# line so prose can appear before/after the marker without false matches).
# `\s+` (one-or-more) is used after each `:` so we reject the typo case
# `schema:recon-v1` (no space after the colon) but still accept the
# well-formed `schema: recon-v1` and even `schema:   recon-v1`.
#
# Note: the regex below does NOT capture ``status`` — the deprecated
# ``status: complete|partial|failed`` form is parsed by the second
# ``RESULT_REGEX_LEGACY`` regex. Callers iterate both and treat the
# results uniformly via :func:`parse_result_marker` (which returns a
# ``ResultMarker`` populated from whichever form matched).
RESULT_REGEX = re.compile(
    r"^\s*schema:\s+(?P<schema>\S+)\s*\|\s*"
    r"phase:\s+(?P<phase>evidence-collection|synthesis|exploitation|complete)\s*\|\s*"
    r"wave:\s+(?P<wave>\d+/\d+)\s*\|\s*"
    r"deps:\s+(?P<deps>\S+)\s*$",
    re.MULTILINE,
)

# Legacy Result Marker regex — accepts the pre-2026-06-07 form
# ``schema: <x> | status: <complete|partial|failed> | deps: <csv>``.
# Kept so existing subagents (whose system prompts have not yet been
# updated to the new phase+wave form) keep working while the rollout
# happens. New subagents MUST use ``RESULT_REGEX`` (the phase+wave form).
RESULT_REGEX_LEGACY = re.compile(
    r"^\s*schema:\s+(?P<schema>\S+)\s*\|\s*"
    r"status:\s+(?P<status>complete|partial|failed)\s*\|\s*"
    r"deps:\s+(?P<deps>\S+)\s*$",
    re.MULTILINE,
)

# Result status enum shared with evidence.py (legacy form). Re-declared
# locally to keep envelope.py importable without dragging in pydantic
# evidence models in minimal contexts.
ResultStatus = Literal["complete", "partial", "failed"]
VALID_RESULT_STATUSES: tuple[str, ...] = ("complete", "partial", "failed")

# Phase enum for the new marker form. Note that ``complete`` is BOTH a
# phase (meaning "this is the last wave of the last layer") AND a legacy
# status — they map to the same final-commit semantics.
ResultPhase = Literal["evidence-collection", "synthesis", "exploitation", "complete"]
VALID_RESULT_PHASES: tuple[str, ...] = (
    "evidence-collection",
    "synthesis",
    "exploitation",
    "complete",
)


class EnvelopeFormatError(ValueError):
    """Raised when a task string does not start with a valid HANDOFF header."""


class ResultFormatError(ValueError):
    """Raised when a subagent reply does not contain a valid Result Marker."""


class HandoffEnvelope(BaseModel):
    """The 4 mandatory fields of a Typed Task Envelope, plus an optional
    5th field ``input_artifacts`` that maps each upstream handoff_id to the
    on-disk file path of its persisted evidence bundle.

    The 4 mandatory fields are the wave-to-wave contract. The
    ``input_artifacts`` field (2026-06-07) is the contract between
    the executor and the receiving specialist: the executor knows where it
    wrote the upstream evidence; the specialist knows where to read it
    from. This is the durable alternative to the in-memory
    ``state.evidence`` dict, and the foundation of the per-step archive
    pattern (``stage:agent:session:file_path``) that the orchestrator uses
    to keep wave-to-wave context deterministic across process restarts,
    LLM context evictions, and drill-in / emit_new_target feedback loops.

    All other dispatch metadata (specialist agent, model, model_id, etc.)
    is carried alongside, not inside, the envelope — the envelope is a
    contract, not a configuration object.
    """

    handoff_id: str = Field(
        ...,
        description=(
            "Wave-orchestrator-assigned unique id, conventionally "
            "`<wave>.<agent_id>.<sub_n>`, e.g. `W1.recon.1` or `W4.5c.recon.1` "
            "for drill-in."
        ),
    )
    input_dependencies: list[str] = Field(
        default_factory=list,
        description=(
            "List of upstream handoff_ids whose evidence this wave consumes. "
            "Empty list (==literal 'empty' in text form) means no upstream "
            "evidence required (only the W0 ROE)."
        ),
    )
    evidence_schema: str = Field(
        ...,
        description=(
            "Name of the evidence schema the specialist MUST produce. Must be "
            "one of EVIDENCE_SCHEMA_NAMES; validated at parse time."
        ),
    )
    expected_runtime_s: int = Field(
        ...,
        ge=0,
        description="Integer seconds — orchestrator's budget for this call.",
    )
    input_artifacts: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "2026-06-07 per-step archive. Maps each upstream handoff_id to "
            "the on-disk file path of its persisted evidence bundle. Keys "
            "should be a subset of ``input_dependencies``; values are "
            "absolute paths written by the executor's artifact-root "
            "convention (`<artifact_root>/<wave>/<handoff_id>.json`). "
            "Encoded in the HANDOFF header as the optional trailing "
            "``artifacts=<urlencoded-json>`` field; absent on envelopes "
            "produced by older orchestrators (the executor will fill it in "
            "when re-dispatching)."
        ),
    )
    dispatch_mode: Literal["parallel", "serial"] | None = Field(
        default=None,
        description=(
            "2026-06-08 (hack-deep v3.3, Issue 4). Per-envelope override of "
            "the executor's session-level ``DispatchMode``. When ``None`` "
            "(the default for envelopes produced by older orchestrators), "
            "the executor's session default applies. When set, the "
            "executor routes this wave to ``_run_wave_serial`` or "
            "``_run_wave_parallel`` based on this value, regardless of "
            "``self.mode``. Useful when the LLM wants, for example, the "
            "W7 fan-out to run in parallel for a small engagement even "
            "though the session is SERIAL. Header form: "
            "``| mode=parallel`` or ``| mode=serial`` after the optional "
            "``artifacts=`` field."
        ),
    )
    auto_approve: bool = Field(
        default=False,
        description=(
            "2026-06-08 (hack-deep v3.3, Issue 1). When True, the parent "
            "signals that this specialist should run unattended — no "
            "human-in-loop TUI approval dialogs. The gateway's "
            "``sessions_spawn`` implementation translates this into "
            "``ToolContext.auto_approve_specialists=True`` on the child's "
            "tool context, which causes the shell approval pipeline "
            "(``shell._check_exec_approval``) to return a synthetic "
            "``approval_denied`` envelope instead of raising "
            "``UnsupportedSurfaceError``. Header form: "
            "``| auto_approve=true`` (also accepts ``1``/``0`` / "
            "``false``); absent on older envelopes and defaults to False."
        ),
    )

    @field_validator("handoff_id")
    @classmethod
    def _no_whitespace_in_handoff_id(cls, value: str) -> str:
        if " " in value or "\t" in value or "\n" in value:
            raise ValueError(f"handoff_id must be a single token; got {value!r}")
        return value

    def to_text(self) -> str:
        """Render as the HANDOFF header line (no brief)."""
        deps_repr = ",".join(self.input_dependencies) if self.input_dependencies else "empty"
        header = (
            f"HANDOFF {self.handoff_id} | "
            f"deps={deps_repr} | "
            f"schema={self.evidence_schema} | "
            f"eta={self.expected_runtime_s}"
        )
        if self.input_artifacts:
            # urlencoded JSON dict so the header stays single-line and
            # token-friendly. Decode: parse_envelope() does the inverse.
            artifacts_json = json.dumps(
                self.input_artifacts, sort_keys=True, ensure_ascii=False
            )
            header += f" | artifacts={quote(artifacts_json, safe='')}"
        # 2026-06-08 (Issues 1+4): render the optional mode / auto_approve
        # fields in the same order the regex captures them. Both default
        # values are omitted to keep the header identical to the v3.2
        # form for envelopes that don't use the new features.
        if self.dispatch_mode is not None:
            header += f" | mode={self.dispatch_mode}"
        if self.auto_approve:
            header += " | auto_approve=true"
        return header

    def render_full(self, brief: str) -> str:
        """Render the full task string (header + blank line + brief)."""
        return f"{self.to_text()}\n\n{brief}"


# ---------------------------------------------------------------------------
# Parse / validate
# ---------------------------------------------------------------------------


def parse_envelope(task: str) -> HandoffEnvelope:
    """Parse the HANDOFF header line out of a task string.

    The task string is expected to start with the HANDOFF header, optionally
    preceded by whitespace, followed by a blank line and a brief.

    Raises:
        EnvelopeFormatError: if the header is missing or malformed.
    """
    if not task or not task.strip():
        raise EnvelopeFormatError("task is empty")
    first_line = task.split("\n", 1)[0]
    match = ENVELOPE_REGEX.match(first_line)
    if not match:
        raise EnvelopeFormatError(
            f"task does not start with a valid HANDOFF header: {first_line!r}"
        )
    deps_raw = match.group("deps")
    if deps_raw == "empty":
        deps: list[str] = []
    else:
        deps = [d.strip() for d in deps_raw.split(",") if d.strip()]
        if not deps:
            raise EnvelopeFormatError(f"deps is neither 'empty' nor csv: {deps_raw!r}")
    artifacts_raw = match.group("artifacts")
    artifacts: dict[str, str] = {}
    if artifacts_raw:
        try:
            artifacts = json.loads(unquote(artifacts_raw))
        except (ValueError, TypeError) as exc:
            raise EnvelopeFormatError(
                f"artifacts field is not valid JSON: {artifacts_raw!r} ({exc})"
            ) from exc
        if not isinstance(artifacts, dict):
            raise EnvelopeFormatError(
                f"artifacts must be a JSON object; got {type(artifacts).__name__}"
            )
    # 2026-06-08 (Issue 4): per-envelope dispatch mode override. The
    # regex already constrains the captured string to "parallel" or
    # "serial" (or None when absent), so this is a simple pass-through.
    mode_raw = match.group("mode")
    dispatch_mode: Literal["parallel", "serial"] | None = (
        mode_raw if mode_raw in VALID_DISPATCH_MODES else None
    )
    # 2026-06-08 (Issue 1): auto_approve boolean coercion. Accept the
    # common truthy / falsy spellings; everything else is False.
    auto_approve_raw = match.group("auto_approve")
    auto_approve: bool = (
        auto_approve_raw in _VALID_AUTO_APPROVE_TRUE
        if auto_approve_raw is not None
        else False
    )
    return HandoffEnvelope(
        handoff_id=match.group("handoff_id"),
        input_dependencies=deps,
        evidence_schema=match.group("schema"),
        expected_runtime_s=int(match.group("eta")),
        input_artifacts=artifacts,
        dispatch_mode=dispatch_mode,
        auto_approve=auto_approve,
    )


def envelope_to_text(env: HandoffEnvelope) -> str:
    """Alias for ``HandoffEnvelope.to_text`` — returns the header line only."""
    return env.to_text()


def validate_envelope_format(task: str) -> bool:
    """Cheap boolean check; raises nothing. Useful in tests."""
    try:
        parse_envelope(task)
        return True
    except EnvelopeFormatError:
        return False


def to_dict(env: HandoffEnvelope) -> dict[str, Any]:
    """JSON-friendly dict representation."""
    return env.model_dump()


# ---------------------------------------------------------------------------
# Result Marker — subagent → parent structured completion footer
# ---------------------------------------------------------------------------


class ResultMarker(BaseModel):
    """The 4 mandatory fields of a Result Marker line.

    Parsed from the LAST ``schema: <x> | phase: <p> | wave: <N/M> | deps: <d>``
    line in the subagent's final assistant message. The legacy
    ``status: complete|partial|failed`` form is also accepted and is
    mapped onto ``phase: complete|synthesis|exploitation|failed`` (with
    ``wave: 0/0`` since the legacy form did not carry wave info).

    Used by the orchestrator to correlate the reply with the HANDOFF
    envelope it sent, to know whether the run is over, and to flag
    partial / failed runs explicitly.
    """

    evidence_schema: str = Field(
        ...,
        description=(
            "Name of the evidence schema the subagent actually produced. "
            "Should match the HANDOFF envelope's schema; if not, the parent "
            "logs a schema_mismatch but still accepts the marker."
        ),
    )
    phase: ResultPhase = Field(
        ...,
        description=(
            "evidence-collection | synthesis | exploitation | complete. "
            "``complete`` is reserved for the final wave of the final layer."
        ),
    )
    wave: str = Field(
        default="0/0",
        description=(
            "``<N>/<M>`` zero-based wave index and total. ``0/0`` when the "
            "subagent used the legacy ``status:`` form and did not carry "
            "wave info."
        ),
    )
    consumed_dependencies: list[str] = Field(
        default_factory=list,
        description=(
            "List of handoff_ids the subagent actually consumed from the "
            "HANDOFF envelope. Empty list (==literal 'empty' in text form) "
            "means no upstream evidence was consumed."
        ),
    )

    @property
    def status(self) -> str:
        """Backward-compat alias: map the new ``phase`` enum back to the
        legacy ``status`` enum so older code paths and tests that read
        ``marker.status`` keep working.

        Mapping:
        - ``phase=complete`` → ``status=complete``
        - ``phase=synthesis|exploitation|evidence-collection`` → ``status=partial``
          (the run is in progress; the parent should keep going)
        - (No direct ``status=failed`` mapping — failures are carried
          through the prose and the ``error_class``/``error_message``
          fields on the task record instead of via the marker.)

        New code MUST read ``marker.phase`` (or ``marker.wave``) and treat
        this property as deprecated. It exists only to keep the rollout
        non-breaking.
        """
        if self.phase == "complete":
            return "complete"
        return "partial"

    def to_text(self) -> str:
        """Render as the Result Marker footer line (no body)."""
        deps_repr = ",".join(self.consumed_dependencies) if self.consumed_dependencies else "empty"
        return (
            f"schema: {self.evidence_schema} | phase: {self.phase} | "
            f"wave: {self.wave} | deps: {deps_repr}"
        )

    @field_validator("evidence_schema")
    @classmethod
    def _no_whitespace_in_schema(cls, value: str) -> str:
        if " " in value or "\t" in value or "\n" in value:
            raise ValueError(f"evidence_schema must be a single token; got {value!r}")
        return value


def _coerce_legacy_status_to_phase(status: str) -> tuple[ResultPhase, str]:
    """Map a legacy ``status:`` value to a (phase, wave) pair.

    The legacy status enum does not carry wave info, so the wave field
    is set to ``0/0`` (meaning "unknown"). The phase mapping tries to
    preserve the intent: ``complete`` → ``complete`` (still terminal),
    ``partial`` → ``synthesis`` (something was produced but not all),
    ``failed`` → ``synthesis`` (failure should not abort the rest of
    the DAG; the orchestrator decides whether to retry or move on).
    """
    if status == "complete":
        return "complete", "0/0"
    if status == "partial":
        # Treat partial as the latest in-progress phase so the
        # orchestrator does not interpret the marker as final.
        return "synthesis", "0/0"
    # status == "failed"
    return "synthesis", "0/0"


def parse_result_marker(text: str) -> ResultMarker:
    """Parse the LAST Result Marker footer line out of an assistant message.

    The text may contain arbitrary prose before / after the marker. The
    canonical form is matched first; if absent, the legacy
    ``status: complete|partial|failed`` form is accepted as a fallback
    so existing subagents keep working during the rollout. A bare text
    with no marker (either form) raises :class:`ResultFormatError` — the
    parent treats this as ``incomplete_contract=true`` and falls back to
    ``phase=synthesis`` in the wake payload.

    Raises:
        ResultFormatError: if no marker line is present (in either form)
            or the last one is malformed.
    """
    if not text or not text.strip():
        raise ResultFormatError("assistant text is empty")
    # Canonical form first.
    matches = list(RESULT_REGEX.finditer(text))
    if matches:
        match = matches[-1]
        phase = match.group("phase")
        if phase not in VALID_RESULT_PHASES:
            raise ResultFormatError(
                f"phase must be one of {VALID_RESULT_PHASES}; got {phase!r}"
            )
        wave = match.group("wave")
        deps_raw = match.group("deps")
    else:
        # Legacy form. Same dedup behavior — last match wins.
        legacy_matches = list(RESULT_REGEX_LEGACY.finditer(text))
        if not legacy_matches:
            raise ResultFormatError(
                "assistant text does not contain a Result Marker "
                "(expected line matching `schema: <x> | phase: <p> | wave: <N/M> "
                "| deps: <csv>` or the legacy `schema: <x> | status: "
                "<complete|partial|failed> | deps: <csv>`)"
            )
        match = legacy_matches[-1]
        phase, wave = _coerce_legacy_status_to_phase(match.group("status"))
        deps_raw = match.group("deps")
    if deps_raw == "empty":
        deps: list[str] = []
    else:
        deps = [d.strip() for d in deps_raw.split(",") if d.strip()]
        if not deps:
            raise ResultFormatError(f"deps is neither 'empty' nor csv: {deps_raw!r}")
    return ResultMarker(
        evidence_schema=match.group("schema"),
        phase=phase,  # type: ignore[arg-type]
        wave=wave,
        consumed_dependencies=deps,
    )


def validate_result_marker_format(text: str) -> bool:
    """Cheap boolean check; raises nothing. Useful in tests."""
    try:
        parse_result_marker(text)
        return True
    except ResultFormatError:
        return False


def result_marker_to_text(marker: ResultMarker) -> str:
    """Alias for :meth:`ResultMarker.to_text`."""


def synthesize_marker(
    *,
    evidence_schema: str = "unknown-v1",
    phase: str = "evidence-collection",
    wave: str = "0/1",
    deps: list[str] | str | None = None,
) -> str:
    """Build a synthetic Result Marker line (2026-06-07).

    The runtime auto-emits a marker of this form when a delegated
    subagent's last assistant message is non-empty but contains NO
    parseable marker. The subagent contract (``subagent_contract.py``)
    tells the LLM to do this manually, but the runtime cannot assume
    the LLM will comply — a subagent that runs out of output budget,
    gets confused by an unreachable target, or is killed by an
    upstream timeout will leave the parent waiting for a marker that
    never arrives. The auto-marker is the safety net that keeps the
    parent's wave barrier moving.

    Default values model the "the subagent did something but we
    cannot say what" recovery:
      - ``phase`` defaults to ``evidence-collection`` (we cannot claim
        the run is over, but we cannot claim the subagent synthesized
        anything either; the lowest-impact truthful default is
        "evidence-collection in progress" so the parent continues
        into the next wave).
      - ``wave`` defaults to ``0/1`` (one wave, no progress known).
      - ``deps`` defaults to ``empty`` (we do not have the subagent's
        bookkeeping of what it consumed).
      - ``evidence_schema`` defaults to ``unknown-v1`` (a synthetic
        schema the parent can detect as "not from a real specialist").

    Returns a string of the form:
        ``schema: <x> | phase: <p> | wave: <N/M> | deps: <csv-or-'empty'>``

    Round-trips through :func:`parse_result_marker` so the parent can
    parse the wake payload normally; the only signal that it was
    auto-generated is the ``marker_synthetic=True`` flag the gateway
    attaches in the wake payload (see
    :mod:`opensquilla.gateway.subagent_announce`).
    """
    if deps is None:
        deps_text = "empty"
    elif isinstance(deps, str):
        deps_text = deps if deps else "empty"
    else:
        deps_text = ",".join(deps) if deps else "empty"
    # Sanity-check the phase — fall back to evidence-collection if the
    # caller passed an unknown phase value (defensive).
    if phase not in VALID_RESULT_PHASES:
        phase = "evidence-collection"
    # wave must be N/M; default to 0/1 if not.
    if not wave or "/" not in wave:
        wave = "0/1"
    return f"schema: {evidence_schema} | phase: {phase} | wave: {wave} | deps: {deps_text}"


def append_synthetic_marker_if_missing(text: str, **kwargs: Any) -> tuple[str, bool]:
    """Append a synthetic marker line to ``text`` if it has no marker.

    The check is "last line matches ``RESULT_REGEX``" — if not, we
    append a single line produced by :func:`synthesize_marker` with
    the given kwargs (defaulting to the "unknown" recovery values).

    Returns a 2-tuple ``(new_text, marker_was_appended)``:
      - ``new_text`` is the original text with one extra newline +
        marker line appended when ``marker_was_appended`` is True.
      - ``marker_was_appended`` is False if the text already ends
        with a parseable marker, or if the text is empty (the
        gateway's empty-text path handles itself).

    The original ``text`` is unchanged when no marker is appended; the
    caller can decide whether to use the new text or just record the
    flag (the gateway does both — it stores the augmented text so the
    parent can read a valid marker, AND records ``marker_synthetic``
    in the wake payload so the parent can distinguish auto from real).
    """
    if not text or not text.strip():
        return text, False
    if validate_result_marker_format(text):
        return text, False
    # Strip a trailing newline from the original so the appended marker
    # sits on its own line without a blank line in between (cleaner
    # regex match for the parser).
    base = text.rstrip("\n")
    marker_line = synthesize_marker(**kwargs)
    return f"{base}\n{marker_line}", True


# v3.3 (2026-06-08): auto-continue stall detection (fix 11).
# Matches the LAST substantive non-empty line in ``text`` against a
# regex set of "shall I continue?" / "是否继续?" patterns. When the
# pattern matches AND the text has no parseable RESULT MARKER, the
# subagent is considered to be stalling on a confirmation question
# (the 2026-06-08 51ifind.com incident: the LLM paused at "是否继续
# 推进 W3?" for 24+ hours).
#
# The check is intentionally narrow:
#   - only the LAST non-empty line is inspected (LLM-body questions
#     mid-text are not stalls, they're legit clarification)
#   - a real RESULT MARKER supersedes the check (if the LLM wrote a
#     marker, it wasn't stalling — the question was rhetorical)
#   - the regex is conservative: only matches patterns that
#     BLOCK the next action (continuation / confirmation / approval
#     requests). Generic "?" sentences in the middle of an
#     analysis paragraph are NOT stalls.
import re as _re_stall  # local alias to avoid module-level re import clash

# 2026-06-09 (Issue 7 — parallel mode collapsed to serial).
# User-prompt keywords that explicitly opt INTO parallel dispatch.
# When the LLM sees any of these in the user's message, it MUST
# emit multiple ``sessions_spawn`` calls in ONE assistant message
# (the engine's tool loop already runs concurrent tool calls in
# parallel via the parallel_batch path; the SOUL previously
# FORBADE this unconditionally, which is why "@hack-deep 并行模式"
# still ran serial). The check is intentionally narrow — only
# these exact phrases flip the SOUL contract. The LLM also reads
# the agent config / session-level override (see
# ``FORCE_PARALLEL_AGENT_IDS`` in the gateway config) for a
# system-side override.
_PARALLEL_TRIGGER_KEYWORDS: tuple[str, ...] = (
    # English (case-insensitive substring match in the user prompt)
    "parallel mode",
    "parallel dispatch",
    "parallel spawn",
    "run in parallel",
    "fire in parallel",
    "dispatch in parallel",
    "all at once",
    "all simultaneously",
    "concurrently",
    "comprehensively attack",
    "comprehensive attack",
    "full sweep",
    "widescale",
    "simultaneously attack",
    # Chinese
    "并行模式",
    "并行执行",
    "并行派出",
    "并发执行",
    "并发派出",
    "一次性派出",
    "一次性执行",
    "全面入侵",
    "全面攻击",
    "全面扫描",
    "同时派出",
    "同时执行",
    "一起派出",
    "一次性",
)

# Agent IDs that ALWAYS run in parallel regardless of the user
# prompt. The user can add their own via the gateway config; the
# default set includes the LLM-orchestrated deep agents.
_DEFAULT_FORCE_PARALLEL_AGENT_IDS: frozenset[str] = frozenset({"hack-deep"})


def user_prompt_requests_parallel(user_prompt: str) -> bool:
    """True iff ``user_prompt`` contains an explicit parallel-mode keyword.

    2026-06-09 (Issue 7). The 2026-06-09 51ifind.com / 51ifind.com
    regression: user typed "@hack-deep 并行模式, 全面入侵 51ifind.com"
    and the LLM ran the dispatch SERIALLY because the SOUL contract
    unconditionally forbade multi-spawn-per-message. This helper
    gives the LLM (and the runtime self-check) a single source of
    truth for "did the user ask for parallel?".

    The check is case-insensitive substring match. Generic words
    like "all" alone don't trigger (we want "all at once" or
    "comprehensively attack", not "all the wave evidence"). When
    in doubt the LLM should err on the side of NOT triggering
    (conservative) and let the user re-prompt with a stronger
    parallel hint.
    """
    if not user_prompt or not user_prompt.strip():
        return False
    text = user_prompt.lower()
    for kw in _PARALLEL_TRIGGER_KEYWORDS:
        if kw.lower() in text:
            return True
    return False


def force_parallel_agent(agent_id: str) -> bool:
    """True iff ``agent_id`` is in the always-parallel set.

    2026-06-09 (Issue 7). The default set is ``{"hack-deep"}`` —
    the LLM-orchestrated deep agent. Operators can add their own
    via the gateway config; this function reads the live set so
    tests can pin behavior.
    """
    if not agent_id:
        return False
    normalized = agent_id.strip().lower()
    if not normalized:
        return False
    return normalized in _DEFAULT_FORCE_PARALLEL_AGENT_IDS

_STALL_KEYWORDS: tuple[str, ...] = (
    # English (case-insensitive substring match in last line)
    "shall i",
    "should i",
    "do you want me to",
    "do you want to",
    "want me to",
    "continue?",
    "should i proceed",
    "shall i proceed",
    "roll back?",
    "rollback?",
    # Chinese
    "是否继续",
    "是否开始",
    "是否推进",
    "是否进入",
    "是否执行",
    "是否启动",
    "是否要",
    "需要我",
    "需要立即",
    "请确认是否",
    "请确认",
)


def is_confirmation_question_stall(text: str) -> bool:
    """True iff ``text`` ends in a confirmation question that blocks next action.

    The 2026-06-08 51ifind.com incident: qwen3.6-35b paused at
    "是否继续推进 W3?" with no RESULT MARKER, blocking the parent
    ``sessions_yield`` for 24+ hours. This helper detects that
    class of stall so the runtime can:

      1. Auto-append a synthetic marker (existing fix 8 path).
      2. Tag the wake payload with ``auto_continue=True`` +
         ``stall_reason="confirmation_question"`` so the parent
         can log / count this anti-pattern.

    The check is conservative:
      - empty / blank text → False
      - text already ending in a valid RESULT MARKER → False
        (a marker means the LLM is genuinely handing control back)
      - only the LAST non-empty line is matched (mid-text
        rhetorical questions are not stalls)
      - only patterns that BLOCK the next action (continuation /
        approval / start-next-phase). A "?" mid-analysis is fine.

    Returns:
        bool: True if the text is a stall.
    """
    if not text or not text.strip():
        return False
    # Already has a marker — not a stall, the LLM is intentionally
    # handing off with a valid footer.
    if validate_result_marker_format(text):
        return False
    # Find the last non-empty line.
    lines = [ln for ln in text.rstrip().splitlines() if ln.strip()]
    if not lines:
        return False
    last = lines[-1].strip()
    # The last line must end with a question mark or full-stop —
    # this is the structural signal of "the LLM is asking, not
    # narrating". We accept ASCII "?", full-width "？", the
    # full-width Chinese period "。", AND trailing ")" since
    # "(Y/n)" is a common LLM convention to annotate a
    # yes/no confirmation. We don't strip the ")" so the keyword
    # search below still hits "continue? (y/n)" → "continue?"
    # matches "Continue? (Y/n)".
    if not (
        last.endswith("?")
        or last.endswith("？")
        or last.endswith("。")
        or last.endswith(")")
    ):
        return False
    # Substring match: any of the canonical continuation-blocking
    # keywords appears in the last line. Case-insensitive for English.
    last_lower = last.lower()
    for kw in _STALL_KEYWORDS:
        if kw.lower() in last_lower:
            return True
    return False


def rewrite_stall_to_continuation(text: str) -> str:
    """Rewrite a confirmation-question stall into a "continuing" statement.

    v3.3 (2026-06-08, fix 11 hardening — 2026-06-09):

    Just *detecting* a stall (``is_confirmation_question_stall``) wasn't
    enough. The 2026-06-09 51ifind.com run showed the LLM still emitted
    "是否继续推进 W5: Privilege Escalation?" and the parent was waiting
    for the operator. The wake payload got ``auto_continue=True`` but
    the parent didn't act on it — and on top of that, the OpenClaw
    gateway run the user was watching showed the raw text to the
    operator, not the auto-rewritten form.

    This helper does the **active rewrite** — the last line of the
    stall text is replaced with a fixed "auto-continuing" statement,
    so the text the operator sees is unambiguous: there is no question
    to answer, the next phase is auto-proceeding.

    The rewrite is intentionally bland ("Auto-continuing. (next: ...)"):
    we don't want to impersonate the LLM by writing a fake substantive
    line. The point is to remove the question, period.

    Args:
        text: The LLM's last assistant message (may or may not be a stall).

    Returns:
        The rewritten text. If the input isn't a stall, the original
        text is returned unchanged.
    """
    if not is_confirmation_question_stall(text):
        return text
    # Split text into (body_lines, last_stall_line). Drop the last
    # stall line, append a fixed "auto-continuing" line.
    base = text.rstrip()
    lines = base.splitlines()
    # Trim trailing empty lines (we'll add our own newline).
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return "Auto-continuing.\n"
    body = lines[:-1]  # everything except the last stall question
    # Body might be empty (LLM ended right with the question). In that
    # case we don't emit a body line — just the continuation statement.
    continuation_line = "Auto-continuing. (removed confirmation question)"
    rewritten = "\n".join(body + [continuation_line]) + "\n"
    return rewritten


def enforce_no_stall(
    text: str,
    *,
    context: str = "unknown",
) -> tuple[str, bool]:
    """Public self-check helper for the parent (orchestrator) loop.

    2026-06-09 (Issue 6 — never-stop hardening). The parent LLM
    (e.g. hack-deep) can emit a confirmation-question stall just
    like a subagent can, but unlike the subagent path it had no
    runtime gate. This helper gives the parent a one-liner it can
    call after every assistant turn:

        text, auto_continue = enforce_no_stall(text, context="hack-deep")

    On a stall, the text is rewritten via
    :func:`rewrite_stall_to_continuation` and ``auto_continue=True``
    is returned. The caller is expected to:

      1. Persist the rewritten text in place of the original.
      2. Fire the next turn immediately, NOT block on the
         operator (no ``AskUserQuestion``, no confirmation
         prompt, no agent-idle pause).

    On a non-stall, the original text is returned unchanged and
    ``auto_continue=False``.

    Args:
        text: The LLM's last assistant message (the parent's own
            output, not a subagent's reply).
        context: Free-form tag for observability — e.g. the agent
            id (``"hack-deep"``) or the wave (``"W4"``). Logged in
            the metric on a rewrite.

    Returns:
        (rewritten_text, auto_continue_flag).
    """
    if not text or not text.strip():
        return text, False
    if not is_confirmation_question_stall(text):
        return text, False
    rewritten = rewrite_stall_to_continuation(text)
    if rewritten == text:
        return text, False
    return rewritten, True
