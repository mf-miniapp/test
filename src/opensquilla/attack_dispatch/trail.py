"""Step trail — minimal Markdown view of a hack-deep run that survives L3/L4 compaction.

The executor writes per-wave evidence JSONs to disk at
``<artifact_root>/<wave>/<handoff_id>.json`` plus a top-level
``<artifact_root>/manifest.json``. This module derives a compact
Markdown "trail" from those artifacts so the orchestrating LLM can
recover "what we already did, where the full evidence lives" after
context compression has thrown away everything else.

The output file is ``<artifact_root>/trail.md`` (sibling of
``manifest.json``). Format: a header block, then three sections —
Wave runs, Drill-ins, Errors — and a literal ``## End of trail``
footer. The footer is the integrity marker ``StepTrailRebuilderHook``
scans for to confirm the read is complete.

Atomic write: the file is written to ``trail.md.tmp`` first and then
renamed via ``os.replace`` (atomic on POSIX and Windows for same-FS
moves). If ``os.replace`` fails, the ``.tmp`` file is unlinked so a
later rebuild does not read a half-written artifact.

Pure functions where possible; the only impure surface is
:func:`rebuild_trail_markdown` which writes to disk.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from opensquilla.attack_dispatch.executor import DispatchState


# Public constants ---------------------------------------------------------

TRAIL_FILENAME = "trail.md"
"""Sibling of ``manifest.json``; the in-prompt view is rebuilt from this file."""

# Token-budget for the in-prompt overlay (chars/token is an order-of-magnitude
# estimator). The hook reads ``AgentConfig.request_context_prompt_max_tokens``
# and translates to ~4 chars/token for the truncation rule.
_CHARS_PER_TOKEN = 4

# Brief cell cap. Keep small so the whole trail fits in the in-prompt
# budget (2000 tokens / 4 = 8000 chars / 4 columns = 2000 chars per cell).
_BRIEF_MAX_CHARS = 200

# When the trail overflows the in-prompt budget, keep the last N rows of
# the Wave runs / Drill-ins tables and add a pointer to the on-disk file.
_OVERFLOW_KEEP_ROWS = 5


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TrailRow(BaseModel):
    """One row of the in-prompt step trail table.

    All four fields are mandatory. ``brief`` is a deterministic 1-line
    summary the executor generates from the evidence JSON; the LLM can
    read the full record from ``path`` on demand.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    step: str = Field(description="handoff_id, e.g. 'W0.engagement-planning.1' or 'W1.6a'.")
    wave: str = Field(description="Parent wave id ('W0'..'W8') or drill-in slot id ('W1.6a').")
    brief: str = Field(description="1-line deterministic summary, <= 200 chars, no embedded newlines.")
    path: str = Field(description="Absolute path to the on-disk evidence JSON.")

    @field_validator("step", "wave")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be non-empty")
        return v

    @field_validator("brief")
    @classmethod
    def _bounded_brief(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("brief must be non-empty after strip")
        if len(v) > _BRIEF_MAX_CHARS:
            v = v[: _BRIEF_MAX_CHARS - 1] + "…"
        if "\n" in v or "\r" in v:
            v = v.replace("\r\n", "⏎").replace("\n", "⏎").replace("\r", "⏎")
        return v

    @field_validator("path")
    @classmethod
    def _absolute_path(cls, v: str) -> str:
        if not v:
            raise ValueError("path must be non-empty")
        if not Path(v).is_absolute():
            raise ValueError(f"path must be absolute: {v!r}")
        return v


class TrailSnapshot(BaseModel):
    """A complete snapshot used to render the Markdown trail file.

    Tuples (not lists) so the snapshot is hashable and frozen.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rows: tuple[TrailRow, ...] = Field(default_factory=tuple)
    drill_ins: tuple[TrailRow, ...] = Field(default_factory=tuple)
    errors: tuple[str, ...] = Field(default_factory=tuple)
    target: str | None = None
    started_at: datetime | None = None
    produced_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # 2026-06-08 (Issue 3): per-subdomain nested snapshots. The
    # per-subdomain driver (executor.run_per_subdomain) populates
    # this field with one TrailSnapshot per subdomain; the
    # markdown renderer emits a ``## Per-subdomain runs`` section
    # below the top-level ``## Wave runs`` table when this tuple
    # is non-empty. Default is empty tuple so the single-pass
    # path's output is unchanged.
    per_subdomain: tuple["TrailSnapshot", ...] = Field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Brief generation — deterministic, no LLM call
# ---------------------------------------------------------------------------


def _truncate(s: str, n: int) -> str:
    s = s.replace("\r\n", "⏎").replace("\n", "⏎").replace("\r", "⏎")
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _build_brief(evidence: dict[str, Any]) -> str:
    """Produce a 1-line deterministic summary from a typed evidence dict.

    Dispatches on ``evidence_schema`` (the discriminator every wave sets).
    Unknown schemas fall back to a generic "N fields" count so the table
    always has a row.
    """
    schema = evidence.get("evidence_schema", "unknown")
    if schema == "roe-v1":
        scope = _truncate(evidence.get("scope_summary", ""), 60)
        return _truncate(f"ROE: scope={scope}, success={evidence.get('success_unit', '?')}", _BRIEF_MAX_CHARS)
    if schema == "recon-v1":
        n_subs = len(evidence.get("subdomains") or [])
        n_services = len(evidence.get("services") or [])
        sharing = evidence.get("infra_sharing") or []
        n_shared = sum(len(e.get("shared_with") or []) for e in sharing)
        prefix = ""
        if evidence.get("parent_domain"):
            prefix = f"{evidence['parent_domain']}/"
        return _truncate(
            f"{prefix}{n_subs} subs, {n_services} services, infra-shared with {n_shared}",
            _BRIEF_MAX_CHARS,
        )
    if schema == "intel-v1":
        return _truncate(
            f"{len(evidence.get('findings') or [])} findings, "
            f"{len(evidence.get('sources') or [])} sources, "
            f"conf={evidence.get('confidence', '?')}",
            _BRIEF_MAX_CHARS,
        )
    if schema == "surface-v1":
        return _truncate(
            f"{len(evidence.get('entrypoints') or [])} entrypoints, "
            f"{len(evidence.get('asset_map') or [])} assets, "
            f"top{len(evidence.get('priority_top_n') or [])}",
            _BRIEF_MAX_CHARS,
        )
    if schema == "triage-v1":
        return _truncate(
            f"{len(evidence.get('candidates') or [])} candidates, "
            f"{len(evidence.get('prioritized_top_n') or [])} prioritized",
            _BRIEF_MAX_CHARS,
        )
    if schema == "opsec-v1":
        return _truncate(
            f"{len(evidence.get('low_interference_strategy') or [])} strat, "
            f"{len(evidence.get('audit_requirements') or [])} audits, "
            f"{len(evidence.get('per_target_group') or [])} per-tg",
            _BRIEF_MAX_CHARS,
        )
    if schema == "pentest-v1":
        findings = evidence.get("findings") or []
        owned = [f for f in findings if f.get("status") == "owned"]
        blocked = [f for f in findings if f.get("status") == "blocked"]
        ids = ", ".join(f.get("entry_id", "?") for f in owned[:3])
        return _truncate(
            f"{len(owned)} owned ({ids}), {len(blocked)} blocked, {len(findings)} total",
            _BRIEF_MAX_CHARS,
        )
    if schema in ("privesc-v1", "lateral-v1", "persist-v1", "impact-v1"):
        # These schemas share a similar shape (vectors/steps list + status).
        candidates = (
            evidence.get("escalation_vectors")
            or evidence.get("pivot_points")
            or evidence.get("options")
            or evidence.get("impact_model")
            or []
        )
        return _truncate(
            f"{len(candidates)} candidates", _BRIEF_MAX_CHARS
        )
    if schema == "cleanup-v1":
        return _truncate(
            f"{len(evidence.get('cleanup_checklist') or [])} cleanup items, "
            f"{len(evidence.get('risk_residual') or [])} residuals",
            _BRIEF_MAX_CHARS,
        )
    if schema == "report-v1":
        return _truncate(
            f"{len(evidence.get('per_target_finding') or [])} per-target, "
            f"{len(evidence.get('global_finding_index') or [])} global",
            _BRIEF_MAX_CHARS,
        )
    if schema == "sub_target_handle-v1":
        return _truncate(
            f"{len(evidence.get('handles') or [])} subdomain handles",
            _BRIEF_MAX_CHARS,
        )
    # Unknown schema — generic fallback.
    return _truncate(f"{len(evidence)} fields", _BRIEF_MAX_CHARS)


def _row_from_evidence(step: str, wave: str, path: str, evidence: dict[str, Any]) -> TrailRow:
    """Construct one TrailRow from an evidence JSON loaded off disk."""
    return TrailRow(step=step, wave=wave, brief=_build_brief(evidence), path=path)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _escape_cell(s: str) -> str:
    """Make a value safe to embed in a Markdown table cell."""
    return s.replace("|", "\\|").replace("\r\n", "⏎").replace("\n", "⏎").replace("\r", "⏎")


def _format_table(rows: tuple[TrailRow, ...] | list[TrailRow], placeholder: str) -> list[str]:
    """Render a 4-column Markdown table.

    ``placeholder`` is the body row shown when the table is empty
    (typically ``"(no waves yet)"`` or ``"(no drill-ins)"``).
    """
    out = [
        "| step | wave | brief | path |",
        "| --- | --- | --- | --- |",
    ]
    if not rows:
        out.append(f"| {placeholder} | | | |")
        return out
    for r in rows:
        out.append(
            f"| {_escape_cell(r.step)} "
            f"| {_escape_cell(r.wave)} "
            f"| {_escape_cell(r.brief)} "
            f"| `{_escape_cell(r.path)}` |"
        )
    return out


def _format_errors(errors: tuple[str, ...] | list[str]) -> list[str]:
    if not errors:
        return ["- (none)"]
    out: list[str] = []
    for e in errors:
        out.append(f"- {_truncate(e, 240)}")
    return out


def _format_markdown(snapshot: TrailSnapshot) -> str:
    """Render the snapshot to a Markdown string (the on-disk file body)."""
    target = snapshot.target or "(unset)"
    started = snapshot.started_at.isoformat() if snapshot.started_at else "(unset)"
    produced = snapshot.produced_at.isoformat()
    waves_done = len({r.wave for r in snapshot.rows})
    step_count = len(snapshot.rows) + len(snapshot.drill_ins)

    lines: list[str] = []
    lines.append("# Step trail — hack-deep run")
    lines.append("")
    lines.append(f"- target: {target}")
    lines.append(f"- started: {started}")
    lines.append(f"- produced: {produced}")
    lines.append(f"- waves: {waves_done}")
    lines.append(f"- step_count: {step_count}")
    lines.append(f"- source: {TRAIL_FILENAME}")
    lines.append("")
    lines.append("## Wave runs")
    lines.append("")
    lines.extend(_format_table(snapshot.rows, "(no waves yet)"))
    lines.append("")
    # 2026-06-08 (Issue 3): per-subdomain sections. When the
    # per-subdomain driver ran, the top-level ``## Wave runs`` table
    # contains only the prelude (W0/W0.5); each subdomain's
    # W1..W8 evidence is rendered as a nested sub-section below.
    if snapshot.per_subdomain:
        lines.append("## Per-subdomain runs")
        lines.append("")
        for sub_snap in snapshot.per_subdomain:
            sub_target = sub_snap.target or "(unset)"
            sub_waves = len({r.wave for r in sub_snap.rows})
            sub_steps = len(sub_snap.rows) + len(sub_snap.drill_ins)
            lines.append(f"### {sub_target}")
            lines.append("")
            lines.append(
                f"- target: {sub_target}  "
                f"waves: {sub_waves}  "
                f"step_count: {sub_steps}"
            )
            lines.append("")
            lines.append("#### Wave runs (this subdomain)")
            lines.append("")
            lines.extend(_format_table(sub_snap.rows, "(no waves yet)"))
            lines.append("")
            if sub_snap.drill_ins:
                lines.append("#### Drill-ins (this subdomain)")
                lines.append("")
                lines.extend(_format_table(sub_snap.drill_ins, "(no drill-ins)"))
                lines.append("")
        lines.append("")
    lines.append("## Drill-ins")
    lines.append("")
    lines.extend(_format_table(snapshot.drill_ins, "(no drill-ins)"))
    lines.append("")
    lines.append("## Errors")
    lines.append("")
    lines.extend(_format_errors(snapshot.errors))
    lines.append("")
    lines.append("## End of trail")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Atomic write helper
# ---------------------------------------------------------------------------


def _atomic_write_text(path: Path, content: str) -> bool:
    """Write ``content`` to ``path`` atomically.

    Returns True on success, False on any OSError. The temp file is
    unlinked on failure so the next attempt starts clean. The rename
    step is the only atomic operation — readers always see either the
    full old content or the full new content, never a half-written
    file.
    """
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        return False
    except Exception:  # noqa: BLE001 — last-ditch cleanup, never raise from a writer
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        return False


# ---------------------------------------------------------------------------
# Build + write
# ---------------------------------------------------------------------------


def build_snapshot(
    state: "DispatchState",
    *,
    target: str | None = None,
    started_at: datetime | None = None,
) -> TrailSnapshot:
    """Build a :class:`TrailSnapshot` from executor state + on-disk evidence.

    For each parent wave in ``state.evidence_paths``:
      - Read the on-disk JSON (best-effort; failure is logged to errors)
      - Build a Wave-run row
    For each entry in ``state.specialist_artifacts`` (SERIAL mode):
      - Read the per-specialist JSON
      - Build a Drill-in row with a ``serial:`` prefix
    For each ``state.drill_ins`` entry:
      - Read the slot artifact at ``<artifact_root>/<wave>.drill_in/<slot>.json``
      - Build a Drill-in row with a ``drill:`` prefix
    The last 10 unique errors are returned (deduped, ordered).
    """
    from opensquilla.attack_dispatch.executor import DispatchState  # local import to avoid cycle

    if not isinstance(state, DispatchState):
        raise TypeError(f"state must be DispatchState, got {type(state).__name__}")

    rows: list[TrailRow] = []
    drill_rows: list[TrailRow] = []
    errors: list[str] = []

    # Parent waves (one row each).
    for wave, path_str in state.evidence_paths.items():
        try:
            evidence = _read_evidence(path_str)
        except (OSError, ValueError) as exc:
            errors.append(f"{wave}: read failed: {exc}")
            continue
        if evidence is None:
            errors.append(f"{wave}: empty artifact at {path_str}")
            continue
        # Choose a step id from the evidence session_id if present, else derive.
        session_id = evidence.get("session_id") or f"{wave}.{evidence.get('agent', '?')}.1"
        rows.append(_row_from_evidence(session_id, wave, path_str, evidence))

    # Sort parent-wave rows by canonical wave order.
    from opensquilla.attack_dispatch.waves import WAVE_NAMES  # late import

    rows.sort(key=lambda r: WAVE_NAMES.index(r.wave) if r.wave in WAVE_NAMES else 999)

    # SERIAL mode per-specialist rows.
    for handoff_id, path_str in (state.specialist_artifacts or {}).items():
        try:
            evidence = _read_evidence(path_str)
        except (OSError, ValueError) as exc:
            errors.append(f"{handoff_id}: read failed: {exc}")
            continue
        if evidence is None:
            continue
        # Use the parent wave (Wn) as the wave column.
        parent_wave = handoff_id.split(".", 1)[0] if "." in handoff_id else handoff_id
        brief_raw = _build_brief(evidence)
        # Mark as serial so the table signals it.
        brief = f"serial: {brief_raw}" if not brief_raw.startswith("serial:") else brief_raw
        try:
            drill_rows.append(TrailRow(step=handoff_id, wave=parent_wave, brief=brief, path=path_str))
        except ValueError as exc:
            errors.append(f"{handoff_id}: row invalid: {exc}")

    # Drill-in slot rows.
    for d in state.drill_ins or []:
        slot = getattr(d, "slot", None) or getattr(d, "name", None)
        if not slot:
            continue
        parent = getattr(d, "parent_wave", None) or slot.split(".", 1)[0]
        # The slot file is at <artifact_root>/<parent>.drill_in/<slot>.json.
        # We do not know the artifact_root from state alone, so we ask the
        # caller to pass it via the DrillInSpec. As a fallback, we just
        # mark the row without a path (path="" is rejected by the validator;
        # use a placeholder absolute path that the executor rewrites on the
        # next wave). For now, skip drill-in rows we cannot resolve.
        reason_class = getattr(d, "reason_class", None) or getattr(d, "reason", "")
        reason_detail = getattr(d, "reason_detail", "") or ""
        brief = f"drill: {reason_class} on {parent}: {_truncate(reason_detail, 80)}"
        # No path known — omit. Drill-in rows are best-effort.
        # We surface the brief in the snapshot's drill_ins list by adding a
        # synthetic row only if we can compute a path; otherwise drop silently.
        # The build_snapshot caller is expected to also pass a slot path
        # resolver (see executor wiring).
        # For now: if d has ``slot_path`` (set by executor), use it.
        slot_path = getattr(d, "slot_path", None)
        if slot_path:
            try:
                drill_rows.append(TrailRow(step=slot, wave=slot, brief=brief, path=slot_path))
            except ValueError as exc:
                errors.append(f"{slot}: row invalid: {exc}")

    # Dedupe errors, keep last 10.
    seen: set[str] = set()
    deduped_errors: list[str] = []
    for e in state.errors or []:
        if e in seen:
            continue
        seen.add(e)
        deduped_errors.append(e)
        if len(deduped_errors) >= 10:
            break

    return TrailSnapshot(
        rows=tuple(rows),
        drill_ins=tuple(drill_rows),
        errors=tuple(deduped_errors),
        target=target,
        started_at=started_at,
        # 2026-06-08 (Issue 3): per-subdomain nested snapshots.
        # When the per-subdomain driver populated
        # ``state.per_subdomain_results``, build a sub-snapshot per
        # subdomain and pass them through. The sub-snapshots are
        # themselves full :class:`TrailSnapshot` instances, so the
        # markdown renderer can recurse without special-casing.
        per_subdomain=tuple(
            _build_subdomain_snapshot(
                sub, results, target=sub, started_at=started_at,
            )
            for sub, results in sorted(
                (state.per_subdomain_results or {}).items()
            )
        ),
    )


def _build_subdomain_snapshot(
    subdomain: str,
    wave_results: list[Any],
    *,
    target: str,
    started_at: datetime | None,
) -> TrailSnapshot:
    """Build a per-subdomain :class:`TrailSnapshot` (2026-06-08, Issue 3).

    The per-subdomain driver keeps the per-subdomain evidence in
    on-disk files under ``<artifact_root>/<subdomain>/<wave>/...``.
    We re-read those files via the standard evidence-paths lookup
    so the sub-snapshot mirrors the top-level snapshot's shape —
    same row format, same brief generator, same drill-in
    classification.

    Wave results from ``state.per_subdomain_results`` are
    WaveResult objects; we extract the on-disk evidence via
    the dispatch executor's manifest keys. The implementation is
    intentionally minimal — the markdown renderer needs only
    ``rows`` + ``drill_ins`` + ``target`` for the per-subdomain
    sections; we do NOT duplicate the per-specialist SERIAL rows
    here (they live in the top-level snapshot's ``drill_ins``).
    """
    from opensquilla.attack_dispatch.executor import WaveResult  # local
    rows: list[TrailRow] = []
    drill_rows: list[TrailRow] = []
    if not wave_results:
        return TrailSnapshot(
            rows=(),
            drill_ins=(),
            target=target,
            started_at=started_at,
        )
    for wr in wave_results:
        if not isinstance(wr, WaveResult):
            continue
        if wr.error or wr.evidence is None:
            continue
        # The per-subdomain W4 evidence carries the verifier
        # counters; surface a deterministic 1-line summary in the
        # brief cell via a synthetic row.
        try:
            evidence_dict = wr.evidence.model_dump(mode="json")
        except Exception:  # noqa: BLE001 — best-effort
            evidence_dict = {}
        # Use the per-subdomain evidence path if the wave wrote one;
        # otherwise fall back to a synthetic path that the renderer
        # can recognize.
        path = f"<per-subdomain>/{subdomain}/{wr.wave}"
        rows.append(
            TrailRow(
                step=f"{wr.wave}.sub.{subdomain}",
                wave=wr.wave,
                brief=_per_subdomain_brief(evidence_dict, wr),
                path=path,
            )
        )
    return TrailSnapshot(
        rows=tuple(rows),
        drill_ins=tuple(drill_rows),
        target=target,
        started_at=started_at,
    )


def _per_subdomain_brief(evidence_dict: dict[str, Any], wr: Any) -> str:
    """Build the brief cell for one per-subdomain wave row.

    Mirrors :func:`_build_brief`'s shape but appends the
    ``(verified X/Y, downgraded Z)`` suffix for W4 so the
    operator can read the verifier counters at a glance without
    opening the on-disk JSON.
    """
    base = _build_brief(evidence_dict) if evidence_dict else "(empty evidence)"
    if wr.wave == "W4":
        suffix = f" — verified {wr.findings_verified}, downgraded {wr.findings_downgraded}"
        base = (base + suffix)[:_BRIEF_MAX_CHARS]
    return base


def _read_evidence(path_str: str) -> dict[str, Any] | None:
    """Best-effort read of a per-wave or per-specialist JSON file.

    Returns the ``evidence`` dict if present, else the top-level dict.
    Returns None on empty / JSON-decode failure.
    """
    p = Path(path_str)
    raw = p.read_text(encoding="utf-8")
    import json

    parsed = json.loads(raw) if raw.strip() else None
    if parsed is None:
        return None
    if not isinstance(parsed, dict):
        return None
    ev = parsed.get("evidence")
    if isinstance(ev, dict):
        return ev
    return parsed


def rebuild_trail_markdown(
    artifact_root: Path | str,
    state: "DispatchState",
    *,
    target: str | None = None,
    started_at: datetime | None = None,
) -> Path | None:
    """Build the trail snapshot and write it to ``<artifact_root>/trail.md``.

    Returns the path on success, None on any write failure. The caller
    is expected to have already populated ``state.evidence_paths`` and
    (in SERIAL mode) ``state.specialist_artifacts``.
    """
    root = Path(artifact_root)
    snapshot = build_snapshot(state, target=target, started_at=started_at)
    content = _format_markdown(snapshot)
    trail_path = root / TRAIL_FILENAME
    if _atomic_write_text(trail_path, content):
        return trail_path
    return None


# ---------------------------------------------------------------------------
# Truncation for the in-prompt overlay
# ---------------------------------------------------------------------------


def truncate_trail_for_overlay(
    content: str,
    max_tokens: int,
) -> str:
    """Truncate a full ``trail.md`` body to the in-prompt budget.

    Keeps the header + the LAST N rows of each table + a pointer to
    the on-disk file. Used by ``StepTrailRebuilderHook`` so the
    injected overlay never blows up the request budget.
    """
    if max_tokens <= 0:
        return content  # 0 = unbounded; hook default is non-zero
    char_budget = max_tokens * _CHARS_PER_TOKEN
    # Pad char budget so the table-trim path activates reliably even when
    # the per-section parsing leaves the body slightly over budget.
    effective_budget = max(1, char_budget - 32)
    if len(content) <= effective_budget:
        return content

    # Split into sections by H2 headers, keep header, keep last N table rows.
    sections: list[tuple[str, list[str]]] = []
    current_name = ""
    current_lines: list[str] = []
    for line in content.splitlines():
        if line.startswith("## "):
            if current_name or current_lines:
                sections.append((current_name, current_lines))
            current_name = line
            current_lines = []
        else:
            current_lines.append(line)
    if current_name or current_lines:
        sections.append((current_name, current_lines))

    # Find the Wave runs and Drill-ins sections and trim their bodies.
    out: list[str] = []
    for name, body in sections:
        if name in ("## Wave runs", "## Drill-ins"):
            # The body is: blank, header row, separator row, then N data rows.
            # Find the first data row.
            data_idx = None
            for i, line in enumerate(body):
                if line.startswith("| ") and not line.startswith("| ---") and not line.startswith("| step "):
                    data_idx = i
                    break
            if data_idx is None:
                out.append(name)
                out.extend(body)
                continue
            data_rows = body[data_idx:]
            if len(data_rows) > _OVERFLOW_KEEP_ROWS:
                kept = data_rows[-_OVERFLOW_KEEP_ROWS:]
                out.append(name)
                out.extend(body[:data_idx])
                out.extend(kept)
                out.append("")
                out.append(f"… (showing last {_OVERFLOW_KEEP_ROWS} of {len(data_rows)} rows; full file at TRAIL_PATH)")
            else:
                out.append(name)
                out.extend(body)
        else:
            out.append(name)
            out.extend(body)
    truncated = "\n".join(out)
    if len(truncated) > char_budget:
        # Last-resort: hard-cap by characters, keep the head.
        truncated = truncated[:char_budget] + "\n…[truncated]"
    return truncated
