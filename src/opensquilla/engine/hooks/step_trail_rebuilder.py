"""Compaction hook that re-injects the step-trail overlay after L3/L4 compaction.

After context compression, the LLM loses all "what we already did"
memory. This hook re-reads ``<artifact_root>/trail.md`` (the
compact Markdown view the executor maintains) and prepends it to
``agent.config.request_context_prompt`` so the orchestrator can
recover "W0..Wn are done; here is where the full evidence lives".

The hook uses an mtime cache: when ``trail.md`` has not changed
since the last ``after_compact`` call, the previously built overlay
is reused. When it has changed (a new wave finished since the last
compaction), the file is re-read, truncated to the per-agent
``request_context_prompt_max_tokens`` budget, and the new overlay
is prepended.

Exception isolation: every code path is wrapped in
``except Exception: pass`` so a misbehaving hook (disk full, bad
JSON, missing agent_workspace_dir) cannot break a turn. The
surrounding stage also swallows hook exceptions
(``compaction_and_history_stage._fire_after_compact``), so this is
defense-in-depth.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from opensquilla.attack_dispatch.trail import (
    TRAIL_FILENAME,
    truncate_trail_for_overlay,
)
from opensquilla.engine.hooks.types import CompactionState


# Header prepended to the overlay so the LLM knows the table is a
# pre-injected artifact and not part of its own output. Mirrors the
# "## Upstream context (per-step archive)" header used in the
# executor's per-wave brief block (executor.py:1264-1280).
_OVERLAY_HEADER = "## Step trail (auto-rebuilt from disk after compaction)"


# ---------------------------------------------------------------------------
# Optional agent access protocol — the hook only needs .config, but tests
# may pass plain SimpleNamespace mocks.
# ---------------------------------------------------------------------------


@runtime_checkable
class _HasConfig(Protocol):
    config: Any


def _agent_config(agent: Any) -> Any | None:
    """Best-effort accessor for an agent's AgentConfig.

    Returns None if the agent is not a structural match (e.g. a
    SimpleNamespace in tests without a `config` attribute).
    """
    if isinstance(agent, _HasConfig):
        return agent.config
    return getattr(agent, "config", None)


def _resolve_trail_path(
    state: CompactionState,
    agent: Any,
    default_artifact_root: Path | str | None,
) -> Path | None:
    """Resolve the on-disk trail file path.

    Priority (most-specific to least):
      1. ``state.extra["artifact_root"]`` — when set by the caller.
      2. ``agent.config.workspace_dir/memory/waves/trail.md`` — per-agent.
      3. ``default_artifact_root/trail.md`` — when supplied at construction.
      4. ``None`` — non-pentest agent, the hook no-ops.
    """
    try:
        # 1. explicit override via CompactionState.extra
        extra_root = state.extra.get("artifact_root") if state.extra else None
        if extra_root:
            return Path(extra_root) / TRAIL_FILENAME

        # 2. agent's own workspace
        cfg = _agent_config(agent)
        ws = getattr(cfg, "workspace_dir", None) if cfg is not None else None
        if ws:
            return Path(ws) / "memory" / "waves" / TRAIL_FILENAME

        # 3. constructor-provided default
        if default_artifact_root is not None:
            return Path(default_artifact_root) / TRAIL_FILENAME

        return None
    except (OSError, TypeError, ValueError):
        return None


class StepTrailRebuilderHook:
    """``CompactionHook`` that re-injects the step trail after compaction.

    The hook is designed to be registered in the
    ``CompactionAndHistoryStage.compaction_hooks`` tuple. It mutates
    ``agent.config.request_context_prompt`` in place from
    ``after_compact``, which crosses the architectural boundary
    documented in ``compaction_and_history_stage.py`` (the harness is
    the only "official" mutator for that field). This is a deliberate
    trade-off for simplicity — see plan §10.1.
    """

    name = "step_trail_rebuilder"

    def __init__(
        self,
        *,
        artifact_root: Path | str | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self._default_artifact_root = (
            Path(artifact_root) if artifact_root is not None else None
        )
        # Per-trail-path mtime cache. Keys are absolute path strings;
        # values are the last-seen mtime in nanoseconds.
        self._mtime_cache: dict[str, int] = {}
        # Cached overlay keyed on (path, mtime). Reuse when mtime
        # hasn't changed.
        self._overlay_cache: dict[str, tuple[int, str]] = {}
        # Default token budget when the agent does not expose
        # ``request_context_prompt_max_tokens``. 2000 tokens ≈ 8000
        # chars at 4 chars/token.
        self._default_max_tokens = max_tokens if max_tokens is not None else 2000

    async def before_compact(self, state: CompactionState) -> None:
        return None  # One-way: read on after_compact, never on before.

    async def after_compact(self, state: CompactionState, outcome: Any) -> None:
        try:
            await self._maybe_inject(state, outcome)
        except Exception:  # noqa: BLE001 — hook isolation contract
            pass

    async def _maybe_inject(
        self,
        state: CompactionState,
        outcome: Any,
    ) -> None:
        agent = self._extract_agent(state, outcome)
        path = _resolve_trail_path(state, agent, self._default_artifact_root)
        if path is None:
            return  # non-pentest agent, nothing to do

        try:
            stat_result = path.stat()
        except (OSError, FileNotFoundError):
            return  # file not yet written (first compaction) or disk error

        path_key = str(path)
        mtime_ns = getattr(stat_result, "st_mtime_ns", int(stat_result.st_mtime * 1e9))
        cached = self._overlay_cache.get(path_key)
        if cached and cached[0] == mtime_ns:
            overlay = cached[1]
        else:
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return
            # Truncate to the per-agent budget (or hook default).
            max_tokens = self._resolve_max_tokens(agent)
            overlay_body = truncate_trail_for_overlay(content, max_tokens=max_tokens)
            overlay = f"{_OVERLAY_HEADER}\n\n{overlay_body}"
            self._overlay_cache[path_key] = (mtime_ns, overlay)
            self._mtime_cache[path_key] = mtime_ns

        # Mutate the agent's request_context_prompt. The stage's
        # "harness is the only mutator" boundary is intentionally
        # crossed here for ephemeral overlays like the trail (see
        # compaction_and_history_stage docstring update).
        cfg = _agent_config(agent)
        if cfg is None:
            return
        existing = getattr(cfg, "request_context_prompt", None) or ""
        if existing.startswith(_OVERLAY_HEADER):
            # The previous overlay is already at the top of
            # request_context_prompt. Detect its end (the first `## `
            # heading that is not a trail sub-section) and replace just
            # the overlay prefix with the freshly built one.
            tail_start = _find_overlay_end(existing)
            tail = existing[tail_start:] if tail_start < len(existing) else ""
            new = f"{overlay}{tail}".rstrip() if tail else overlay
        else:
            new = f"{overlay}\n\n{existing}".rstrip() if existing else overlay
        try:
            cfg.request_context_prompt = new
        except (AttributeError, TypeError, ValueError):
            pass  # frozen dataclass or otherwise immutable

    def _resolve_max_tokens(self, agent: Any) -> int:
        cfg = _agent_config(agent)
        if cfg is None:
            return self._default_max_tokens
        value = getattr(cfg, "request_context_prompt_max_tokens", None)
        if isinstance(value, int) and value > 0:
            return value
        return self._default_max_tokens

    @staticmethod
    def _extract_agent(state: CompactionState, outcome: Any) -> Any | None:
        """Best-effort: find the Agent object on state or outcome.

        The stage's harness doesn't pass the agent directly to the
        hook; we read it from ``state.extra`` when the runtime
        supplies it (a non-binding convention; the hook works
        regardless). Falls back to ``None`` for a no-op.
        """
        extra = state.extra or {}
        return extra.get("agent") or extra.get("_agent")


def _find_overlay_end(text: str) -> int:
    """Find the index just after the trail overlay block in ``text``.

    The overlay is delimited at the top by ``_OVERLAY_HEADER`` and at
    the bottom by the first ``## `` heading that is NOT part of the
    trail's own H2 sections (``## Wave runs`` / ``## Drill-ins`` /
    ``## Errors`` / ``## End of trail``), or end-of-string. This
    prevents the trail's own headers from prematurely terminating the
    overlay block.
    """
    # The H2 sections that belong to the trail overlay and must be
    # skipped when finding the overlay's tail boundary.
    _TRAIL_OWN_SECTIONS = frozenset({
        "## Wave runs",
        "## Drill-ins",
        "## Errors",
        "## End of trail",
    })
    start = text.find(_OVERLAY_HEADER)
    if start < 0:
        return 0
    # Skip the header line itself.
    cursor = text.find("\n", start)
    if cursor < 0:
        return len(text)
    cursor += 1
    # Scan forward for the next H2 heading that is NOT a trail section.
    while cursor < len(text):
        newline = text.find("\n", cursor)
        if newline < 0:
            return len(text)
        line = text[cursor:newline]
        if line.startswith("## ") and line not in _TRAIL_OWN_SECTIONS:
            return cursor
        cursor = newline + 1
    return len(text)


def build_step_trail_hook(
    *,
    artifact_root: Path | str | None = None,
    max_tokens: int | None = None,
) -> StepTrailRebuilderHook:
    """Factory used by the runtime to construct the hook with defaults."""
    return StepTrailRebuilderHook(artifact_root=artifact_root, max_tokens=max_tokens)
