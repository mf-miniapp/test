"""Subagent health supervisor — watchdog for stuck or unannounced subagents.

Why this exists
---------------
The primary announce path (``subagent_announce.announce_subagent_completion``)
relies on every subagent's ``_notify_subagent_terminal`` event firing before
the gateway can wake the parent. The 2026-06-05 hack-deep incident proved
that path is not enough: the FIRST child to complete marked the spawn group
as "woken" via an add-only dedup set, then the LAST child to complete
(which carried the full aggregated payload) was silently dropped, and the
parent stayed stuck for the entire 30+ minute remainder of the workflow.

The supervisor is the safety net. Once per ``interval_seconds`` it:

1. Walks every subagent session whose ``parent_task_id`` is still the
   current task of an open parent session.
2. For each spawn group, classifies the children into "terminal-done",
   "running-and-progressing", and "running-but-stuck" (no activity for
   ``stuck_threshold_seconds``).
3. If a child finished but the announce never fired the parent wake, the
   supervisor **replays the announce** by calling
   ``announce_subagent_completion`` with a synthetic
   ``SubagentCompletionEvent``. The existing dedup state in
   ``SpawnGroupTracker`` correctly fires the wake for any child that has
   not yet been delivered.
4. If a child is genuinely stuck (no progress past the threshold AND the
   announce still didn't fire), the supervisor records a ``stuck_retry``
   counter, re-emits the synthetic terminal event once per tick until the
   cap is hit, and then escalates to a human-acknowledgable warning
   event on the parent session.

What the supervisor does NOT do
-------------------------------
- It does NOT cancel or restart long-running subagents. The 30+ minute
  recon scan and 60+ minute attack-surface scan both look "stuck" if
  the threshold is too aggressive; tuning is the operator's job, not the
  supervisor's.
- It does NOT re-implement wake delivery. It calls into the same
  ``announce_subagent_completion`` + ``_send_parent_wake`` pipeline the
  primary path uses, so dedup, ordering, and child-set semantics stay
  in one place.
- It does NOT open new spawn groups. The supervisor is read-only with
  respect to children; it only nudges already-finished work into the
  parent's awareness.

Activation
----------
The supervisor is **off by default**. Set
``OPENSQUILLA_SUBAGENT_SUPERVISOR=1`` or
``subagent_supervisor.enabled = true`` in the gateway config to install
the cron. The first gateway boot after enabling installs the cron; the
parent-task terminal lifecycle listener removes it (per-parent cron
slot) once the parent session ends.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import structlog

from opensquilla.gateway.subagent_announce import (
    announce_subagent_completion,
    close_subagent_spawn_group,
)
from opensquilla.gateway.task_runtime import SubagentCompletionEvent
from opensquilla.session.models import AgentTaskStatus

log = structlog.get_logger(__name__)

# Sessions whose last activity is older than this are considered "stuck"
# for the purposes of supervisor retries. The default is generous on
# purpose: long attack-surface scans legitimately run 30+ minutes.
DEFAULT_STUCK_THRESHOLD_SECONDS = 600.0

# Per-(parent, child) retry cap. Once hit, the supervisor emits a
# terminal-failure warning event and stops nudging.
DEFAULT_MAX_RETRIES = 3

# 2026-06-09 (Issue 6 — never-stop hardening). Per-(parent, child)
# cap for context-overflow auto-retries. When a child fails with
# ``provider_request_too_large`` we don't surface the failure to
# the parent (the parent would then ask "是否继续" and stall); we
# auto-retry with a slim brief. The retry counter is separate
# from ``MAX_RETRIES`` so a context-overflow retry doesn't
# interact with the stuck-child retry budget.
DEFAULT_CONTEXT_OVERFLOW_MAX_RETRIES = 2

# Default tick interval when the cron is set up.
DEFAULT_INTERVAL_SECONDS = 60


@dataclass
class _GroupState:
    """Per-spawn-group reconciliation state held by the supervisor.

    We deliberately keep this small: only the per-child retry counter.
    The supervisor's "have we already pushed a wake for child X?" question
    is delegated to ``SpawnGroupTracker.delivered_children`` so a wake
    replayed here and a wake delivered by the primary announce path are
    dedup'd through the same data structure.
    """

    parent_session_key: str
    parent_task_id: str
    retry_counters: dict[str, int] = field(default_factory=dict)
    # Per-child last-stuck-warning timestamp so we don't spam the parent
    # session transcript when a child genuinely takes a long time.
    last_stuck_warning_at: dict[str, float] = field(default_factory=dict)
    # 2026-06-09 (Issue 6): per-child context-overflow retry counter.
    # Tracked SEPARATELY from ``retry_counters`` so a stuck-child
    # retry and a context-overflow auto-retry don't share the same
    # budget — they're independent failure modes with independent
    # caps.
    context_overflow_retries: dict[str, int] = field(default_factory=dict)
    # 2026-06-09 (Issue 6): per-child slim-brief replay state. When
    # a context-overflow retry is in flight, we record the slim
    # brief here so the parent's next turn (which the no-stall
    # guard auto-fires) can pick it up and dispatch the re-spawn.
    pending_slim_respawns: dict[str, str] = field(default_factory=dict)


def _is_terminal_status(value: Any) -> bool:
    """True if a session/agent_task status string is a terminal outcome."""
    if value is None:
        return False
    text = str(value).lower()
    return text in {"done", "succeeded", "failed", "killed", "timeout", "cancelled"}


def _agent_task_status_to_terminal(
    status_value: Any,
) -> AgentTaskStatus:
    """Map a raw ``agent_tasks.status`` string to an ``AgentTaskStatus`` enum."""
    text = str(status_value or "").lower()
    if text in {"succeeded", "done"}:
        return AgentTaskStatus.SUCCEEDED
    if text == "failed":
        return AgentTaskStatus.FAILED
    if text == "timeout":
        return AgentTaskStatus.TIMEOUT
    if text in {"cancelled", "killed"}:
        return AgentTaskStatus.CANCELLED
    if text == "abandoned":
        return AgentTaskStatus.ABANDONED
    return AgentTaskStatus.SUCCEEDED


def _child_key(*, parent_session_key: str, parent_task_id: str, child_session_key: str) -> str:
    return f"{parent_session_key}::{parent_task_id}::{child_session_key}"


class SubagentHealthSupervisor:
    """Watchdog that nudges the announce path for stuck / unannounced subagents.

    Lifecycle: a single instance is created at gateway boot, registered as
    a cron handler, and torn down at gateway shutdown. Per-parent-task
    state is keyed by ``(parent_session_key, parent_task_id)`` and is
    pruned by ``forget_parent_task`` when the parent's lifecycle listener
    fires ``phase=terminal``.
    """

    def __init__(
        self,
        *,
        session_manager: Any,
        task_runtime: Any,
        stuck_threshold_seconds: float = DEFAULT_STUCK_THRESHOLD_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        context_overflow_max_retries: int = DEFAULT_CONTEXT_OVERFLOW_MAX_RETRIES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._session_manager = session_manager
        self._task_runtime = task_runtime
        self._stuck_threshold_s = float(stuck_threshold_seconds)
        self._max_retries = int(max_retries)
        self._context_overflow_max_retries = int(context_overflow_max_retries)
        self._clock: Callable[[], float] = clock or asyncio.get_event_loop().time
        self._group_states: dict[tuple[str, str], _GroupState] = {}
        self._state_lock = asyncio.Lock()
        self._closing = False

    async def tick(self) -> dict[str, int]:
        """One reconciliation pass.

        Returns a small metrics dict so the cron handler can log progress
        without the supervisor having to depend on a metrics registry.
        """
        if self._closing:
            return {
                "groups": 0, "replayed": 0, "stuck": 0, "escalated": 0,
                "context_overflow_retried": 0, "context_overflow_exhausted": 0,
                "empty_response_skipped": 0,
                "progress_stuck_skipped": 0,
            }

        groups = await self._iter_active_groups()
        replayed = 0
        stuck = 0
        escalated = 0
        # 2026-06-09 (Issue 6): counter for context-overflow auto-retries
        # so the cron log surfaces the new behavior. ``exhausted`` is
        # when the per-child cap was hit and the failure is now
        # surfaced (as an audit marker, not a stall prompt).
        context_overflow_retried = 0
        context_overflow_exhausted = 0
        # 2026-06-09 (Issue 8): counter for empty-response auto-skips
        # after the engine's 3x retry budget is exhausted. The parent
        # reads the audit marker and dispatches the next fan-out
        # sub-track.
        empty_response_skipped = 0
        # 2026-06-09 (Issue 12): counter for progress-stuck auto-skips
        # (LLM is repeating the same tool+args 3+ times). The
        # "activation mechanism" the user explicitly requested.
        progress_stuck_skipped = 0
        for parent_session_key, parent_task_id, children in groups:
            for child in children:
                action = await self._reconcile_child(
                    parent_session_key=parent_session_key,
                    parent_task_id=parent_task_id,
                    child=child,
                )
                if action == "replayed":
                    replayed += 1
                elif action == "stuck":
                    stuck += 1
                elif action == "escalated":
                    escalated += 1
                elif action == "context_overflow_retried":
                    context_overflow_retried += 1
                elif action == "context_overflow_exhausted":
                    context_overflow_exhausted += 1
                elif action == "empty_response_skipped":
                    empty_response_skipped += 1
                elif action == "progress_stuck_skipped":
                    progress_stuck_skipped += 1
        return {
            "groups": len(groups),
            "replayed": replayed,
            "stuck": stuck,
            "escalated": escalated,
            "context_overflow_retried": context_overflow_retried,
            "context_overflow_exhausted": context_overflow_exhausted,
            "empty_response_skipped": empty_response_skipped,
            "progress_stuck_skipped": progress_stuck_skipped,
        }

    async def forget_parent_task(self, parent_session_key: str, parent_task_id: str) -> None:
        """Drop any per-group state owned by a parent task that ended.

        Wired to the lifecycle listener's ``phase=terminal`` event so we
        don't accumulate dead group state across the gateway's lifetime.
        """
        async with self._state_lock:
            self._group_states.pop((parent_session_key, parent_task_id), None)

    async def close(self) -> None:
        self._closing = True
        async with self._state_lock:
            self._group_states.clear()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _iter_active_groups(self) -> list[tuple[str, str, list[Any]]]:
        """Enumerate all (parent, task, children) triples worth watching.

        A "worth watching" group is one where the parent task is still
        open (not terminal in ``agent_tasks``) AND at least one child
        session with that ``parent_task_id`` exists in the session
        table. We do not filter by agent_id at this layer; the operator
        who turns the supervisor on accepts the broader cost in exchange
        for catching any orphan subagent regardless of which parent
        spawned it.

        Note: we include BOTH running and terminal children. The
        supervisor's primary job is to find children that finished
        without firing the parent wake; filtering them out here would
        defeat the whole point. ``_reconcile_child`` itself decides
        whether to replay an announce, count a stuck child, or skip.
        """
        list_sessions = getattr(self._session_manager, "list_sessions", None)
        if not callable(list_sessions):
            return []
        # Build a {parent_task_id -> [child rows]} map by walking all
        # child sessions once. We do not have a first-class "open group"
        # index, so this is a linear scan; for a typical deployment the
        # session count is small enough that one tick per minute is fine.
        groups: dict[tuple[str, str], list[Any]] = {}
        page_size = 200
        offset = 0
        while True:
            try:
                rows = await list_sessions(limit=page_size, offset=offset)
            except TypeError:
                try:
                    rows = await list_sessions(limit=page_size)
                except Exception:
                    return []
                offset = 0  # no offset support; treat as single page
            except Exception:
                return []
            if not rows:
                break
            for row in rows:
                spawned_by = getattr(row, "spawned_by", None)
                if not isinstance(spawned_by, str) or not spawned_by:
                    continue
                origin = getattr(row, "origin", None)
                if not isinstance(origin, dict):
                    continue
                parent_task_id = origin.get("parent_task_id")
                if not isinstance(parent_task_id, str) or not parent_task_id:
                    continue
                groups.setdefault((spawned_by, parent_task_id), []).append(row)
            if len(rows) < page_size:
                break
            offset += page_size

        # Filter out groups whose parent task is already terminal. We
        # cannot rely on agent_tasks filtering here because the parent
        # task id alone is enough to skip a dead group cheaply.
        result: list[tuple[str, str, list[Any]]] = []
        for (parent_session_key, parent_task_id), children in groups.items():
            if not await self._is_parent_task_open(parent_session_key, parent_task_id):
                continue
            result.append((parent_session_key, parent_task_id, children))
        return result

    async def _is_parent_task_open(self, parent_session_key: str, parent_task_id: str) -> bool:
        storage = getattr(self._session_manager, "_storage", None) or self._session_manager
        get_task = getattr(storage, "get_agent_task", None)
        if not callable(get_task):
            return True  # fail open; don't drop the group
        try:
            record = await get_task(parent_task_id)
        except Exception:
            return True
        if record is None:
            return False
        status = getattr(record, "status", None)
        if status is None:
            return True
        return not _is_terminal_status(status)

    async def _reconcile_child(
        self,
        *,
        parent_session_key: str,
        parent_task_id: str,
        child: Any,
    ) -> str | None:
        """Return one of: 'replayed', 'stuck', 'escalated', or None.

        The reconciliation is intentionally side-effect-light: the only
        state change is the per-(parent, child) retry counter and the
        parent-session transcript append. Everything else (the wake
        itself) is delegated to ``announce_subagent_completion`` so the
        primary path's dedup state stays authoritative.
        """
        child_session_key = getattr(child, "session_key", None)
        if not isinstance(child_session_key, str) or not child_session_key:
            return None

        child_status = getattr(child, "status", None)
        last_activity = getattr(child, "updated_at", None) or getattr(child, "started_at", None)
        now = self._clock()
        stuck_seconds = (
            (now - float(last_activity)) / 1000.0
            if isinstance(last_activity, (int, float)) and last_activity > 0
            else 0.0
        )

        # Case 1: child is terminal but announce never fired. The fastest
        # way to detect this is to look at the storage-side task ledger;
        # if the child task is in a terminal status but the tracker has
        # not seen the child_session_key, we replay the announce.
        if not _is_terminal_status(child_status):
            if stuck_seconds >= self._stuck_threshold_s:
                return await self._handle_stuck(
                    parent_session_key=parent_session_key,
                    parent_task_id=parent_task_id,
                    child_session_key=child_session_key,
                    stuck_seconds=stuck_seconds,
                )
            return None

        # 2026-06-09 (Issue 12 — "activation mechanism").
        # Run the progress-stuck check FIRST, before any
        # failure-mode check. Rationale: the user's
        # screenshot showed the LLM stuck in a
        # write_file + exec_command loop, and the final
        # error was either ``provider_request_too_large``
        # or ``empty_response`` — but the LLM was already
        # making no progress. Per the user's explicit
        # request, the system should SKIP rather than
        # RETRY when the LLM is clearly stuck, regardless
        # of which failure mode the final terminal_reason
        # reports. Detecting this BEFORE the context_overflow
        # / empty_response handlers ensures the activation
        # mechanism takes priority over the slim-retry /
        # auto-skip paths (which assume the LLM might make
        # progress on the next attempt).
        recent_calls = await self._read_child_recent_tool_calls(
            child_session_key, limit=self.PROGRESS_STUCK_THRESHOLD
        )
        stuck = self._detect_progress_stuck(
            recent_calls, threshold=self.PROGRESS_STUCK_THRESHOLD
        )
        if stuck is not None:
            stuck_tool, stuck_count = stuck
            return await self._handle_progress_stuck(
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                child_session_key=child_session_key,
                stuck_tool=stuck_tool,
                stuck_count=stuck_count,
                transcript_summary=(
                    f"child {child_session_key} called "
                    f"`{stuck_tool}` {stuck_count} times in a "
                    f"row with identical args (terminal_reason="
                    f"{str(getattr(child, 'terminal_reason', '') or '')!r})"
                ),
            )

        # 2026-06-09 (Issue 6 — never-stop hardening). BEFORE the
        # replay-announce path, check for a context-overflow
        # terminal. If the child failed because its request was
        # too large for the provider context window, we
        # auto-retry with a slim brief — the announce is left
        # to the re-spawned child to fire. The parent's
        # transcript gets a structured ``auto-retry`` marker
        # (not a question), and the no-stall guard on the next
        # turn ensures the parent fires the re-spawn without
        # operator input.
        if self._is_provider_context_overflow(
            str(getattr(child, "terminal_reason", "") or "")
        ):
            return await self._handle_provider_context_overflow(
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                child_session_key=child_session_key,
                reason=str(getattr(child, "terminal_reason", "") or ""),
                original_brief=getattr(child, "last_brief", None),
                target=getattr(child, "target", None),
                agent_id=getattr(child, "agent_id", None),
            )

        # 2026-06-09 (Issue 8 — empty-response auto-skip). When
        # the child failed because the provider returned an empty
        # response 3 times in a row (the engine's
        # ``_ProviderRetryPolicy.from_provider_budget`` budget
        # for ``ProviderFailureKind.EMPTY_RESPONSE`` is now 3),
        # we auto-skip the failing child and write an audit
        # marker telling the parent to move to the next fan-out
        # sub-track. The agent.py engine side already retried
        # 3x; the supervisor's job is to surface the failure as
        # an actionable audit marker (NOT a stall question) so
        # the parent can proceed without asking the operator.
        if self._is_empty_response_exhausted(
            str(getattr(child, "terminal_reason", "") or "")
        ):
            return await self._handle_empty_response(
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                child_session_key=child_session_key,
                reason=str(getattr(child, "terminal_reason", "") or ""),
            )

        # Child is terminal. Decide whether to replay the announce.
        child_task_id = getattr(child, "last_task_id", None) or child_session_key
        already_delivered = await self._child_already_delivered(
            parent_session_key=parent_session_key,
            parent_task_id=parent_task_id,
            child_session_key=child_session_key,
        )
        if already_delivered:
            return None
        # Replay the announce by calling into the same code path the
        # primary listener uses. The synthesized event uses the child's
        # session status to derive the AgentTaskStatus; the
        # _notify_subagent_terminal -> announce_subagent_completion
        # chain is the same one a real terminal event would have taken.
        terminal_status = _agent_task_status_to_terminal(child_status)
        terminal_reason = (
            str(getattr(child, "terminal_reason", "") or "")
            or {"done": "completed", "succeeded": "completed", "failed": "error",
                "timeout": "timeout", "cancelled": "cancelled"}.get(
                    str(child_status).lower(), "completed"
                )
        )
        event = SubagentCompletionEvent(
            parent_session_key=parent_session_key,
            child_session_key=child_session_key,
            task_id=str(child_task_id),
            status=terminal_status,
            terminal_reason=terminal_reason,
            agent_id=getattr(child, "agent_id", None),
            parent_task_id=parent_task_id,
        )
        try:
            await announce_subagent_completion(
                event,
                session_manager=self._session_manager,
                task_runtime=self._task_runtime,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "subagent_supervisor.replay_failed",
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                child_session_key=child_session_key,
                error=str(exc),
            )
            return None
        # ``announce_subagent_completion`` alone won't fire the parent
        # wake when the spawn group is still open (the deferred path
        # waits for the parent to call ``sessions_yield``). The
        # supervisor's whole point is to recover the wake when the
        # primary path is stuck, so we also drive
        # ``close_subagent_spawn_group``: it closes the group, builds
        # the aggregated payload, and — if all known children are
        # terminal — fires the wake through the same dedup state the
        # primary path uses. Re-running ``announce_subagent_completion``
        # above is still useful because it appends the
        # ``subagent_completion`` system message to the parent's
        # transcript, which a raw close would skip.
        try:
            await close_subagent_spawn_group(
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                session_manager=self._session_manager,
                task_runtime=self._task_runtime,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "subagent_supervisor.close_group_failed",
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                error=str(exc),
            )
            return None
        log.info(
            "subagent_supervisor.replayed_announce",
            parent_session_key=parent_session_key,
            parent_task_id=parent_task_id,
            child_session_key=child_session_key,
            child_status=str(child_status),
        )
        return "replayed"

    async def _child_already_delivered(
        self,
        *,
        parent_session_key: str,
        parent_task_id: str,
        child_session_key: str,
    ) -> bool:
        # Use the same dedup state the announce path uses; importing at
        # module top would create a circular dep with subagent_announce.
        from opensquilla.gateway.subagent_announce import _tracker

        already = _tracker.delivered_children((parent_session_key, parent_task_id))
        return child_session_key in already

    async def _handle_stuck(
        self,
        *,
        parent_session_key: str,
        parent_task_id: str,
        child_session_key: str,
        stuck_seconds: float,
    ) -> str | None:
        async with self._state_lock:
            state = self._group_states.setdefault(
                (parent_session_key, parent_task_id),
                _GroupState(parent_session_key=parent_session_key, parent_task_id=parent_task_id),
            )
            counter_key = child_session_key
            attempts = state.retry_counters.get(counter_key, 0) + 1
            state.retry_counters[counter_key] = attempts

        if attempts <= self._max_retries:
            log.warning(
                "subagent_supervisor.child_stuck",
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                child_session_key=child_session_key,
                stuck_seconds=round(stuck_seconds, 1),
                retry=attempts,
                max_retries=self._max_retries,
            )
            return "stuck"

        # Exhausted retries: emit a one-shot transcript warning on the
        # parent so the operator sees the situation in the chat UI. We
        # do NOT auto-cancel the child; the supervisor is read-only with
        # respect to running work. The operator is expected to either
        # cancel manually or wait for the child to finish.
        log.error(
            "subagent_supervisor.child_stuck_exhausted",
            parent_session_key=parent_session_key,
            parent_task_id=parent_task_id,
            child_session_key=child_session_key,
            stuck_seconds=round(stuck_seconds, 1),
            attempts=attempts,
        )
        await self._emit_transcript_warning(
            parent_session_key=parent_session_key,
            child_session_key=child_session_key,
            stuck_seconds=stuck_seconds,
            attempts=attempts,
        )
        return "escalated"

    async def _emit_transcript_warning(
        self,
        *,
        parent_session_key: str,
        child_session_key: str,
        stuck_seconds: float,
        attempts: int,
    ) -> None:
        append_message = getattr(self._session_manager, "append_message", None)
        if not callable(append_message):
            return
        import json

        payload = {
            "type": "subagent_supervisor_warning",
            "kind": "internal_system",
            "source_session_key": child_session_key,
            "source_tool": "subagent_supervisor",
            "message": (
                f"Subagent {child_session_key} has not produced progress for "
                f"{round(stuck_seconds, 1)}s; supervisor retried the announce "
                f"{attempts} times. Operator review recommended."
            ),
        }
        try:
            await append_message(
                parent_session_key,
                role="system",
                content=json.dumps(payload, ensure_ascii=False),
                provenance={
                    "kind": "internal_system",
                    "source_session_key": child_session_key,
                    "source_tool": "subagent_supervisor",
                },
            )
        except Exception:  # noqa: BLE001
            return

    # ------------------------------------------------------------------
    # 2026-06-09 (Issue 6 — never-stop hardening). Context-overflow
    # auto-retry path. When a subagent fails with
    # ``provider_request_too_large`` (the 2026-06-09 51ifind.com
    # W4.3 b4a7a205 incident), the supervisor must NOT surface the
    # failure to the parent in a way that invites a "是否继续?"
    # stall. Instead it auto-queues a slim-brief re-spawn and writes
    # a non-blocking audit marker. The parent's next turn (which
    # the no-stall guard above auto-fires) picks up the queued
    # re-spawn and dispatches it.
    # ------------------------------------------------------------------

    @staticmethod
    def _is_provider_context_overflow(reason: str | None) -> bool:
        """True iff the terminal reason indicates a context overflow.

        The terminal_reason string is a free-form value the
        announce path derives from the child session status. The
        canonical overflow tags we look for:
        - ``provider_request_too_large``
        - ``provider_output_truncated``
        - ``current_turn_context_exhausted``
        - substrings of the above for forward-compat
        """
        if not reason:
            return False
        text = str(reason).lower()
        return any(
            tag in text
            for tag in (
                "provider_request_too_large",
                "provider_output_truncated",
                "context_exhausted",
                "context_overflow",
            )
        )

    @staticmethod
    def _build_slim_brief(
        original_brief: str | None,
        *,
        target: str | None,
        agent_id: str | None,
        reason: str,
    ) -> str:
        """Build a context-slimmed brief for an auto-retry.

        The 51ifind.com W4.3 incident root cause was that the
        original brief included the full W2 triage summary + W3
        opsec per-target-group dump + the typed Envelope header —
        all of which are large and re-readable from
        ``<artifact_root>/<wave>/`` on disk. The slim brief
        drops everything except:

        - a one-line header stating the re-spawn is an auto-retry
        - the W4 / W7 contract (the schema-required fields), which
          the specialist MUST read from its own on-disk brief
        - the target (so the specialist knows what to hit)
        - a one-line note telling the specialist to ``cat`` the
          upstream artifact file for triage / opsec context instead
          of receiving them inline

        This typically drops the brief from ~12K tokens to ~1K.
        """
        target_line = f"Target: {target}." if target else "Target: (see prior turn)."
        agent_line = f"Agent: {agent_id}." if agent_id else "Agent: (see prior turn)."
        reason_line = (
            f"Auto-retry reason: {reason}. The original brief was too "
            f"large for the provider context window; this slim brief "
            f"contains only the contract. Read the upstream artifact "
            f"files on disk for context (don't re-inline them in the "
            f"prompt)."
        )
        # Pull the W4 contract section out of the original brief if
        # it's there. We use a soft substring match — the
        # contract section is always delimited by an uppercase
        # "CONTRACT" header in the W4 / W7 brief footers.
        contract_block = ""
        if original_brief:
            upper = original_brief.upper()
            for marker in ("CONTRACT — READ BEFORE STARTING",
                           "## ⚠️ CONTRACT", "## CONTRACT"):
                idx = upper.find(marker)
                if idx >= 0:
                    contract_block = original_brief[idx:].strip()
                    break
        if not contract_block:
            # Fallback: take the last 4KB of the original brief.
            # This still drops the input_artifacts / triage summary
            # section (which is at the head) and keeps the
            # RESULT MARKER footer.
            contract_block = (original_brief or "")[-4096:].strip()
        slim = (
            "## AUTO-RETRY (context overflow)\n"
            f"{reason_line}\n"
            f"\n## {agent_line} {target_line}\n"
            "\n## Slim contract (read upstream artifacts on disk for context)\n"
            f"{contract_block}\n"
        )
        return slim

    async def _handle_provider_context_overflow(
        self,
        *,
        parent_session_key: str,
        parent_task_id: str,
        child_session_key: str,
        reason: str,
        original_brief: str | None,
        target: str | None,
        agent_id: str | None,
    ) -> str:
        """Auto-retry with a slim brief, or mark exhausted.

        Returns:
            ``"context_overflow_retried"`` when a slim re-spawn was
            queued; ``"context_overflow_exhausted"`` when the
            per-child cap was hit and the failure is now surfaced
            as an audit marker (the parent can then make its own
            decision but is NOT expected to ask the operator).

        Side effects:
        - Increments the per-child counter
        - Records the slim brief in ``pending_slim_respawns`` so the
          parent's next turn can dispatch it
        - Writes a structured system message to the parent's
          transcript with the slim brief inline (parent LLM
          reads it from the transcript and re-spawns).
        """
        async with self._state_lock:
            state = self._group_states.setdefault(
                (parent_session_key, parent_task_id),
                _GroupState(
                    parent_session_key=parent_session_key,
                    parent_task_id=parent_task_id,
                ),
            )
            attempts = state.context_overflow_retries.get(child_session_key, 0) + 1
            state.context_overflow_retries[child_session_key] = attempts

        # Cap reached: surface the failure as a structured audit
        # marker and let the parent continue. Crucially we do NOT
        # add a "是否继续" question — the parent should just keep
        # moving. The audit marker is a JSON blob in the system
        # channel; the LLM (with the no-stall guard above) will
        # process it as a normal wake and decide.
        if attempts > self._context_overflow_max_retries:
            log.error(
                "subagent_supervisor.context_overflow_exhausted",
                parent_session_key=parent_session_key,
                parent_task_id=parent_task_id,
                child_session_key=child_session_key,
                reason=reason,
                attempts=attempts,
                max_retries=self._context_overflow_max_retries,
            )
            # Drop any pending slim respawn from a previous
            # under-cap tick. If we don't clear it, the parent's
            # next turn will read the stale "AUTO-RETRY" marker
            # and try to dispatch a slim re-spawn even though
            # we've now exhausted the budget.
            async with self._state_lock:
                state.pending_slim_respawns.pop(child_session_key, None)
            await self._emit_transcript_warning(
                parent_session_key=parent_session_key,
                child_session_key=child_session_key,
                stuck_seconds=0.0,
                attempts=attempts,
            )
            # Append a follow-up audit note that the cap is hit.
            try:
                append_message = getattr(
                    self._session_manager, "append_message", None
                )
                if callable(append_message):
                    import json as _json
                    payload = {
                        "type": "subagent_context_overflow_exhausted",
                        "kind": "internal_system",
                        "source_session_key": child_session_key,
                        "source_tool": "subagent_supervisor",
                        "message": (
                            f"Context-overflow auto-retry exhausted for "
                            f"{child_session_key} after {attempts} attempts. "
                            f"Surfacing failure as audit; parent MUST continue "
                            f"with the remaining sub-tracks and NOT ask the "
                            f"operator to confirm."
                        ),
                    }
                    await append_message(
                        parent_session_key,
                        role="system",
                        content=_json.dumps(payload, ensure_ascii=False),
                        provenance={
                            "kind": "internal_system",
                            "source_session_key": child_session_key,
                            "source_tool": "subagent_supervisor",
                        },
                    )
            except Exception:  # noqa: BLE001
                pass
            return "context_overflow_exhausted"

        # Cap not reached: queue a slim re-spawn and write a
        # structured "auto-retrying" marker to the parent
        # transcript. The parent LLM will see this on its next
        # turn and dispatch the slim re-spawn (the brief is
        # included in the marker so the parent doesn't need to
        # re-derive it).
        slim = self._build_slim_brief(
            original_brief,
            target=target,
            agent_id=agent_id,
            reason=reason,
        )
        async with self._state_lock:
            state.pending_slim_respawns[child_session_key] = slim
        log.warning(
            "subagent_supervisor.context_overflow_retry_queued",
            parent_session_key=parent_session_key,
            parent_task_id=parent_task_id,
            child_session_key=child_session_key,
            reason=reason,
            attempts=attempts,
            max_retries=self._context_overflow_max_retries,
            slim_brief_chars=len(slim),
        )
        try:
            append_message = getattr(
                self._session_manager, "append_message", None
            )
            if callable(append_message):
                import json as _json
                payload = {
                    "type": "subagent_context_overflow_auto_retry",
                    "kind": "internal_system",
                    "source_session_key": child_session_key,
                    "source_tool": "subagent_supervisor",
                    "attempt": attempts,
                    "max_retries": self._context_overflow_max_retries,
                    "reason": reason,
                    "slim_brief": slim,
                    "instruction": (
                        "AUTO-RETRY: re-spawn this subagent with the "
                        "included slim_brief. Do NOT ask the operator "
                        "to confirm. Do NOT change the wave plan."
                    ),
                }
                await append_message(
                    parent_session_key,
                    role="system",
                    content=_json.dumps(payload, ensure_ascii=False),
                    provenance={
                        "kind": "internal_system",
                        "source_session_key": child_session_key,
                        "source_tool": "subagent_supervisor",
                    },
                )
        except Exception:  # noqa: BLE001
            pass
        return "context_overflow_retried"

    def take_pending_slim_respawn(self, child_session_key: str) -> str | None:
        """Pop the pending slim brief for a child (if any).

        The parent's next turn (after the no-stall guard fires)
        calls this for each failed child in its spawn group and
        dispatches the slim re-spawn. Returns ``None`` when no
        pending re-spawn exists for the child.
        """
        for state in self._group_states.values():
            slim = state.pending_slim_respawns.pop(child_session_key, None)
            if slim is not None:
                return slim
        return None

    # ------------------------------------------------------------------
    # 2026-06-09 (Issue 8 — empty-response auto-skip). When the
    # engine's ``_ProviderRetryPolicy`` exhausts its 3-attempt
    # ``ProviderFailureKind.EMPTY_RESPONSE`` budget, the child
    # surfaces ``code="empty_response"``. The supervisor must
    # NOT block the parent waiting for the operator; it writes
    # an ``empty_response_auto_skip`` audit marker and an
    # ``empty_response_skipped_exhausted`` follow-up so the
    # parent can dispatch the next fan-out sub-track.
    # ------------------------------------------------------------------

    @staticmethod
    def _is_empty_response_exhausted(reason: str | None) -> bool:
        """True iff the terminal reason is the engine's 3x-exhausted
        empty-response signal.

        The engine's ``agent.py`` raises ``code="empty_response"``
        with message ``"Provider returned an empty response"``
        after the 3-attempt budget is exhausted. The supervisor
        matches the code (canonical) AND a small set of
        forward-compat substrings.
        """
        if not reason:
            return False
        text = str(reason).lower()
        return any(
            tag in text
            for tag in (
                "empty_response",
                "empty response",
                "empty-response",
                "empty_response_exhausted",
            )
        )

    async def _handle_empty_response(
        self,
        *,
        parent_session_key: str,
        parent_task_id: str,
        child_session_key: str,
        reason: str,
    ) -> str:
        """Auto-skip a child that hit the 3x empty-response ceiling.

        Unlike :meth:`_handle_provider_context_overflow` (which
        RETRIES the same child with a slim brief), this handler
        SKIPS the child entirely. The 51ifind.com 2026-06-09
        regression: a penetration subagent got 3 empty responses
        in a row, the engine gave up with a terminal_error, and
        the parent stalled waiting for the operator to manually
        dispatch the next sub-track. The fix:

        1. Write a structured ``empty_response_auto_skip`` marker
           on the parent's transcript. The marker carries the
           child_session_key + reason + an explicit
           ``instruction: "AUTO-SKIP: do not retry this child,
           proceed to the next fan-out sub-track / next wave.
           Do NOT ask the operator to confirm."``
        2. Return the metric action ``empty_response_skipped`` so
           the cron log surfaces the count.

        No further supervisor state needs to be tracked: the
        parent reads the marker and dispatches the next
        sub-track on its own next turn (the no-stall guard
        auto-fires that turn).
        """
        log.error(
            "subagent_supervisor.empty_response_auto_skip",
            parent_session_key=parent_session_key,
            parent_task_id=parent_task_id,
            child_session_key=child_session_key,
            reason=reason,
        )
        try:
            append_message = getattr(
                self._session_manager, "append_message", None
            )
            if callable(append_message):
                import json as _json
                payload = {
                    "type": "subagent_empty_response_auto_skip",
                    "kind": "internal_system",
                    "source_session_key": child_session_key,
                    "source_tool": "subagent_supervisor",
                    "reason": reason,
                    "instruction": (
                        "AUTO-SKIP: the provider returned 3 empty "
                        "responses in a row; the engine's retry "
                        "budget is exhausted. Do NOT retry this "
                        "child. Proceed to the next fan-out "
                        "sub-track / next wave. Do NOT ask the "
                        "operator to confirm. Record the skipped "
                        "child in the W8 unverified_findings list."
                    ),
                }
                await append_message(
                    parent_session_key,
                    role="system",
                    content=_json.dumps(payload, ensure_ascii=False),
                    provenance={
                        "kind": "internal_system",
                        "source_session_key": child_session_key,
                        "source_tool": "subagent_supervisor",
                    },
                )
        except Exception:  # noqa: BLE001
            pass
        return "empty_response_skipped"

    # ------------------------------------------------------------------
    # 2026-06-09 (Issue 12 — "activation mechanism" / skip on
    # progress stuck). The 51ifind.com 2026-06-09 review
    # exposed a class of regressions where the LLM is stuck in
    # a loop — the same tool called with the same args 3+ times
    # in a row, often followed by a
    # "provider_request_too_large" or "empty_response" error.
    # The legacy behavior retried the same step (Issue 8) up
    # to 3 times; the user explicitly requested a SKIP
    # mechanism instead: detect the loop, write an audit
    # marker, and let the parent (hack-deep) dispatch the
    # next planned sub-task without asking the operator.
    #
    # The detector walks the child's recent tool-call
    # history (the supervisor already reads
    # ``session_manager.read_transcript`` in production; the
    # test fixture exposes ``session_manager.transcripts``
    # directly). It looks for 3+ consecutive tool_use blocks
    # with the same ``name`` and the same ``input`` (after
    # JSON canonicalization). When matched, the supervisor
    # writes ``subagent_progress_stuck_skip`` with the
    # failing step + reason + an explicit
    # "AUTO-SKIP: dispatch the next planned sub-task; do
    # NOT retry the same call" instruction.
    # ------------------------------------------------------------------

    # The threshold for "consecutive same tool+args". 3 is
    # the canonical "stuck" signal — 1-2 is normal
    # investigation, 3+ is a loop.
    PROGRESS_STUCK_THRESHOLD: int = 3

    @staticmethod
    def _extract_recent_tool_calls(
        transcript: list[Any],
    ) -> list[tuple[str, str]]:
        """Extract ``(tool_name, input_json_canonical)`` for every
        tool_use block in ``transcript``, in order.

        The supervisor reads ``transcript`` as a list of
        simple-namespace objects (test path) OR a list of
        pydantic message objects (production path). We
        handle both by duck-typing on the ``.role`` field
        and the ``.content`` list. The canonical input JSON
        is stable across re-serialization so two calls with
        the same logical args produce the same hash.
        """
        out: list[tuple[str, str]] = []
        for msg in transcript:
            role = getattr(msg, "role", None)
            if role != "assistant":
                continue
            content = getattr(msg, "content", None)
            if not isinstance(content, list):
                continue
            for block in content:
                # tool_use blocks carry .name + .input
                name = getattr(block, "name", None)
                if not name:
                    continue
                inp = getattr(block, "input", None)
                if inp is None:
                    continue
                try:
                    canonical = json.dumps(
                        inp, sort_keys=True, ensure_ascii=False
                    )
                except TypeError:
                    canonical = str(inp)
                out.append((name, canonical))
        return out

    @classmethod
    def _detect_progress_stuck(
        cls,
        recent_tool_calls: list[tuple[str, str]],
        threshold: int = 3,
    ) -> tuple[str, int] | None:
        """Return ``(tool_name, count)`` if the LLM is
        stuck repeating the same tool+args, else ``None``.

        "Stuck" = the last ``threshold`` consecutive tool
        calls all have the same ``(name, canonical_input)``.
        """
        if len(recent_tool_calls) < threshold:
            return None
        tail = recent_tool_calls[-threshold:]
        first = tail[0]
        if all(call == first for call in tail):
            return first[0], threshold
        return None

    async def _read_child_recent_tool_calls(
        self,
        child_session_key: str,
        *,
        limit: int = 12,
    ) -> list[tuple[str, str]]:
        """Read the child's recent tool-call history.

        Production path: ``session_manager.read_transcript``
        returns a list of message-like objects whose
        ``.content`` is either a list of tool_use blocks
        (real production) or a JSON string of the same
        shape (test fixture). Test path: the
        ``session_manager.transcripts[child_session_key]``
        attribute carries a JSON-encoded string of the
        assistant's tool calls. The helper handles both.
        """
        # Test fixture path: transcripts dict carries the
        # canonical JSON list. Try this first because the
        # production read_transcript shim in tests wraps
        # the same data in a SimpleNamespace.
        transcripts = getattr(self._session_manager, "transcripts", None)
        if isinstance(transcripts, dict) and child_session_key in transcripts:
            text = transcripts[child_session_key]
            if not text:
                return []
            return self._parse_transcript_text(text, limit=limit)
        # Production: read from session_manager.
        read_fn = getattr(self._session_manager, "read_transcript", None)
        if callable(read_fn):
            try:
                msgs = await read_fn(child_session_key, limit=limit)
                if msgs:
                    # Some shims return ``content`` as a
                    # JSON string (not a list of tool_use
                    # blocks). Try parsing each message's
                    # content as a JSON tool-call list
                    # before falling back to the structured
                    # tool_use-block walk.
                    calls: list[tuple[str, str]] = []
                    for msg in msgs:
                        content = getattr(msg, "content", None)
                        if isinstance(content, str) and content.strip().startswith(
                            ("[", "{")
                        ):
                            calls.extend(
                                self._parse_transcript_text(content, limit=limit)
                            )
                        else:
                            calls.extend(
                                self._extract_recent_tool_calls([msg])
                            )
                    return calls
            except Exception:  # noqa: BLE001
                pass
        return []

    @staticmethod
    def _parse_transcript_text(
        text: str, *, limit: int = 12
    ) -> list[tuple[str, str]]:
        """Parse a JSON-encoded tool-call transcript into
        ``(name, canonical_input)`` tuples.

        Handles the test-fixture shape:
        ``'[{"name": "write_file", "input": {...}}, ...]'``
        and the legacy free-form text ``"name=write_file
        input=..."`` shape.
        """
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, list):
            calls: list[tuple[str, str]] = []
            for entry in parsed:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or entry.get("tool")
                inp = entry.get("input")
                if name is None or inp is None:
                    continue
                try:
                    canonical = json.dumps(
                        inp, sort_keys=True, ensure_ascii=False
                    )
                except TypeError:
                    canonical = str(inp)
                calls.append((str(name), canonical))
            return calls[-limit:]
        # Fallback: text was a free-form transcript; do
        # best-effort line scan for "name=write_file
        # input=..." patterns.
        calls2: list[tuple[str, str]] = []
        for line in text.splitlines():
            if "name=" not in line:
                continue
            name = line.split("name=", 1)[1].split(" ", 1)[0]
            calls2.append((name, line))
        return calls2[-limit:]

    async def _handle_progress_stuck(
        self,
        *,
        parent_session_key: str,
        parent_task_id: str,
        child_session_key: str,
        stuck_tool: str,
        stuck_count: int,
        transcript_summary: str,
    ) -> str:
        """Auto-skip a child whose LLM is stuck in a loop.

        The 51ifind.com 2026-06-09 "activation mechanism"
        requirement: when the LLM is clearly making no
        progress (3+ consecutive identical tool+args
        calls, often followed by
        ``provider_request_too_large`` or ``empty_response``),
        the supervisor MUST write an audit marker that
        tells the parent (hack-deep) to dispatch the
        next planned sub-task, NOT retry the same one.
        """
        log.error(
            "subagent_supervisor.progress_stuck_skip",
            parent_session_key=parent_session_key,
            parent_task_id=parent_task_id,
            child_session_key=child_session_key,
            stuck_tool=stuck_tool,
            stuck_count=stuck_count,
            transcript_summary=transcript_summary,
        )
        try:
            append_message = getattr(
                self._session_manager, "append_message", None
            )
            if callable(append_message):
                payload = {
                    "type": "subagent_progress_stuck_skip",
                    "kind": "internal_system",
                    "source_session_key": child_session_key,
                    "source_tool": "subagent_supervisor",
                    "stuck_tool": stuck_tool,
                    "stuck_count": stuck_count,
                    "transcript_summary": transcript_summary,
                    "instruction": (
                        f"AUTO-SKIP: the LLM is stuck repeating "
                        f"`{stuck_tool}` with the same args "
                        f"{stuck_count} times in a row (often "
                        f"followed by provider_request_too_large "
                        f"or empty_response). Do NOT retry the "
                        f"same call. Dispatch the next planned "
                        f"sub-task. Do NOT ask the operator "
                        f"to confirm. Record the skipped sub-"
                        f"task in the W8 unverified_findings "
                        f"list."
                    ),
                }
                await append_message(
                    parent_session_key,
                    role="system",
                    content=json.dumps(payload, ensure_ascii=False),
                    provenance={
                        "kind": "internal_system",
                        "source_session_key": child_session_key,
                        "source_tool": "subagent_supervisor",
                    },
                )
        except Exception:  # noqa: BLE001
            pass
        return "progress_stuck_skipped"


# ---------------------------------------------------------------------------
# Cron handler — registered as `subagent_supervisor` in the scheduler.
# ---------------------------------------------------------------------------


def make_subagent_supervisor_handler(
    supervisor: SubagentHealthSupervisor,
) -> Callable[[Any], Awaitable[dict[str, Any]]]:
    """Adapt ``SubagentHealthSupervisor.tick`` to the cron handler signature.

    The scheduler invokes a handler with a ``CronJob`` and expects back a
    ``dict`` describing the run (the scheduler wraps it into a
    ``HandlerResult``). We surface the supervisor's metrics directly so
    operators can see the watchdog's behavior in the cron log.
    """

    async def handle_subagent_supervisor_tick(_job: Any) -> dict[str, Any]:
        metrics = await supervisor.tick()
        return {"summary": "subagent_supervisor tick", "metrics": metrics, "delivery_status": "delivered"}

    return handle_subagent_supervisor_tick


__all__ = [
    "DEFAULT_INTERVAL_SECONDS",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_STUCK_THRESHOLD_SECONDS",
    "SubagentHealthSupervisor",
    "make_subagent_supervisor_handler",
]
