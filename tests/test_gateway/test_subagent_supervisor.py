"""Unit tests for ``SubagentHealthSupervisor``.

These exercise the supervisor's read-only reconcile path and the
``forget_parent_task`` cleanup hook. They do not boot the full
gateway; the supervisor is constructed with in-memory fakes for the
session manager and task runtime.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from opensquilla.gateway.subagent_announce import (
    _tracker,
    announce_subagent_completion,
)
from opensquilla.gateway.subagent_supervisor import (
    DEFAULT_STUCK_THRESHOLD_SECONDS,
    SubagentHealthSupervisor,
    make_subagent_supervisor_handler,
)
from opensquilla.gateway.task_runtime import SubagentCompletionEvent
from opensquilla.session.models import AgentTaskStatus


PARENT = "agent:hack-deep:webchat:parent"
PARENT_TASK = "task-parent"
CHILD_W0 = "agent:worker:subagent:w0"


class _SessionRow:
    def __init__(self, session_key, *, status, agent_id="worker", **extra):
        self.session_key = session_key
        self.spawned_by = extra.pop("spawned_by", PARENT)
        self.parent_session_key = extra.pop("parent_session_key", PARENT)
        self.agent_id = agent_id
        self.status = status
        self.origin = {
            "kind": "subagent",
            "parent_task_id": PARENT_TASK,
            **extra,
        }
        self.updated_at = extra.pop("updated_at", 1_000)
        self.started_at = extra.pop("started_at", 900)
        self.last_task_id = extra.pop("last_task_id", f"task-{session_key[-8:]}")
        self.terminal_reason = extra.pop("terminal_reason", "completed")
        for k, v in extra.items():
            setattr(self, k, v)


class _Storage:
    def __init__(self, parent_status: str = "running", parent_task_id: str = PARENT_TASK):
        self.parent_status = parent_status
        self.parent_task_id = parent_task_id

    async def get_agent_task(self, task_id: str):
        if task_id == self.parent_task_id:
            return SimpleNamespace(status=self.parent_status)
        return None


class _SessionManager:
    def __init__(self, rows, *, parent_status: str = "running"):
        self.rows = list(rows)
        self._storage = _Storage(parent_status=parent_status)
        self.messages: list[tuple[str, str, str]] = []
        self.transcripts: dict[str, str] = {}

    async def list_sessions(self, *, limit: int = 200, offset: int = 0):
        return self.rows[offset : offset + limit]

    async def get_session(self, key):
        return SimpleNamespace(session_key=key, last_channel=None, last_to=None)

    async def read_transcript(self, session_key: str, limit: int = 50):
        text = self.transcripts.get(session_key, "")
        return [SimpleNamespace(role="assistant", content=text)] if text else []

    async def append_message(self, key, *, role: str, content: str, provenance=None):
        self.messages.append((key, role, content))

    async def finish(self, key, *, status):
        for row in self.rows:
            if row.session_key == key:
                row.status = str(status)


class _TaskRuntime:
    def __init__(self):
        self.sent: list[tuple[str, str, dict | None]] = []

    async def send(self, session_key, message, provenance=None):
        self.sent.append((session_key, message, provenance))
        return SimpleNamespace(task_id=f"wake-{len(self.sent)}")


@pytest.fixture(autouse=True)
def _clean_tracker():
    _tracker.evict(PARENT)
    yield
    _tracker.evict(PARENT)


def _make_supervisor(
    rows,
    *,
    parent_status: str = "running",
    stuck_threshold_seconds: float = DEFAULT_STUCK_THRESHOLD_SECONDS,
    max_retries: int = 3,
) -> SubagentHealthSupervisor:
    return SubagentHealthSupervisor(
        session_manager=_SessionManager(rows, parent_status=parent_status),
        task_runtime=_TaskRuntime(),
        stuck_threshold_seconds=stuck_threshold_seconds,
        max_retries=max_retries,
    )


@pytest.mark.asyncio
async def test_tick_replays_announce_for_unannounced_terminal_child() -> None:
    """If a child is terminal but the tracker has no record of the
    wake, the supervisor must replay the announce through the primary
    code path so dedup state fires the wake for the new child.
    """
    manager_rows = [
        _SessionRow(
            CHILD_W0,
            status="done",
            last_task_id="task-w0",
            transcripts=None,  # populated below
        ),
    ]
    supervisor = _make_supervisor(manager_rows)
    # Seed the transcript so the announce can read a child result.
    supervisor._session_manager.transcripts[CHILD_W0] = "ROE result"

    metrics = await supervisor.tick()
    assert metrics["groups"] == 1
    # Replay counted: one announce was emitted, no stuck children, no
    # escalation.
    assert metrics["replayed"] == 1
    assert metrics["stuck"] == 0
    assert metrics["escalated"] == 0

    # The supervisor's replayed announce should have driven the
    # primary ``announce_subagent_completion`` path, which in turn
    # enqueued a wake via the bound task runtime.
    runtime = supervisor._task_runtime
    assert isinstance(runtime, _TaskRuntime)
    assert len(runtime.sent) == 1
    sent_session, sent_message, _provenance = runtime.sent[0]
    assert sent_session == PARENT
    assert "[SUBAGENT_COMPLETION_GROUP]" in sent_message
    assert CHILD_W0 in sent_message


@pytest.mark.asyncio
async def test_tick_skips_already_delivered_child() -> None:
    """If the tracker has already seen the child_session_key (the
    primary path's wake actually fired), the supervisor must not
    double-fire. We model that by manually closing the spawn group
    and running the primary path so the tracker records the child as
    delivered.
    """
    from opensquilla.gateway.subagent_announce import close_subagent_spawn_group

    supervisor = _make_supervisor(
        [_SessionRow(CHILD_W0, status="running", last_task_id="task-w0")]
    )
    supervisor._session_manager.transcripts[CHILD_W0] = "ROE result"

    # Mark the child terminal in storage, close the group (this fires
    # the wake and records the child as delivered), then verify the
    # supervisor's tick does NOT replay.
    supervisor._session_manager.rows[0].status = "done"
    await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=supervisor._session_manager,
        task_runtime=supervisor._task_runtime,
    )
    primary_wake_count = len(supervisor._task_runtime.sent)
    assert primary_wake_count == 1, "close should have fired the initial wake"

    metrics = await supervisor.tick()
    assert metrics["replayed"] == 0, (
        "supervisor must not replay a wake for a child the tracker "
        "already records as delivered"
    )
    assert len(supervisor._task_runtime.sent) == primary_wake_count


@pytest.mark.asyncio
async def test_tick_drops_groups_with_terminal_parent() -> None:
    """When the parent task is already terminal, the supervisor must
    not waste a tick iterating its (closed) spawn group. A closed
    parent's terminal phase already fired ``forget_parent_task`` via
    the lifecycle listener in production, but the supervisor's own
    ``_iter_active_groups`` also short-circuits at the storage level
    for safety.
    """
    supervisor = _make_supervisor(
        [_SessionRow(CHILD_W0, status="done", last_task_id="task-w0")],
        parent_status="succeeded",
    )
    metrics = await supervisor.tick()
    assert metrics["groups"] == 0
    assert metrics["replayed"] == 0


@pytest.mark.asyncio
async def test_forget_parent_task_clears_per_group_state() -> None:
    """After ``forget_parent_task`` runs, future ticks must skip the
    group's children even if the parent is still open (the lifecycle
    listener only fires on terminal, but the supervisor should be
    safe to call directly from tests / admin tools).
    """
    supervisor = _make_supervisor(
        [_SessionRow(CHILD_W0, status="done", last_task_id="task-w0")]
    )
    supervisor._session_manager.transcripts[CHILD_W0] = "ROE result"
    # Pretend the supervisor recorded a retry counter for this group.
    supervisor._group_states[(PARENT, PARENT_TASK)] = SimpleNamespace(
        parent_session_key=PARENT,
        parent_task_id=PARENT_TASK,
        retry_counters={CHILD_W0: 2},
        last_stuck_warning_at={},
    )

    await supervisor.forget_parent_task(PARENT, PARENT_TASK)
    assert (PARENT, PARENT_TASK) not in supervisor._group_states

    metrics = await supervisor.tick()
    # After forget_parent_task, the group's state is gone; a new tick
    # against the same row re-iterates and replays the announce.
    assert metrics["replayed"] == 1


@pytest.mark.asyncio
async def test_cron_handler_returns_metrics_payload() -> None:
    """The cron handler adapter must return a dict the scheduler can
    wrap into a HandlerResult; the metrics dict flows through as-is
    so operators can grep the cron log for ``replayed`` / ``stuck``.
    """
    supervisor = _make_supervisor([])
    handler = make_subagent_supervisor_handler(supervisor)
    result = await handler(SimpleNamespace(id="job-1"))
    assert result["summary"] == "subagent_supervisor tick"
    assert result["delivery_status"] == "delivered"
    assert result["metrics"] == {
        "groups": 0,
        "replayed": 0,
        "stuck": 0,
        "escalated": 0,
        # 2026-06-09 (Issue 6): context-overflow retry counters
        # added alongside the existing replay / stuck / escalated
        # actions. Tests covering the new path live further down
        # in this file.
        "context_overflow_retried": 0,
        "context_overflow_exhausted": 0,
        # 2026-06-09 (Issue 8): empty-response auto-skip counter.
        "empty_response_skipped": 0,
        # 2026-06-09 (Issue 12): progress-stuck auto-skip
        # counter (LLM repeating same tool+args 3+ times).
        "progress_stuck_skipped": 0,
    }


@pytest.mark.asyncio
async def test_close_disables_further_ticks() -> None:
    """After ``close`` the tick returns zeros without iterating, so a
    shutdown sequence can rely on the supervisor being quiescent.
    """
    supervisor = _make_supervisor(
        [_SessionRow(CHILD_W0, status="done", last_task_id="task-w0")]
    )
    supervisor._session_manager.transcripts[CHILD_W0] = "ignored"
    await supervisor.close()
    metrics = await supervisor.tick()
    assert metrics == {
        "groups": 0, "replayed": 0, "stuck": 0, "escalated": 0,
        "context_overflow_retried": 0, "context_overflow_exhausted": 0,
        "empty_response_skipped": 0,
        "progress_stuck_skipped": 0,
    }


# ===========================================================================
# 2026-06-09 (Issue 6 — never-stop hardening). Context-overflow
# auto-retry. When a subagent fails with ``provider_request_too_large``,
# the supervisor must NOT surface the failure to the parent in a
# way that invites a "是否继续?" stall. Instead it auto-queues a
# slim-brief re-spawn and writes a structured audit marker.
# ===========================================================================


class _SlimSessionRow(_SessionRow):
    """Session row that carries the original brief + target for the
    slim-brief builder to consume.
    """

    def __init__(
        self,
        session_key,
        *,
        target: str,
        brief: str,
        terminal_reason: str = "provider_request_too_large",
        status: str = "failed",
        agent_id: str = "penetration",
        **extra,
    ):
        super().__init__(
            session_key,
            status=status,
            terminal_reason=terminal_reason,
            agent_id=agent_id,
            **extra,
        )
        self.last_brief = brief
        self.target = target


def test_is_provider_context_overflow_recognises_known_tags() -> None:
    """The detector should match every canonical overflow tag.
    Adding a new tag requires updating the detector; this test
    pins the current set.
    """
    assert (
        SubagentHealthSupervisor._is_provider_context_overflow(
            "provider_request_too_large"
        )
        is True
    )
    assert (
        SubagentHealthSupervisor._is_provider_context_overflow(
            "provider_output_truncated"
        )
        is True
    )
    assert (
        SubagentHealthSupervisor._is_provider_context_overflow(
            "current_turn_context_exhausted"
        )
        is True
    )
    assert (
        SubagentHealthSupervisor._is_provider_context_overflow("completed")
        is False
    )
    assert (
        SubagentHealthSupervisor._is_provider_context_overflow("error")
        is False
    )
    assert (
        SubagentHealthSupervisor._is_provider_context_overflow(None) is False
    )


def test_build_slim_brief_drops_upstream_summary_keeps_contract() -> None:
    """The slim brief must drop the upstream input_artifacts /
    triage summary section (the part that bloats the prompt) and
    keep the W4 / W7 contract section (the part the specialist
    must read).
    """
    # Build a realistic large original brief (~6KB) with the
    # upstream sections that bloated the 51ifind.com W4.3 brief.
    upstream_block = (
        "## Upstream triage (W2, top-N)\n"
        + "".join(
            f"{i}. V{i:03d} — Finding {i} — CVSS {8.0 + i * 0.1:.1f} — "
            f"vector web — long description {'x' * 200}\n"
            for i in range(1, 11)
        )
        + "\n## OpSec strategy (W3, per-target-group)\n"
        + "".join(
            f"- group_id=g{i} strategy=low-noise-i{i} stop_signal=429 "
            f"description={'y' * 200}\n"
            for i in range(1, 6)
        )
        + "\n## Upstream artifacts (per-step archive)\n"
        + "".join(
            f"- W{i} artifact at /long/path/{'z' * 100}.json\n"
            for i in range(1, 6)
        )
    )
    contract_block = (
        "## ⚠️ CONTRACT — READ BEFORE STARTING (2026-06-07)\n"
        "You are a senior penetration tester. You produce "
        "``pentest-v1`` evidence.\n"
        "**MUST carry**: entry_id, title, status, confidence, "
        "classification, CVSS, auth_context, request, response, "
        "reproduce_steps, impact, chain, tooling, cleanup, ROE, "
        "origin.\n"
        "\n## 🛑 FINAL CONTRACT — RESULT MARKER FOOTER (MANDATORY)\n"
        "Your final assistant message MUST end with EXACTLY one line:\n"
        "schema: pentest-v1 | phase: <phase> | wave: <N/M> | deps: <csv>\n"
    )
    original = (
        "Penetration sub-track W4.3 of 1 sub-tracks. "
        "Target: 51ifind.com:443.\n"
        f"\n{upstream_block}\n{contract_block}"
    )
    slim = SubagentHealthSupervisor._build_slim_brief(
        original,
        target="51ifind.com:443",
        agent_id="penetration",
        reason="provider_request_too_large",
    )
    # Slim brief has the AUTO-RETRY header
    assert "AUTO-RETRY" in slim
    # Slim brief includes the agent + target
    assert "penetration" in slim
    assert "51ifind.com:443" in slim
    # Slim brief KEEPS the contract section
    assert "CONTRACT" in slim
    assert "RESULT MARKER" in slim or "RESULT" in slim
    # Slim brief DROPS the upstream triage section
    assert "Upstream triage" not in slim
    assert "V001 — Auth bypass" not in slim
    assert "Upstream artifacts" not in slim
    # Slim brief is meaningfully shorter than the original
    # (the upstream block alone is ~5KB)
    assert len(slim) < len(original) // 2


def test_build_slim_brief_falls_back_when_no_contract_marker() -> None:
    """When the original brief has no CONTRACT marker (legacy
    artifact), the slim brief falls back to the last 4KB.
    """
    original = "Some short brief with no contract marker.\n" * 50
    slim = SubagentHealthSupervisor._build_slim_brief(
        original,
        target="target",
        agent_id="agent",
        reason="provider_request_too_large",
    )
    assert "AUTO-RETRY" in slim
    assert "Some short brief" in slim


@pytest.mark.asyncio
async def test_context_overflow_triggers_slim_retry_under_cap() -> None:
    """A child that failed with ``provider_request_too_large``
    must trigger a slim re-spawn (not a stall-prompt leak to
    the parent) when the per-child cap is not yet hit.
    """
    rows = [
        _SlimSessionRow(
            CHILD_W0,
            status="failed",
            terminal_reason="provider_request_too_large",
            target="51ifind.com:443",
            brief=(
                "Penetration sub-track W4.3 of 1.\n"
                "## Upstream triage (W2, top-N)\n"
                "1. V001 — Auth bypass\n"
                "## ⚠️ CONTRACT — READ BEFORE STARTING\n"
                "You are a senior penetration tester.\n"
                "schema: pentest-v1 | phase: exploitation | wave: 4/9 | deps: empty\n"
            ),
        ),
    ]
    supervisor = _make_supervisor(rows)
    metrics = await supervisor.tick()
    # The supervisor counted the context-overflow retry as a
    # retried action, not as a stuck / escalated / replayed.
    assert metrics["context_overflow_retried"] == 1
    assert metrics["replayed"] == 0
    assert metrics["stuck"] == 0
    assert metrics["escalated"] == 0
    # The supervisor wrote a structured ``subagent_context_overflow_auto_retry``
    # marker to the parent's transcript — that's how the parent's
    # next turn (auto-fired by the no-stall guard) learns to dispatch
    # the slim re-spawn.
    messages = supervisor._session_manager.messages
    assert any(
        "subagent_context_overflow_auto_retry" in (content or "")
        for _key, _role, content in messages
    )
    # The marker carries the slim brief and the explicit
    # "Do NOT ask the operator to confirm" instruction.
    marker = next(
        content
        for _key, _role, content in messages
        if "subagent_context_overflow_auto_retry" in (content or "")
    )
    assert "Do NOT ask the operator" in marker
    assert "AUTO-RETRY" in marker
    # The slim brief was stored in pending_slim_respawns so the
    # parent's next turn can pop it via take_pending_slim_respawn.
    pending = supervisor.take_pending_slim_respawn(CHILD_W0)
    assert pending is not None
    assert "AUTO-RETRY" in pending


@pytest.mark.asyncio
async def test_context_overflow_surfaces_audit_when_cap_exhausted() -> None:
    """After the per-child cap is hit, the supervisor must surface
    the failure as an audit marker (NOT a stall question) and
    let the parent continue.
    """
    rows = [
        _SlimSessionRow(
            CHILD_W0,
            status="failed",
            terminal_reason="provider_request_too_large",
            target="51ifind.com:443",
            brief="## ⚠️ CONTRACT — READ BEFORE STARTING\n" + ("x" * 5000),
        ),
    ]
    supervisor = _make_supervisor(rows, max_retries=3)
    # The supervisor has a fresh _group_states populated lazily on
    # the FIRST reconcile call. We trigger that by running tick()
    # once to enroll the group, then bump the per-child counter
    # directly on the resulting state.
    await supervisor.tick()  # first tick: enrolls the group, increments counter to 1
    state = supervisor._group_states[(PARENT, PARENT_TASK)]
    # Bump to the cap. The next reconcile will see
    # attempts > max_retries and emit the audit marker.
    state.context_overflow_retries[CHILD_W0] = supervisor._context_overflow_max_retries
    metrics = await supervisor.tick()
    # The action is "exhausted" — the failure is now surfaced as
    # an audit marker; the parent should keep moving.
    assert metrics["context_overflow_exhausted"] == 1
    assert metrics["context_overflow_retried"] == 0
    # The audit marker was written.
    messages = supervisor._session_manager.messages
    assert any(
        "subagent_context_overflow_exhausted" in (content or "")
        for _key, _role, content in messages
    )
    # No stall-style question was written — the audit marker
    # explicitly tells the parent to keep moving.
    exhausted_marker = next(
        content
        for _key, _role, content in messages
        if "subagent_context_overflow_exhausted" in (content or "")
    )
    assert "MUST continue" in exhausted_marker
    # No pending slim re-spawn was queued.
    assert supervisor.take_pending_slim_respawn(CHILD_W0) is None


def test_take_pending_slim_respawn_returns_none_when_no_pending() -> None:
    """The pop helper returns None when no slim re-spawn is queued.
    """
    # Pass an explicit clock so the supervisor's __init__ doesn't
    # call ``asyncio.get_event_loop()`` (deprecated on Python 3.12
    # when no event loop is running).
    supervisor = SubagentHealthSupervisor(
        session_manager=_SessionManager([]),
        task_runtime=_TaskRuntime(),
        clock=lambda: 0.0,
    )
    assert supervisor.take_pending_slim_respawn("no-such-child") is None


# ===========================================================================
# 2026-06-09 (Issue 8 — empty-response auto-skip). When the engine
# exhausts its 3x ``ProviderFailureKind.EMPTY_RESPONSE`` budget, the
# child surfaces ``code="empty_response"``. The supervisor must
# auto-skip the failing child (NOT a stall question) so the parent
# can dispatch the next fan-out sub-track.
# ===========================================================================


def test_is_empty_response_exhausted_recognises_known_tags() -> None:
    """The detector should match every canonical empty-response tag
    the engine's terminal_error path produces. Adding a new tag
    requires updating the detector; this test pins the current set.
    """
    # The engine's ``code="empty_response"`` lowercased terminal_reason.
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted(
            "empty_response"
        )
        is True
    )
    # Substring matches (forward-compat: provider error messages
    # that mention "empty response").
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted(
            "Provider returned an empty response"
        )
        is True
    )
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted(
            "empty-response"
        )
        is True
    )
    # Non-empty-response failure modes must NOT match.
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted("completed")
        is False
    )
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted("error")
        is False
    )
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted("timeout")
        is False
    )
    # Empty / None safe.
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted(None) is False
    )
    assert (
        SubagentHealthSupervisor._is_empty_response_exhausted("") is False
    )


@pytest.mark.asyncio
async def test_empty_response_after_3_fails_triggers_auto_skip() -> None:
    """The 51ifind.com 2026-06-09 regression: a penetration subagent
    got 3 empty responses in a row, the engine's
    ``_ProviderRetryPolicy.EMPTY_RESPONSE`` budget (now 3) was
    exhausted, and the parent stalled waiting for the operator to
    manually dispatch the next sub-track. The supervisor must
    auto-skip the failing child and write a structured
    ``empty_response_auto_skip`` marker so the parent (with the
    no-stall guard) auto-fires the next fan-out sub-track.
    """
    rows = [
        _SessionRow(
            CHILD_W0,
            status="failed",
            terminal_reason="empty_response",
            last_task_id="task-w0",
        ),
    ]
    supervisor = _make_supervisor(rows)
    metrics = await supervisor.tick()
    # The supervisor counted the auto-skip as a dedicated action.
    assert metrics["empty_response_skipped"] == 1
    assert metrics["replayed"] == 0
    assert metrics["stuck"] == 0
    assert metrics["escalated"] == 0
    assert metrics["context_overflow_retried"] == 0
    assert metrics["context_overflow_exhausted"] == 0
    # The supervisor wrote a structured marker to the parent's
    # transcript — that's how the parent's next turn (auto-fired
    # by the no-stall guard) learns to dispatch the next
    # sub-track.
    messages = supervisor._session_manager.messages
    assert any(
        "subagent_empty_response_auto_skip" in (content or "")
        for _key, _role, content in messages
    )
    # The marker carries the explicit "Do NOT retry this child,
    # proceed to the next sub-track" instruction.
    marker = next(
        content
        for _key, _role, content in messages
        if "subagent_empty_response_auto_skip" in (content or "")
    )
    assert "AUTO-SKIP" in marker
    assert "Do NOT retry" in marker
    assert "Do NOT ask the operator" in marker


@pytest.mark.asyncio
async def test_empty_response_auto_skip_does_not_queue_slim_respawn() -> None:
    """An empty-response auto-skip is fundamentally different from
    a context-overflow auto-retry: the child is SKIPPED, not
    re-spawned. The slim-respawn queue must remain empty so the
    parent's next turn does NOT try to re-dispatch the failed
    child.
    """
    rows = [
        _SessionRow(
            CHILD_W0,
            status="failed",
            terminal_reason="empty_response",
            last_task_id="task-w0",
        ),
    ]
    supervisor = _make_supervisor(rows)
    await supervisor.tick()
    # No slim re-spawn was queued.
    assert supervisor.take_pending_slim_respawn(CHILD_W0) is None


@pytest.mark.asyncio
async def test_empty_response_substring_in_terminal_reason_triggers_skip() -> None:
    """The engine's ``code="empty_response"`` plus message
    "Provider returned an empty response" is one common shape.
    Another shape is ``terminal_reason="empty_response_exhausted"``
    (the engine's own 3x budget tag). Both must trigger the
    auto-skip path.
    """
    for reason in (
        "empty_response",
        "empty_response_exhausted",
        "Provider returned an empty response",
        "empty-response",
    ):
        rows = [
            _SessionRow(
                CHILD_W0,
                status="failed",
                terminal_reason=reason,
                last_task_id="task-w0",
            ),
        ]
        supervisor = _make_supervisor(rows)
        metrics = await supervisor.tick()
        assert metrics["empty_response_skipped"] == 1, (
            f"reason={reason!r} should trigger empty_response_skipped"
        )


@pytest.mark.asyncio
async def test_non_empty_response_failures_do_not_trigger_auto_skip() -> None:
    """The auto-skip is empty-response-specific. Other failure
    modes (error, timeout, completed) must NOT take the
    empty-response path; they fall through to the existing
    replay-announce or stuck handler.
    """
    rows = [
        _SessionRow(
            CHILD_W0,
            status="failed",
            terminal_reason="error",
            last_task_id="task-w0",
        ),
    ]
    supervisor = _make_supervisor(rows)
    metrics = await supervisor.tick()
    # The empty-response counter is 0; the failure took a
    # different path (replay / stuck / etc.).
    assert metrics["empty_response_skipped"] == 0


def test_empty_response_retry_budget_is_three() -> None:
    """Pin the engine's ``EMPTY_RESPONSE`` retry budget at 3 (the
    51ifind.com Issue 8 contract). Reducing it back to 1 would
    regress to the original stall; raising it past 3 risks
    wasting budget on truly broken models. The 3-attempt
    budget is the sweet spot.
    """
    from opensquilla.engine.agent import _ProviderRetryPolicy
    from opensquilla.engine.fallback import ProviderFailureKind

    policy = _ProviderRetryPolicy.from_provider_budget(max_provider_retries=3)
    assert (
        policy.provider_failure_budgets[ProviderFailureKind.EMPTY_RESPONSE]
        == 3
    )
    # And the policy's can_retry_provider_failure returns True
    # for the first 3 attempts and False on the 4th.
    for attempt in range(3):
        assert (
            policy.can_retry_provider_failure(
                ProviderFailureKind.EMPTY_RESPONSE,
                post_tool_turn=True,
                provider_retry_attempt=attempt,
            )
            is True
        ), f"attempt {attempt} should still allow retry"
    assert (
        policy.can_retry_provider_failure(
            ProviderFailureKind.EMPTY_RESPONSE,
            post_tool_turn=True,
            provider_retry_attempt=3,
        )
        is False
    )


# ===========================================================================
# 2026-06-09 (Issue 12 — "activation mechanism" / progress-stuck
# skip). The user explicitly requested: when the LLM is stuck
# repeating the same tool+args 3+ times, the system must
# SKIP rather than retry. The detector walks the child's
# recent tool-call history, hashes the (tool_name, input)
# pair, and triggers the skip when the last N consecutive
# calls are identical. Tests cover the detector + the
# audit marker.
# ===========================================================================


class TestProgressStuckDetector:
    """``_detect_progress_stuck`` + ``_handle_progress_stuck``
    (Issue 12).
    """

    def test_detect_three_consecutive_same_tool_fires(self) -> None:
        """3 consecutive write_file with the same args is
        the canonical 'stuck' signal. Detector returns
        ``(tool_name, count)``.
        """
        recent = [
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
        ]
        out = SubagentHealthSupervisor._detect_progress_stuck(
            recent, threshold=3
        )
        assert out == ("write_file", 3)

    def test_detect_two_same_then_different_does_not_fire(self) -> None:
        """The LLM tries the same thing twice, then varies
        the args. Not a stuck pattern.
        """
        recent = [
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("write_file", '{"path":"/tmp/y","content":"a"}'),
        ]
        assert SubagentHealthSupervisor._detect_progress_stuck(
            recent, threshold=3
        ) is None

    def test_detect_too_few_calls_does_not_fire(self) -> None:
        """Fewer than 3 calls — not enough signal to call
        it stuck.
        """
        recent = [
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
        ]
        assert SubagentHealthSupervisor._detect_progress_stuck(
            recent, threshold=3
        ) is None

    def test_detect_threshold_overridable(self) -> None:
        """An operator can set the threshold to 2 (more
        aggressive) or 5 (more conservative) for tighter /
        looser loop detection.
        """
        recent = [
            ("curl", "x"),
            ("curl", "x"),
        ]
        # threshold=2 → fires (2 consecutive == stuck)
        assert SubagentHealthSupervisor._detect_progress_stuck(
            recent, threshold=2
        ) == ("curl", 2)
        # threshold=3 → not stuck (only 2 consecutive)
        assert SubagentHealthSupervisor._detect_progress_stuck(
            recent, threshold=3
        ) is None

    def test_detect_only_considers_tail(self) -> None:
        """The detector looks at the LAST ``threshold`` calls,
        not the entire history. An early loop doesn't count
        if the recent calls have varied.
        """
        recent = [
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("write_file", '{"path":"/tmp/x","content":"a"}'),
            ("curl", "y"),  # varied
            ("curl", "y"),
            ("curl", "y"),
        ]
        # The last 3 are all curl → fired.
        assert SubagentHealthSupervisor._detect_progress_stuck(
            recent, threshold=3
        ) == ("curl", 3)

    def test_extract_recent_tool_calls_normalizes_inputs(self) -> None:
        """``_extract_recent_tool_calls`` canonicalizes the
        ``input`` payload via ``json.dumps(sort_keys=True)``
        so two calls with the same logical args but
        different key order produce the same signature.
        """
        from types import SimpleNamespace

        msgs = [
            SimpleNamespace(
                role="assistant",
                content=[
                    SimpleNamespace(
                        name="write_file",
                        input={"path": "/tmp/x", "content": "a"},
                    ),
                ],
            ),
            SimpleNamespace(
                role="assistant",
                content=[
                    SimpleNamespace(
                        name="write_file",
                        input={"content": "a", "path": "/tmp/x"},
                    ),
                ],
            ),
        ]
        calls = SubagentHealthSupervisor._extract_recent_tool_calls(msgs)
        assert len(calls) == 2
        # Same logical args → same canonical signature.
        assert calls[0] == calls[1]
        assert calls[0] == (
            "write_file",
            '{"content": "a", "path": "/tmp/x"}',
        )

    def test_extract_recent_tool_calls_skips_non_assistant(self) -> None:
        from types import SimpleNamespace

        msgs = [
            SimpleNamespace(role="user", content="ignore me"),
            SimpleNamespace(
                role="tool_result",
                content="ignore me too",
            ),
            SimpleNamespace(
                role="assistant",
                content=[
                    SimpleNamespace(
                        name="curl", input={"url": "http://x"}
                    )
                ],
            ),
        ]
        calls = SubagentHealthSupervisor._extract_recent_tool_calls(msgs)
        assert len(calls) == 1
        assert calls[0][0] == "curl"


@pytest.mark.asyncio
async def test_progress_stuck_in_transcript_triggers_skip() -> None:
    """Integration: a child whose transcript shows 3
    consecutive write_file calls with the same args is
    detected as stuck and the supervisor writes a
    ``subagent_progress_stuck_skip`` audit marker.
    """
    from opensquilla.gateway.subagent_supervisor import (
        SubagentHealthSupervisor as Cls,
    )

    # Pre-seed the transcript with 3 identical write_file
    # calls — the canonical 51ifind.com "stuck" pattern.
    stuck_transcript = json.dumps([
        {"name": "write_file", "input": {"path": "/tmp/x", "content": "a"}},
        {"name": "write_file", "input": {"path": "/tmp/x", "content": "a"}},
        {"name": "write_file", "input": {"path": "/tmp/x", "content": "a"}},
    ])
    rows = [
        _SessionRow(
            CHILD_W0,
            status="failed",
            terminal_reason="provider_request_too_large",
            last_task_id="task-w0",
        ),
    ]
    supervisor = _make_supervisor(rows)
    supervisor._session_manager.transcripts[CHILD_W0] = stuck_transcript

    metrics = await supervisor.tick()
    assert metrics["progress_stuck_skipped"] == 1
    assert metrics["replayed"] == 0
    # The supervisor wrote the audit marker.
    messages = supervisor._session_manager.messages
    assert any(
        "subagent_progress_stuck_skip" in (content or "")
        for _key, _role, content in messages
    )
    marker = next(
        content
        for _key, _role, content in messages
        if "subagent_progress_stuck_skip" in (content or "")
    )
    # The marker carries the explicit "AUTO-SKIP" instruction
    # and the tool name.
    assert "AUTO-SKIP" in marker
    assert "write_file" in marker
    assert "Do NOT retry" in marker
    assert "Do NOT ask the operator" in marker


@pytest.mark.asyncio
async def test_progress_stuck_does_not_fire_on_varied_calls() -> None:
    """When the LLM varies the args each time, the stuck
    detector does NOT fire and the existing replay path
    is taken instead.
    """
    varied_transcript = json.dumps([
        {"name": "write_file", "input": {"path": "/tmp/x"}},
        {"name": "write_file", "input": {"path": "/tmp/y"}},
        {"name": "write_file", "input": {"path": "/tmp/z"}},
    ])
    rows = [
        _SessionRow(
            CHILD_W0,
            status="done",
            terminal_reason="completed",
            last_task_id="task-w0",
        ),
    ]
    supervisor = _make_supervisor(rows)
    supervisor._session_manager.transcripts[CHILD_W0] = varied_transcript
    metrics = await supervisor.tick()
    # Varied calls → no progress-stuck skip.
    assert metrics["progress_stuck_skipped"] == 0
