from __future__ import annotations

from types import SimpleNamespace

import pytest

from opensquilla.gateway.subagent_announce import (
    _build_subagent_group_outcome,
    _build_terminal_group_payloads,
    _format_parent_wake_message,
    _tracker,
    announce_subagent_completion,
    close_subagent_spawn_group,
    set_background_completion_manager,
)
from opensquilla.gateway.task_runtime import SubagentCompletionEvent
from opensquilla.session.models import AgentTaskStatus, SessionStatus

PARENT = "agent:main:webchat:parent"
PARENT_TASK = "task-parent"


class _SessionRow:
    def __init__(
        self,
        session_key: str,
        *,
        status: str,
        agent_id: str = "worker",
    ) -> None:
        self.session_key = session_key
        self.spawned_by = PARENT
        self.parent_session_key = PARENT
        self.agent_id = agent_id
        self.status = status
        self.origin = {"kind": "subagent", "parent_task_id": PARENT_TASK}


class _Storage:
    def __init__(self, tasks_by_session: dict[str, list[SimpleNamespace]]) -> None:
        self.tasks_by_session = tasks_by_session
        self.batch_calls: list[tuple[str, ...]] = []

    async def list_agent_tasks_for_sessions(
        self,
        session_keys: list[str],
        limit_per_session: int = 100,
    ) -> dict[str, list[SimpleNamespace]]:
        self.batch_calls.append(tuple(session_keys))
        return {
            key: list(self.tasks_by_session.get(key, []))[:limit_per_session]
            for key in session_keys
        }


class _SessionManager:
    def __init__(
        self,
        rows: list[_SessionRow],
        *,
        tasks_by_session: dict[str, list[SimpleNamespace]],
        transcripts: dict[str, str],
    ) -> None:
        self.rows = rows
        self._storage = _Storage(tasks_by_session)
        self.transcripts = transcripts
        self.messages: list[tuple[str, str, str, dict | None]] = []
        self.finished: list[tuple[str, str]] = []

    async def list_sessions(
        self,
        agent_id=None,
        status=None,
        limit=100,
        offset=0,
        spawned_by=None,
    ):
        rows = self.rows
        if spawned_by is not None:
            rows = [row for row in rows if row.spawned_by == spawned_by]
        return rows[offset : offset + limit]

    async def read_transcript(self, session_key: str, limit: int = 50):
        text = self.transcripts.get(session_key, "")
        return [SimpleNamespace(role="assistant", content=text)] if text else []

    async def append_message(
        self,
        key: str,
        *,
        role: str,
        content: str,
        provenance: dict | None = None,
    ) -> None:
        self.messages.append((key, role, content, provenance))

    async def get_session(self, key: str):
        return SimpleNamespace(session_key=key, last_channel=None, last_to=None)

    async def finish(self, session_key: str, *, status: SessionStatus) -> None:
        self.finished.append((session_key, str(status)))
        for row in self.rows:
            if row.session_key == session_key:
                row.status = str(status)


class _TaskRuntime:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, dict | None]] = []

    async def send(self, session_key: str, message: str, provenance: dict | None = None):
        self.sent.append((session_key, message, provenance))
        return SimpleNamespace(task_id=f"wake-{len(self.sent)}")


class _BackgroundCompletion:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.waiting: list[dict] = []
        self.wakes: list[dict] = []

    async def emit_waiting(self, **kwargs) -> None:
        self.calls.append("waiting")
        self.waiting.append(kwargs)

    async def send_parent_wake(self, **kwargs) -> None:
        self.calls.append("wake")
        self.wakes.append(kwargs)


@pytest.fixture(autouse=True)
def _clean_tracker():
    _tracker.evict(PARENT)
    set_background_completion_manager(None)
    yield
    _tracker.evict(PARENT)
    set_background_completion_manager(None)


@pytest.mark.asyncio
async def test_group_payloads_enrich_non_current_children_from_task_ledger() -> None:
    child_done = "agent:worker:subagent:done"
    child_failed = "agent:worker:subagent:failed"
    manager = _SessionManager(
        [
            _SessionRow(child_done, status="done", agent_id="worker-a"),
            _SessionRow(child_failed, status="failed", agent_id="worker-b"),
        ],
        tasks_by_session={
            child_done: [
                SimpleNamespace(
                    task_id="task-default-newer",
                    agent_id="worker-a",
                    status=AgentTaskStatus.FAILED,
                    run_kind="default",
                    terminal_reason="followup_error",
                    created_at=100,
                    updated_at=200,
                    finished_at=300,
                ),
                SimpleNamespace(
                    task_id="task-done",
                    agent_id="worker-a",
                    status=AgentTaskStatus.SUCCEEDED,
                    run_kind="subagent",
                    terminal_reason="done",
                    created_at=10,
                    updated_at=20,
                    finished_at=30,
                )
            ],
            child_failed: [
                SimpleNamespace(
                    task_id="task-failed",
                    agent_id="worker-b",
                    status=AgentTaskStatus.FAILED,
                    run_kind="subagent",
                    terminal_reason="tool_error",
                    error_class="RuntimeError",
                    error_message="boom",
                    created_at=11,
                    updated_at=21,
                    finished_at=31,
                )
            ],
        },
        transcripts={child_done: "done result", child_failed: "partial failure details"},
    )

    payloads = await _build_terminal_group_payloads(
        parent_session_key=PARENT,
        parent_task_id=PARENT_TASK,
        session_manager=manager,
    )

    assert manager._storage.batch_calls == [(child_done, child_failed)]
    assert payloads is not None
    by_child = {payload["child_session_key"]: payload for payload in payloads}
    assert by_child[child_done]["task_id"] == "task-done"
    assert by_child[child_done]["agent_id"] == "worker-a"
    assert by_child[child_done]["status"] == "succeeded"
    assert by_child[child_failed]["task_id"] == "task-failed"
    assert by_child[child_failed]["agent_id"] == "worker-b"
    assert by_child[child_failed]["status"] == "failed"
    assert by_child[child_failed]["terminal_reason"] == "tool_error"
    assert by_child[child_failed]["error_class"] == "RuntimeError"
    assert by_child[child_failed]["error_message"] == "boom"

    wake_message = _format_parent_wake_message(PARENT_TASK, payloads)
    assert "task_id=task-failed" in wake_message
    assert "agent_id=worker-b" in wake_message
    assert "error_class=RuntimeError" in wake_message
    assert "error_message=boom" in wake_message


def test_parent_wake_bounds_aggregate_subagent_output() -> None:
    payloads = []
    for index in range(5):
        payloads.append(
            {
                "child_session_key": f"agent:worker:subagent:{index}",
                "task_id": f"task-{index}",
                "agent_id": f"worker-{index}",
                "status": "succeeded",
                "terminal_reason": "completed",
                "result": {"text": f"result-{index}-" + ("x" * 12_000)},
            }
        )

    wake_message = _format_parent_wake_message(PARENT_TASK, payloads)

    assert len(wake_message) < 20_000
    assert wake_message.count("<untrusted_subagent_result>") == 5
    assert "[subagent result truncated" in wake_message
    assert "child_session_key=agent:worker:subagent:4" in wake_message
    assert "task_id=task-4" in wake_message


def test_group_outcome_summary_counts_and_bounds_non_success_children() -> None:
    long_error = "boom-" * 200
    payloads = [
        {
            "child_session_key": "agent:worker:subagent:done",
            "task_id": "task-done",
            "agent_id": "worker-a",
            "status": "succeeded",
            "terminal_reason": "completed",
        },
        {
            "child_session_key": "agent:worker:subagent:failed",
            "task_id": "task-failed",
            "agent_id": "worker-b",
            "status": "failed",
            "terminal_reason": "tool_error",
            "error_class": "RuntimeError",
            "error_message": long_error,
        },
        {
            "child_session_key": "agent:worker:subagent:timeout",
            "task_id": "task-timeout",
            "agent_id": "worker-c",
            "status": "timeout",
            "terminal_reason": "timeout",
        },
    ]

    outcome = _build_subagent_group_outcome(payloads)

    assert outcome["total"] == 3
    assert outcome["succeeded"] == 1
    assert outcome["failed"] == 1
    assert outcome["timeout"] == 1
    assert outcome["cancelled"] == 0
    assert outcome["abandoned"] == 0
    assert outcome["non_success"] == 2
    assert outcome["runtime_partial_failure_disclosure_required"] is True
    assert [child["child_session_key"] for child in outcome["failed_children"]] == [
        "agent:worker:subagent:failed",
        "agent:worker:subagent:timeout",
    ]
    failed = outcome["failed_children"][0]
    assert failed["task_id"] == "task-failed"
    assert failed["agent_id"] == "worker-b"
    assert failed["status"] == "failed"
    assert failed["terminal_reason"] == "tool_error"
    assert failed["error_class"] == "RuntimeError"
    assert failed["error_message"].startswith("boom-")
    assert len(failed["error_message"]) < len(long_error)
    assert failed["error_message_truncated"] is True


def test_context_overflow_failure_is_sanitized_for_group_outcome_and_wake() -> None:
    raw_error = (
        "Context overflow is in the current turn's recent tool calls or "
        "reasoning tail; history compaction cannot reduce it."
    )
    payloads = [
        {
            "child_session_key": "agent:worker:subagent:failed",
            "task_id": "task-failed",
            "agent_id": "worker-b",
            "status": "failed",
            "terminal_reason": "error",
            "error_class": "current_turn_context_exhausted",
            "error_message": raw_error,
        }
    ]

    outcome = _build_subagent_group_outcome(payloads)
    failed = outcome["failed_children"][0]
    wake_message = _format_parent_wake_message(PARENT_TASK, payloads, outcome=outcome)

    assert failed["error_class"] == "provider_request_too_large"
    assert "too large" in failed["error_message"].lower()
    assert raw_error not in failed["error_message"]
    assert "current_turn_context_exhausted" not in wake_message
    assert "history compaction cannot reduce it" not in wake_message
    assert "too large" in wake_message.lower()


@pytest.mark.asyncio
async def test_group_payloads_fall_back_when_task_ledger_is_unavailable() -> None:
    child = "agent:worker:subagent:fallback"
    manager = _SessionManager(
        [_SessionRow(child, status="timeout", agent_id="worker")],
        tasks_by_session={},
        transcripts={child: "late output"},
    )
    manager._storage = SimpleNamespace()

    payloads = await _build_terminal_group_payloads(
        parent_session_key=PARENT,
        parent_task_id=PARENT_TASK,
        session_manager=manager,
    )

    assert payloads == [
        {
            "type": "subagent_completion",
            "parent_session_key": PARENT,
            "child_session_key": child,
            "status": "timeout",
            "terminal_reason": "timeout",
            "parent_task_id": PARENT_TASK,
            "result": {
                # v3.2.1 (2026-06-07): the runtime auto-appends a
                # synthetic marker line to subagent text that has no
                # marker (defense in depth against the 2026-06-07
                # hack-deep W4.1 incident). The text the parent sees
                # therefore ends with a valid ``schema: ...`` line,
                # and the marker is recorded as ``marker_synthetic``.
                "text": (
                    "late output\n"
                    "schema: unknown-v1 | phase: evidence-collection | "
                    "wave: 0/1 | deps: empty"
                ),
                "truncated": False,
                "source_role": "assistant",
                "marker_present": True,
                "result_marker": (
                    "schema: unknown-v1 | phase: evidence-collection | "
                    "wave: 0/1 | deps: empty"
                ),
                "result_marker_phase": "evidence-collection",
                "result_marker_wave": "0/1",
                "result_marker_schema": "unknown-v1",
                "result_marker_deps": [],
                "marker_synthetic": True,
                "marker_synthetic_reason": "missing_marker_recovered",
            },
            "agent_id": "worker",
        }
    ]


@pytest.mark.asyncio
async def test_parent_wake_is_deferred_until_yield_and_sent_once() -> None:
    child = "agent:worker:subagent:solo"
    manager = _SessionManager(
        [_SessionRow(child, status="done")],
        tasks_by_session={
            child: [
                SimpleNamespace(
                    task_id="task-child",
                    agent_id="worker",
                    status=AgentTaskStatus.SUCCEEDED,
                    run_kind="subagent",
                    terminal_reason="done",
                    created_at=1,
                    updated_at=2,
                    finished_at=3,
                )
            ]
        },
        transcripts={child: "child output"},
    )
    runtime = _TaskRuntime()
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-child",
        status=AgentTaskStatus.SUCCEEDED,
        terminal_reason="done",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert runtime.sent == []
    assert manager.messages

    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1
    assert "[SUBAGENT_COMPLETION_GROUP]" in runtime.sent[0][1]
    assert "task_id=task-child" in runtime.sent[0][1]

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1

    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1


@pytest.mark.asyncio
async def test_parent_wake_provenance_carries_group_outcome_for_mixed_children() -> None:
    child_done = "agent:worker:subagent:done"
    child_failed = "agent:worker:subagent:failed"
    manager = _SessionManager(
        [
            _SessionRow(child_done, status="done", agent_id="worker-a"),
            _SessionRow(child_failed, status="failed", agent_id="worker-b"),
        ],
        tasks_by_session={
            child_done: [
                SimpleNamespace(
                    task_id="task-done",
                    agent_id="worker-a",
                    status=AgentTaskStatus.SUCCEEDED,
                    run_kind="subagent",
                    terminal_reason="completed",
                    created_at=1,
                    updated_at=2,
                    finished_at=3,
                )
            ],
            child_failed: [
                SimpleNamespace(
                    task_id="task-failed",
                    agent_id="worker-b",
                    status=AgentTaskStatus.FAILED,
                    run_kind="subagent",
                    terminal_reason="tool_error",
                    error_class="RuntimeError",
                    error_message="boom",
                    created_at=1,
                    updated_at=2,
                    finished_at=3,
                )
            ],
        },
        transcripts={child_done: "done result", child_failed: "failed details"},
    )
    runtime = _TaskRuntime()

    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    )

    assert len(runtime.sent) == 1
    _, wake_message, provenance = runtime.sent[0]
    assert "Subagents: 1/2 succeeded" in wake_message
    assert provenance is not None
    assert provenance["runtime_partial_failure_disclosure_required"] is True
    outcome = provenance["subagent_group_outcome"]
    assert outcome["total"] == 2
    assert outcome["succeeded"] == 1
    assert outcome["failed"] == 1
    assert outcome["non_success"] == 1
    assert outcome["failed_children"] == [
        {
            "child_session_key": child_failed,
            "task_id": "task-failed",
            "agent_id": "worker-b",
            "status": "failed",
            "terminal_reason": "tool_error",
            "error_class": "RuntimeError",
            "error_message": "boom",
            "error_message_truncated": False,
        }
    ]


@pytest.mark.asyncio
async def test_close_emits_waiting_when_spawn_group_is_not_terminal() -> None:
    child = "agent:worker:subagent:running"
    manager = _SessionManager(
        [_SessionRow(child, status="running")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()
    background = _BackgroundCompletion()
    set_background_completion_manager(background)

    closed = await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    )

    assert closed is False
    assert runtime.sent == []
    assert background.waiting == [
        {
            "parent_session_key": PARENT,
            "parent_task_id": PARENT_TASK,
            "pending_count": 1,
        }
    ]


@pytest.mark.asyncio
async def test_close_uses_background_completion_manager_for_parent_wake() -> None:
    child = "agent:worker:subagent:solo"
    manager = _SessionManager(
        [_SessionRow(child, status="done")],
        tasks_by_session={},
        transcripts={child: "child output"},
    )
    runtime = _TaskRuntime()
    background = _BackgroundCompletion()
    set_background_completion_manager(background)

    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    )

    assert runtime.sent == []
    assert background.calls == ["waiting", "wake"]
    assert len(background.wakes) == 1
    assert background.waiting == [
        {
            "parent_session_key": PARENT,
            "parent_task_id": PARENT_TASK,
            "pending_count": 0,
        }
    ]
    wake = background.wakes[0]
    assert wake["parent_session_key"] == PARENT
    assert wake["parent_task_id"] == PARENT_TASK
    assert wake["task_runtime"] is runtime
    assert "[SUBAGENT_COMPLETION_GROUP]" in wake["message"]


# ---------------------------------------------------------------------------
# Early-wake tests: when the spawn group has not been closed (LLM never
# called sessions_yield) and a subagent ends in a non-success terminal
# status, announce_subagent_completion must still push an incremental
# wake to the parent so the main agent can react immediately.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_announce_failure_wakes_parent_before_yield() -> None:
    child = "agent:worker:subagent:boom"
    manager = _SessionManager(
        [_SessionRow(child, status="failed", agent_id="worker")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-child",
        status=AgentTaskStatus.FAILED,
        terminal_reason="error",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
        error_class="empty_response",
        error_message=(
            "Provider returned no visible response for a large input. "
            "Send the material as an attachment, summarize or shorten "
            "the prompt, or use a stronger model."
        ),
    )

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )

    assert len(runtime.sent) == 1
    _, wake_message, provenance = runtime.sent[0]
    assert "[SUBAGENT_COMPLETION_GROUP]" in wake_message
    assert "[PARTIAL_WAKE]" in wake_message
    assert f"child_session_key={child}" in wake_message
    # The agent's raw "empty_response" / "no visible response for a large
    # input" error must have been sanitized to provider_request_too_large
    # by the time it reaches the parent wake.
    assert "error_class=provider_request_too_large" in wake_message
    assert "too large" in wake_message.lower()
    assert "empty_response" not in wake_message
    assert provenance is not None
    assert provenance["partial_wake"] is True
    assert provenance["runtime_partial_failure_disclosure_required"] is True


@pytest.mark.asyncio
async def test_announce_timeout_wakes_parent_before_yield() -> None:
    child = "agent:worker:subagent:slow"
    manager = _SessionManager(
        [_SessionRow(child, status="timeout", agent_id="worker")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-child",
        status=AgentTaskStatus.TIMEOUT,
        terminal_reason="timeout",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )

    assert len(runtime.sent) == 1
    _, wake_message, _provenance = runtime.sent[0]
    assert "[PARTIAL_WAKE]" in wake_message
    assert "status=timeout" in wake_message


@pytest.mark.asyncio
async def test_announce_success_still_defers_until_yield() -> None:
    # Sanity: success path is unchanged by the early-wake change.  A
    # SUCCEEDED child should NOT trigger a wake on its own — only when
    # the group is closed (via sessions_yield / auto-close).
    child = "agent:worker:subagent:ok"
    manager = _SessionManager(
        [_SessionRow(child, status="done", agent_id="worker")],
        tasks_by_session={},
        transcripts={child: "done output"},
    )
    runtime = _TaskRuntime()
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-child",
        status=AgentTaskStatus.SUCCEEDED,
        terminal_reason="completed",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert runtime.sent == []


@pytest.mark.asyncio
async def test_early_wake_then_close_is_idempotent() -> None:
    # After the early-wake fires for a failed child, an explicit
    # sessions_yield (close_subagent_spawn_group) must not send a second
    # wake.  The tracker guards the group_key and returns early.
    child = "agent:worker:subagent:boom"
    manager = _SessionManager(
        [_SessionRow(child, status="failed", agent_id="worker")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-child",
        status=AgentTaskStatus.FAILED,
        terminal_reason="error",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
        error_class="empty_response",
        error_message="Provider returned no visible response for a large input.",
    )

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1

    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1


@pytest.mark.asyncio
async def test_early_wake_via_background_completion_manager() -> None:
    # When the background completion manager is installed, the early
    # wake should route through it (so channel delivery + synthesis
    # turn work the same as the closed-group path).
    child = "agent:worker:subagent:boom"
    manager = _SessionManager(
        [_SessionRow(child, status="failed", agent_id="worker")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()
    background = _BackgroundCompletion()
    set_background_completion_manager(background)
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-child",
        status=AgentTaskStatus.FAILED,
        terminal_reason="error",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
        error_class="empty_response",
        error_message="Provider returned no visible response for a large input.",
    )

    await announce_subagent_completion(
        event,
        session_manager=manager,
        task_runtime=runtime,
    )

    assert runtime.sent == []
    assert background.calls == ["wake"]
    wake = background.wakes[0]
    assert wake["parent_session_key"] == PARENT
    assert wake["parent_task_id"] == PARENT_TASK
    assert "[PARTIAL_WAKE]" in wake["message"]
    assert wake["provenance"]["partial_wake"] is True


@pytest.mark.asyncio
async def test_first_child_wake_does_not_silently_drop_aggregated_wake() -> None:
    """Regression: parent never receives the aggregated group wake when the
    first child to complete is fast and the remaining children finish later.

    Pre-fix: ``_tracker._woken`` was an add-only ``set`` keyed by group;
    the first child to complete marked the group as woken permanently, so
    the wake fired when the *last* child completed (carrying the full
    aggregated payload) was silently dropped, leaving the parent stuck.

    Post-fix: ``_tracker`` tracks the set of ``child_session_key`` values
    that have been delivered. A wake that would only re-deliver already
    seen children is dropped; a wake carrying at least one new child still
    fires, even if the group was already woken for an earlier child.

    The real production trace for this bug:
    1. parent turn spawns W0 + 3×W1, then sessions_yield (group closed,
       no children terminal yet).
    2. W0 completes first -> first wake fires with W0 payload only.
    3. W1a completes -> siblings still pending -> no wake (existing).
    4. W1b times out -> sibling still pending -> no wake (existing).
    5. W1c completes -> ALL 4 children terminal. Pre-fix this aggregated
       wake was silently dropped because the group was already marked
       woken at step 2. Post-fix it fires and the parent sees all 4
       results in one turn.
    """
    child_w0 = "agent:worker:subagent:w0-fast"
    child_w1a = "agent:worker:subagent:w1a"
    child_w1b = "agent:worker:subagent:w1b"
    child_w1c = "agent:worker:subagent:w1c"
    # Step 0: only W0 has been enqueued so far; W1a/b/c are spawned
    # later by the parent's synthesis turn. This matches the real
    # production trace where W1s were created at 23:52:56, AFTER W0
    # finished at 23:52:01.
    manager = _SessionManager(
        [_SessionRow(child_w0, status="running", agent_id="worker")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()

    # Step 1: parent calls sessions_yield while W0 is still running ->
    # close returns False, no wake fired.
    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    ) is False
    assert len(runtime.sent) == 0

    # Step 2: W0 completes first. It is the ONLY child in the group at
    # this moment (W1s not yet enqueued), so the aggregated wake
    # carries just W0 and fires correctly. Pre-fix this would mark
    # the group as "woken" forever.
    manager.rows[0].status = "done"
    manager.transcripts[child_w0] = "ROE result"
    manager._storage.tasks_by_session[child_w0] = [
        SimpleNamespace(
            task_id="task-w0",
            agent_id="worker",
            status=AgentTaskStatus.SUCCEEDED,
            run_kind="subagent",
            terminal_reason="completed",
            created_at=1,
            updated_at=2,
            finished_at=3,
        )
    ]
    event_w0 = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child_w0,
        task_id="task-w0",
        status=AgentTaskStatus.SUCCEEDED,
        terminal_reason="completed",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )
    await announce_subagent_completion(
        event_w0,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1, (
        "first child should fire the wake so the parent can process it"
    )
    first_outcome = runtime.sent[0][2]["subagent_group_outcome"]
    assert first_outcome["total"] == 1
    assert first_outcome["succeeded"] == 1

    # Step 3: W1a/b/c are now enqueued (parent's wake turn spawns them
    # in parallel). All three show up in the group immediately, two of
    # them still running. W1a then completes. With W1b/c still
    # pending, the aggregated wake is deferred (existing "wait for the
    # rest" behaviour, unchanged by this fix).
    manager.rows.append(_SessionRow(child_w1a, status="running", agent_id="worker"))
    manager.rows.append(_SessionRow(child_w1b, status="running", agent_id="worker"))
    manager.rows.append(_SessionRow(child_w1c, status="running", agent_id="worker"))
    manager.rows[1].status = "done"  # W1a just completed
    manager.transcripts[child_w1a] = "recon output"
    event_w1a = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child_w1a,
        task_id="task-w1a",
        status=AgentTaskStatus.SUCCEEDED,
        terminal_reason="completed",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )
    await announce_subagent_completion(
        event_w1a,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1, (
        "w1a completion while w1b/c still pending must defer the wake"
    )

    # Step 4: W1b times out. W1c still pending, wake still deferred.
    manager.rows[2].status = "timeout"
    event_w1b = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child_w1b,
        task_id="task-w1b",
        status=AgentTaskStatus.TIMEOUT,
        terminal_reason="timeout",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )
    await announce_subagent_completion(
        event_w1b,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 1

    # Step 5: W1c completes. All 4 children are now terminal. The
    # build helper returns a 4-payload list. Pre-fix this aggregated
    # wake was silently dropped because the group was already marked
    # woken at step 2; post-fix it must fire so the parent can
    # synthesize all 4 results.
    manager.rows[3].status = "done"
    manager.transcripts[child_w1c] = "attack-surface output"
    event_w1c = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child_w1c,
        task_id="task-w1c",
        status=AgentTaskStatus.SUCCEEDED,
        terminal_reason="completed",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )
    await announce_subagent_completion(
        event_w1c,
        session_manager=manager,
        task_runtime=runtime,
    )
    assert len(runtime.sent) == 2, (
        "aggregated wake for all 4 children must fire after the last child "
        "completes, even though the group was already woken by the first child"
    )
    second_wake_message = runtime.sent[1][1]
    second_wake_outcome = runtime.sent[1][2]["subagent_group_outcome"]
    assert second_wake_outcome["total"] == 4
    assert second_wake_outcome["succeeded"] == 3
    assert second_wake_outcome["timeout"] == 1
    # The aggregated wake text must include the slow child identifier so
    # the parent can see it actually ran, not just the fast W0.
    assert child_w1c in second_wake_message
    assert child_w0 in second_wake_message


@pytest.mark.asyncio
async def test_duplicate_full_wake_after_group_complete_is_dropped() -> None:
    """Once every child in the group has been delivered, a redundant
    identical wake must still be dropped to avoid double-processing.
    """
    child = "agent:worker:subagent:only"
    manager = _SessionManager(
        [_SessionRow(child, status="running", agent_id="worker")],
        tasks_by_session={},
        transcripts={},
    )
    runtime = _TaskRuntime()

    # Parent closes the group while the child is still running -> no
    # wake fired (no terminal children yet).
    assert await close_subagent_spawn_group(
        PARENT,
        PARENT_TASK,
        session_manager=manager,
        task_runtime=runtime,
    ) is False
    assert len(runtime.sent) == 0

    # Child completes. This is the only child, so the aggregated wake
    # fires immediately and delivers the child to the parent.
    manager.rows[0].status = "done"
    manager.transcripts[child] = "only result"
    manager._storage.tasks_by_session[child] = [
        SimpleNamespace(
            task_id="task-only",
            agent_id="worker",
            status=AgentTaskStatus.SUCCEEDED,
            run_kind="subagent",
            terminal_reason="completed",
            created_at=1,
            updated_at=2,
            finished_at=3,
        )
    ]
    event = SubagentCompletionEvent(
        parent_session_key=PARENT,
        child_session_key=child,
        task_id="task-only",
        status=AgentTaskStatus.SUCCEEDED,
        terminal_reason="completed",
        agent_id="worker",
        parent_task_id=PARENT_TASK,
    )
    await announce_subagent_completion(event, session_manager=manager, task_runtime=runtime)
    assert len(runtime.sent) == 1, (
        "single-child aggregated wake should fire when the child completes"
    )

    # Replay the same event (e.g. due to a duplicate notify). The new
    # per-child dedup must drop it because the child is already in the
    # delivered set for this group.
    await announce_subagent_completion(event, session_manager=manager, task_runtime=runtime)
    assert len(runtime.sent) == 1, (
        "duplicate announce for an already-delivered child must be a no-op"
    )
