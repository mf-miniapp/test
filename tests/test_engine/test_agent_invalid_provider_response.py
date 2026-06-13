from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest
import structlog.testing

from opensquilla.engine import Agent, AgentConfig, ThinkingLevel, ToolResult
from opensquilla.engine.runtime import TurnRunner
from opensquilla.engine.usage import UsageTracker
from opensquilla.provider import (
    ChatConfig,
    Message,
    ModelCapabilities,
    ToolDefinition,
    ToolInputSchema,
)
from opensquilla.provider import DoneEvent as ProviderDone
from opensquilla.provider import TextDeltaEvent as ProviderText
from opensquilla.provider import ToolUseEndEvent as ProviderToolUseEnd
from opensquilla.provider import ToolUseStartEvent as ProviderToolUseStart
from opensquilla.session.manager import SessionManager
from opensquilla.session.storage import SessionStorage
from opensquilla.session.compaction import CompactionResult
from opensquilla.tools.types import CallerKind, ToolContext


class _SequenceProvider:
    provider_name = "fake"

    def __init__(self, streams: list[list[Any]]) -> None:
        self.streams = streams
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        messages: list[Message],
        tools: list[Any] | None = None,
        config: ChatConfig | None = None,
    ) -> AsyncIterator[Any]:
        index = len(self.calls)
        self.calls.append({"messages": messages, "tools": tools, "config": config})
        events = self.streams[index] if index < len(self.streams) else self.streams[-1]
        return self._stream(events)

    async def _stream(self, events: list[Any]) -> AsyncIterator[Any]:
        for event in events:
            yield event

    async def list_models(self) -> list[Any]:
        return []


class _FallbackSequenceProvider(_SequenceProvider):
    def __init__(self, streams: list[list[Any]]) -> None:
        super().__init__(streams)
        self.fallback_reasons: list[str] = []

    def fallback_after_invalid_response(self, reason: str) -> bool:
        self.fallback_reasons.append(reason)
        return True


def _large_reasoning_only_done() -> ProviderDone:
    return ProviderDone(
        stop_reason="stop",
        input_tokens=35_000,
        output_tokens=2,
        reasoning_tokens=2,
        reasoning_content="internal",
    )


class _SelectorClone:
    def __init__(self, provider: _SequenceProvider) -> None:
        self.provider = provider
        self.current_config = SimpleNamespace(model="fake-model")

    def resolve(self) -> _SequenceProvider:
        return self.provider

    def override_model(self, model: str) -> None:
        self.current_config.model = model

    def next_fallback_after_failure(self, primary_failure: Exception) -> _SequenceProvider:
        raise IndexError("No fallback configured")


class _ProviderSelector:
    def __init__(self, provider: _SequenceProvider) -> None:
        self.provider = provider

    def clone(self) -> _SelectorClone:
        return _SelectorClone(self.provider)


class _CacheReport:
    break_detected = False

    def to_log_dict(self) -> dict[str, Any]:
        return {}


@pytest.mark.asyncio
async def test_final_done_returns_openrouter_deepseek_reasoning_content() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderText(text="ok"),
                ProviderDone(
                    stop_reason="stop",
                    input_tokens=10,
                    output_tokens=1,
                    reasoning_tokens=4,
                    reasoning_content="I reasoned through the OpenRouter response.",
                    model="deepseek/deepseek-v4-flash",
                ),
            ]
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            thinking=ThinkingLevel.HIGH,
            model_id="deepseek/deepseek-v4-flash",
            model_capabilities=ModelCapabilities(
                supports_reasoning=True,
                supports_tools=True,
                reasoning_format="openrouter",
            ),
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    done = next(event for event in events if event.kind == "done")
    assert done.text == "ok"
    assert done.reasoning_content == "I reasoned through the OpenRouter response."


@pytest.mark.asyncio
async def test_reasoning_only_first_turn_retries_with_thinking_disabled() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderDone(
                    stop_reason="stop",
                    input_tokens=10,
                    output_tokens=5,
                    reasoning_tokens=5,
                    reasoning_content="internal reasoning",
                    model="z-ai/glm-5.1-20260406",
                )
            ],
            [
                ProviderText(text="ok"),
                ProviderDone(
                    stop_reason="stop",
                    input_tokens=11,
                    output_tokens=1,
                    model="z-ai/glm-5.1-20260406",
                ),
            ],
        ]
    )
    usage = UsageTracker()
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            thinking=ThinkingLevel.MEDIUM,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
        usage_tracker=usage,
        session_key="agent:test:reasoning-only",
    )

    events = [event async for event in agent.run_turn("hello")]

    assert [event.kind for event in events if event.kind == "error"] == []
    assert any(
        event.kind == "warning" and event.code == "provider_reasoning_only_retry"
        for event in events
    )
    done = next(event for event in events if event.kind == "done")
    assert done.text == "ok"
    assert done.input_tokens == 21
    assert done.output_tokens == 6
    assert done.reasoning_tokens == 5
    assert len(provider.calls) == 2
    assert provider.calls[0]["config"].thinking is True
    assert provider.calls[1]["config"].thinking is False
    assert provider.calls[1]["config"].thinking_level is None
    assert provider.calls[1]["config"].thinking_budget_tokens == 0
    tracked = usage.get("agent:test:reasoning-only")
    assert tracked is not None
    assert tracked.input_tokens == 21
    assert tracked.output_tokens == 6
    assistant_messages = [msg for msg in agent._history if msg.role == "assistant"]
    assert len(assistant_messages) == 1
    assert assistant_messages[0].content[0].text == "ok"
    assert assistant_messages[0].reasoning_content is None


@pytest.mark.asyncio
async def test_reasoning_only_post_tool_turn_retries_with_thinking_disabled() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderToolUseStart(tool_use_id="tool-1", tool_name="echo"),
                ProviderToolUseEnd(
                    tool_use_id="tool-1",
                    tool_name="echo",
                    arguments={"value": "ok"},
                ),
                ProviderDone(stop_reason="tool_use", input_tokens=3, output_tokens=1),
            ],
            [
                ProviderDone(
                    stop_reason="stop",
                    input_tokens=4,
                    output_tokens=2,
                    reasoning_tokens=2,
                    reasoning_content="internal reasoning",
                )
            ],
            [
                ProviderText(text="done"),
                ProviderDone(stop_reason="stop", input_tokens=5, output_tokens=1),
            ],
        ]
    )

    async def tool_handler(call: Any) -> ToolResult:
        return ToolResult(
            tool_use_id=call.tool_use_id,
            tool_name=call.tool_name,
            content="tool ok",
        )

    agent = Agent(
        provider=provider,
        config=AgentConfig(
            thinking=ThinkingLevel.MEDIUM,
            max_iterations=2,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
        tool_definitions=[
            ToolDefinition(
                name="echo",
                description="Echo.",
                input_schema=ToolInputSchema(
                    properties={"value": {"type": "string"}},
                    required=["value"],
                ),
            )
        ],
        tool_handler=tool_handler,
    )

    events = [event async for event in agent.run_turn("hello")]

    assert any(event.kind == "done" and event.text == "done" for event in events)
    assert any(
        event.kind == "warning" and event.code == "provider_reasoning_only_retry"
        for event in events
    )
    assert len(provider.calls) == 3
    assert provider.calls[1]["config"].thinking is True
    assert provider.calls[2]["config"].thinking is False


@pytest.mark.asyncio
async def test_reasoning_only_with_thinking_disabled_surfaces_empty_response() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderDone(
                    stop_reason="stop",
                    input_tokens=4,
                    output_tokens=2,
                    reasoning_tokens=2,
                    reasoning_content="internal reasoning",
                )
            ]
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(thinking=False, retry_base_backoff_ms=0, retry_max_backoff_ms=0),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 1
    assert any(event.kind == "error" and event.code == "empty_response" for event in events)
    done = next(event for event in events if event.kind == "done")
    assert done.input_tokens == 4
    assert done.output_tokens == 2
    assert done.reasoning_tokens == 2


@pytest.mark.asyncio
async def test_clean_empty_done_retries_once_then_errors() -> None:
    provider = _SequenceProvider(
        [
            [ProviderDone(stop_reason="stop", input_tokens=3, output_tokens=0)],
            [ProviderDone(stop_reason="stop", input_tokens=4, output_tokens=0)],
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 2
    assert any(event.kind == "warning" and event.code == "provider_empty_retry" for event in events)
    assert any(event.kind == "error" and event.code == "empty_response" for event in events)
    done = next(event for event in events if event.kind == "done")
    assert done.input_tokens == 7
    assert done.output_tokens == 0


@pytest.mark.asyncio
async def test_clean_empty_done_can_switch_to_selector_fallback() -> None:
    provider = _FallbackSequenceProvider(
        [
            [ProviderDone(stop_reason="stop", input_tokens=3, output_tokens=0)],
            [
                ProviderText(text="ok"),
                ProviderDone(stop_reason="stop", input_tokens=4, output_tokens=1),
            ],
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(max_provider_retries=0),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert provider.fallback_reasons == ["malformed_empty"]
    assert len(provider.calls) == 2
    assert any(event.kind == "done" and event.text == "ok" for event in events)
    assert not any(event.kind == "error" for event in events)


@pytest.mark.asyncio
async def test_large_reasoning_only_uses_fallback_before_same_model_retry() -> None:
    provider = _FallbackSequenceProvider(
        [
            [_large_reasoning_only_done()],
            [
                ProviderText(text="ok"),
                ProviderDone(stop_reason="stop", input_tokens=4, output_tokens=1),
            ],
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            thinking=ThinkingLevel.MEDIUM,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert provider.fallback_reasons == ["reasoning_only"]
    assert len(provider.calls) == 2
    assert not any(
        event.kind == "warning" and event.code == "provider_reasoning_only_retry"
        for event in events
    )
    assert any(
        event.kind == "warning" and event.code == "provider_large_context_fallback"
        for event in events
    )
    assert any(event.kind == "done" and event.text == "ok" for event in events)


@pytest.mark.asyncio
async def test_large_empty_response_without_fallback_surfaces_clear_error() -> None:
    provider = _SequenceProvider(
        [[ProviderDone(stop_reason="stop", input_tokens=35_000, output_tokens=0)]]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 1
    error = next(event for event in events if event.kind == "error")
    assert error.code == "empty_response"
    assert "large input" in error.message
    assert "attachment" in error.message
    assert "summarize" in error.message or "shorten" in error.message
    assert "stronger model" in error.message
    assert not any(
        event.kind == "warning" and event.code == "provider_empty_retry"
        for event in events
    )


@pytest.mark.asyncio
async def test_large_reasoning_only_compacts_before_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: provider returning reasoning-only on a large input must
    trigger local context compaction before falling back to a different
    provider. Previously the invalid-response path skipped compaction and
    surfaced a terminal "send as an attachment" error."""

    import opensquilla.engine.agent as agent_module

    provider = _FallbackSequenceProvider(
        [
            [_large_reasoning_only_done()],
            [
                ProviderText(text="ok"),
                ProviderDone(stop_reason="stop", input_tokens=4, output_tokens=1),
            ],
        ]
    )
    compact_requests: list[Any] = []

    async def _compact(request: Any) -> CompactionResult:
        compact_requests.append(request)
        return CompactionResult(
            summary="compacted older history into a short summary",
            kept_entries=[],
            removed_count=len(request.entries),
            chunks_processed=1,
            summary_source="llm",
            coverage_status="ok",
        )

    monkeypatch.setattr(agent_module, "compact_context", _compact)

    # The provider's done event reports 35k input tokens, which is above
    # the 30k cutoff that triggers the `_is_large_context_invalid_response`
    # branch. We keep the actual prompt small so the *live* request
    # estimate stays below the compaction threshold and the standard
    # pre-call overflow check (a separate code path) does not fire —
    # this test is focused on the invalid-response branch.
    long_prompt = "x" * 2_000
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=0,
            max_overflow_retries=2,
            context_window_tokens=20_000,
            context_overflow_threshold=0.5,
            flush_enabled=False,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn(long_prompt)]

    # Compaction must have run and the second call must carry a smaller
    # request than the first.
    assert len(compact_requests) == 1, (
        "context compaction should be attempted before falling back"
    )
    assert len(provider.calls) == 2
    first_request = provider.calls[0]["messages"]
    second_request = provider.calls[1]["messages"]
    first_chars = sum(
        len(str(m.content)) for m in first_request
    )
    second_chars = sum(
        len(str(m.content)) for m in second_request
    )
    assert second_chars < first_chars, (
        f"second call should be smaller: first={first_chars} chars "
        f"second={second_chars} chars"
    )

    warning_codes = [
        event.code for event in events if getattr(event, "kind", "") == "warning"
    ]
    assert "context_auto_compaction_start" in warning_codes
    assert "context_auto_compaction_retry" in warning_codes
    # Fallback must NOT trigger when compaction shrinks the request.
    assert "provider_large_context_fallback" not in warning_codes
    assert provider.fallback_reasons == []

    compaction_events = [
        event
        for event in events
        if getattr(event, "kind", "") == "compaction"
    ]
    assert len(compaction_events) == 1
    assert compaction_events[0].removed_count >= 1

    assert any(
        getattr(event, "kind", "") == "done" and getattr(event, "text", "") == "ok"
        for event in events
    )
    assert not any(getattr(event, "kind", "") == "error" for event in events)


@pytest.mark.asyncio
async def test_large_reasoning_only_compaction_refused_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When compaction refuses because the recent tail already exceeds the
    budget, the agent must skip the compact loop and route to the fallback
    provider instead of looping compaction calls forever."""

    import opensquilla.engine.agent as agent_module

    provider = _FallbackSequenceProvider(
        [
            [_large_reasoning_only_done()],
            [
                ProviderText(text="ok"),
                ProviderDone(stop_reason="stop", input_tokens=4, output_tokens=1),
            ],
        ]
    )
    compact_requests: list[Any] = []

    async def _compact(request: Any) -> CompactionResult:
        compact_requests.append(request)
        # Refusal: keep everything, no summary — surfaced to the agent as a
        # refusal reason "provider_recent_tail_too_large" via skip_reason.
        return CompactionResult(
            summary="",
            kept_entries=[
                {"role": e["role"], "content": e["content"]} for e in request.entries
            ],
            removed_count=0,
            chunks_processed=0,
            skip_reason="recent_tail_too_large",
        )

    monkeypatch.setattr(agent_module, "compact_context", _compact)

    long_prompt = "x" * 2_000
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=0,
            max_overflow_retries=2,
            context_window_tokens=20_000,
            context_overflow_threshold=0.5,
            flush_enabled=False,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn(long_prompt)]

    # Compaction ran once, then we routed to the fallback provider.
    assert len(compact_requests) == 1
    assert provider.fallback_reasons == ["reasoning_only"]
    assert any(
        event.kind == "warning" and event.code == "provider_large_context_fallback"
        for event in events
    )
    assert any(event.kind == "done" and event.text == "ok" for event in events)


@pytest.mark.asyncio
async def test_incomplete_tool_stream_errors_without_running_tool() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderToolUseStart(tool_use_id="tool-1", tool_name="echo"),
                ProviderDone(stop_reason="tool_use", input_tokens=5, output_tokens=1),
            ]
        ]
    )
    called = False

    async def tool_handler(call: Any) -> ToolResult:
        nonlocal called
        called = True
        return ToolResult(tool_use_id=call.tool_use_id, tool_name=call.tool_name, content="tool ok")

    agent = Agent(
        provider=provider,
        config=AgentConfig(retry_base_backoff_ms=0, retry_max_backoff_ms=0),
        tool_definitions=[
            ToolDefinition(
                name="echo",
                description="Echo.",
                input_schema=ToolInputSchema(),
            )
        ],
        tool_handler=tool_handler,
    )

    events = [event async for event in agent.run_turn("hello")]

    assert called is False
    assert any(event.kind == "tool_use_start" for event in events)
    assert any(event.kind == "error" and event.code == "incomplete_tool_stream" for event in events)
    done = next(event for event in events if event.kind == "done")
    assert done.input_tokens == 5
    assert done.output_tokens == 1
    assert agent._history == []


@pytest.mark.asyncio
async def test_turn_runner_drops_unpaired_tool_use_from_incomplete_stream_transcript() -> None:
    storage = SessionStorage(":memory:")
    await storage.connect()
    manager = SessionManager(storage)
    session_key = "agent:main:incomplete-tool-stream"
    await manager.create(session_key)
    provider = _SequenceProvider(
        [
            [
                ProviderToolUseStart(tool_use_id="tool-1", tool_name="echo"),
                ProviderDone(stop_reason="tool_use", input_tokens=5, output_tokens=1),
            ]
        ]
    )
    runner = TurnRunner(
        provider_selector=_ProviderSelector(provider),
        session_manager=manager,
    )

    try:
        events = [
            event
            async for event in runner.run(
                "hello",
                session_key,
                ToolContext(is_owner=True, caller_kind=CallerKind.CLI),
                history_has_persisted_user=False,
                no_memory_capture=True,
            )
        ]
        transcript = await manager.get_transcript(session_key)
    finally:
        await storage.close()

    assert any(event.kind == "error" and event.code == "incomplete_tool_stream" for event in events)
    assert all(entry.role != "assistant" for entry in transcript)
    assert any(
        entry.role == "system"
        and "Provider stream ended with an incomplete tool call" in entry.content
        for entry in transcript
    )


@pytest.mark.asyncio
async def test_turn_runner_persists_no_provider_error_to_transcript() -> None:
    storage = SessionStorage(":memory:")
    await storage.connect()
    manager = SessionManager(storage)
    session_key = "agent:main:no-provider"
    await manager.create(session_key)
    runner = TurnRunner(
        provider_selector=_ProviderSelector(None),  # type: ignore[arg-type]
        session_manager=manager,
    )

    try:
        events = [
            event
            async for event in runner.run(
                "hello",
                session_key,
                ToolContext(is_owner=True, caller_kind=CallerKind.CLI),
                history_has_persisted_user=False,
                no_memory_capture=True,
            )
        ]
        transcript = await manager.get_transcript(session_key)
    finally:
        await storage.close()

    assert any(event.kind == "error" and event.code == "no_provider" for event in events)
    assert any(
        entry.role == "system" and entry.content == "Error: No provider available"
        for entry in transcript
    )


@pytest.mark.asyncio
async def test_no_done_without_visible_output_retries_once_then_errors() -> None:
    provider = _SequenceProvider([[], []])
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 2
    assert any(
        event.kind == "error" and event.code == "provider_stream_incomplete"
        for event in events
    )
    assert not any(event.kind == "done" for event in events)


@pytest.mark.asyncio
async def test_no_done_after_text_does_not_retry() -> None:
    provider = _SequenceProvider([[ProviderText(text="partial")]])
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 1
    assert any(event.kind == "text_delta" and event.text == "partial" for event in events)
    assert any(
        event.kind == "error" and event.code == "provider_stream_incomplete"
        for event in events
    )
    assert not any(event.kind == "done" for event in events)


@pytest.mark.asyncio
async def test_length_capped_visible_text_continues_once_before_terminal() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderText(text="partial answer"),
                ProviderDone(stop_reason="length", input_tokens=7, output_tokens=9),
            ],
            [
                ProviderText(text=" finished"),
                ProviderDone(stop_reason="stop", input_tokens=8, output_tokens=1),
            ],
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 2
    assert any(event.kind == "text_delta" and event.text == "partial answer" for event in events)
    assert any(event.kind == "text_delta" and event.text == " finished" for event in events)
    assert any(
        event.kind == "warning" and event.code == "provider_output_continue"
        for event in events
    )
    assert not any(event.kind == "error" for event in events)
    done = next(event for event in events if event.kind == "done")
    assert done.text == "partial answer finished"
    assert done.input_tokens == 15
    assert done.output_tokens == 10


@pytest.mark.asyncio
async def test_length_capped_visible_text_uses_configured_continuation_budget() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderText(text="part one "),
                ProviderDone(stop_reason="length", input_tokens=1, output_tokens=2),
            ],
            [
                ProviderText(text="part two "),
                ProviderDone(stop_reason="length", input_tokens=3, output_tokens=4),
            ],
            [
                ProviderText(text="part three "),
                ProviderDone(stop_reason="length", input_tokens=5, output_tokens=6),
            ],
            [
                ProviderText(text="done"),
                ProviderDone(stop_reason="stop", input_tokens=7, output_tokens=8),
            ],
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            length_capped_continuations=3,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 4
    assert sum(
        1
        for event in events
        if event.kind == "warning" and event.code == "provider_output_continue"
    ) == 3
    assert not any(event.kind == "error" for event in events)
    done = next(event for event in events if event.kind == "done")
    assert done.text == "part one part two part three done"
    assert done.input_tokens == 16
    assert done.output_tokens == 20


@pytest.mark.asyncio
async def test_length_capped_exhaustion_records_partial_diagnostics() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderText(text="first partial "),
                ProviderDone(stop_reason="length", input_tokens=1, output_tokens=2),
            ],
            [
                ProviderText(text="second partial "),
                ProviderDone(stop_reason="length", input_tokens=3, output_tokens=4),
            ],
        ]
    )
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            length_capped_continuations=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
    )

    with structlog.testing.capture_logs() as captured:
        events = [event async for event in agent.run_turn("hello")]

    assert len(provider.calls) == 2
    assert any(event.kind == "text_delta" and event.text == "first partial " for event in events)
    assert any(event.kind == "text_delta" and event.text == "second partial " for event in events)
    assert any(
        event.kind == "warning" and event.code == "provider_output_continue"
        for event in events
    )
    assert any(
        event.kind == "error" and event.code == "provider_output_truncated"
        for event in events
    )
    exhausted = [
        event
        for event in captured
        if event.get("event") == "provider.output_truncated_exhausted"
    ]
    assert exhausted
    assert exhausted[-1]["attempt"] == 1
    assert exhausted[-1]["budget"] == 1
    assert exhausted[-1]["visible_chars"] == len("second partial ")
    assert exhausted[-1]["partial_preserved"] is True


@pytest.mark.asyncio
async def test_length_capped_tool_call_is_not_executed() -> None:
    provider = _SequenceProvider(
        [
            [
                ProviderToolUseStart(tool_use_id="tool-1", tool_name="echo"),
                ProviderToolUseEnd(
                    tool_use_id="tool-1",
                    tool_name="echo",
                    arguments={"value": "x"},
                ),
                ProviderDone(stop_reason="length", input_tokens=7, output_tokens=9),
            ]
        ]
    )
    called = False

    async def tool_handler(call: Any) -> ToolResult:
        nonlocal called
        called = True
        return ToolResult(tool_use_id=call.tool_use_id, tool_name=call.tool_name, content="tool ok")

    agent = Agent(
        provider=provider,
        config=AgentConfig(retry_base_backoff_ms=0, retry_max_backoff_ms=0),
        tool_definitions=[
            ToolDefinition(
                name="echo",
                description="Echo.",
                input_schema=ToolInputSchema(),
            )
        ],
        tool_handler=tool_handler,
    )

    events = [event async for event in agent.run_turn("hello")]

    assert called is False
    assert any(event.kind == "tool_use_start" for event in events)
    assert any(
        event.kind == "error" and event.code == "provider_output_truncated"
        for event in events
    )
    assert not any(event.kind == "tool_result" for event in events)
    assert agent._history == []


@pytest.mark.asyncio
async def test_discarded_empty_attempt_counts_usage_but_skips_cache_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _SequenceProvider(
        [
            [ProviderDone(stop_reason="stop", input_tokens=3, output_tokens=0)],
            [
                ProviderText(text="ok"),
                ProviderDone(stop_reason="stop", input_tokens=4, output_tokens=1),
            ],
        ]
    )
    cache_checks: list[Any] = []

    def fake_cache_check(*args: Any, **kwargs: Any) -> _CacheReport:
        cache_checks.append((args, kwargs))
        return _CacheReport()

    monkeypatch.setattr("opensquilla.engine.agent.check_response_for_cache_break", fake_cache_check)
    usage = UsageTracker()
    agent = Agent(
        provider=provider,
        config=AgentConfig(
            max_provider_retries=1,
            retry_base_backoff_ms=0,
            retry_max_backoff_ms=0,
        ),
        usage_tracker=usage,
        session_key="agent:test:empty-retry",
    )

    events = [event async for event in agent.run_turn("hello")]

    done = next(event for event in events if event.kind == "done")
    assert done.input_tokens == 7
    assert done.output_tokens == 1
    tracked = usage.get("agent:test:empty-retry")
    assert tracked is not None
    assert tracked.input_tokens == 7
    assert tracked.output_tokens == 1
    assert len(cache_checks) == 1
    assert len([msg for msg in agent._history if msg.role == "assistant"]) == 1


# ===========================================================================
# 2026-06-09 (Issue 9 — compaction did not run; error message lies).
# The 51ifind.com regression: user set context_window_tokens but
# the runtime surfaced "after automatic context compaction and
# payload reduction" even though the compaction step never
# actually ran (the flush pre-check refused it, or the LLM
# compactor returned a no-op, or the compactor raised). The fix:
#
#   1. _context_overflow_error messages now distinguish the
#      "refused" reasons from the "ran but didn't help" reasons.
#   2. _simple_fallback_compact is a deterministic, side-effect
#      free path that runs AFTER the main compactor refuses,
#      drops the oldest messages and the largest tool_result
#      blocks, and returns a CompactionOutcome iff the new size
#      is actually smaller.
#
# These tests cover the new contract.
# ===========================================================================


class TestSimpleFallbackCompact:
    """_simple_fallback_compact is the deterministic fallback for
    when the LLM-driven compactor refuses / fails / returns a
    no-op (Issue 9).
    """

    def test_drops_oldest_quarter_of_messages(self) -> None:
        """Given 100 messages, the simple fallback drops the
        oldest 25 and keeps the most recent 75. The last 4
        messages are always preserved (we never drop the
        current turn).
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        messages = [
            Message(role="user", content=f"msg {i}")
            for i in range(100)
        ]
        # The simple fallback requires an estimated size larger
        # than the new size; estimate the input at 100_000
        # tokens (4 chars/token for the 200-char content).
        out = agent._simple_fallback_compact(
            list(messages),
            context_window_tokens=50_000,
            estimated_context_tokens=100_000,
            compaction_id="test",
        )
        assert out is not None
        assert out.compacted is True
        # 25 messages dropped.
        assert len(out.messages) == 75
        # The last 4 messages are preserved (we never drop
        # the current turn).
        assert out.messages[-1].content == "msg 99"
        assert out.messages[-2].content == "msg 98"

    def test_truncates_oversized_tool_result_blocks(self) -> None:
        """When a tool_result block is much larger than the
        median message size, the simple fallback truncates it
        to ``_SIMPLE_FALLBACK_TRUNCATE_KEEP_FRACTION`` of its
        original length and appends ``[truncated]``.
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        # 10 short messages and 1 very large one.
        from opensquilla.provider import (
            ContentBlockToolResult,
        )
        small = [
            Message(role="user", content=f"small {i}")
            for i in range(10)
        ]
        large_content = "x" * 10_000
        large_tool_result = Message(
            role="user",
            content=[
                ContentBlockToolResult(
                    tool_use_id="t1",
                    content=large_content,
                    is_error=False,
                )
            ],
        )
        messages = small + [large_tool_result]
        out = agent._simple_fallback_compact(
            list(messages),
            context_window_tokens=50_000,
            estimated_context_tokens=200_000,
            compaction_id="test",
        )
        assert out is not None
        assert out.compacted is True
        # The last message was the large tool_result. Its
        # content was truncated.
        last_msg = out.messages[-1]
        assert isinstance(last_msg.content, list)
        truncated_block = last_msg.content[0]
        truncated_content = truncated_block.content
        # Truncated to ~half of 10_000 = ~5000 chars + marker
        assert len(truncated_content) < len(large_content)
        assert "[truncated]" in truncated_content

    def test_no_op_when_nothing_to_drop_returns_none(self) -> None:
        """A list of tiny messages that the simple fallback
        can't reduce returns None and sets the
        ``simple_fallback_not_smaller`` refusal reason. The
        caller's error message then honestly says "compaction
        AND simple-fallback both failed".
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        # 4 tiny messages, well under any sensible threshold.
        messages = [
            Message(role="user", content=f"tiny {i}")
            for i in range(4)
        ]
        out = agent._simple_fallback_compact(
            list(messages),
            context_window_tokens=50_000,
            estimated_context_tokens=20,  # claim huge to force the no-op path
            compaction_id="test",
        )
        # The fallback has nothing to drop (we keep the last 4)
        # and nothing to truncate (all blocks are tiny).
        assert out is None
        assert (
            agent._last_compaction_refusal_reason
            == "simple_fallback_not_smaller"
        )

    def test_smaller_input_keeps_originals(self) -> None:
        """When the input is already smaller than the estimated
        size, the simple fallback does NOT re-truncate (no
        work to do) and returns None with
        ``simple_fallback_not_smaller``. The caller's retry
        counter is bumped; eventually the
        ``_context_overflow_error`` surfaces an honest
        message.
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        # Input size is 50 tokens, but the caller's estimate
        # says 5 tokens (already under threshold — the
        # fallback has no headroom). We test the
        # "new_size_tokens >= estimated_context_tokens"
        # branch.
        messages = [Message(role="user", content="x" * 200)]
        out = agent._simple_fallback_compact(
            list(messages),
            context_window_tokens=1000,
            estimated_context_tokens=10,  # way smaller than the 50-token new size
            compaction_id="test",
        )
        assert out is None
        assert (
            agent._last_compaction_refusal_reason
            == "simple_fallback_not_smaller"
        )


class TestContextOverflowErrorMessages:
    """_context_overflow_error messages now honestly say whether
    compaction was refused vs ran but didn't help.
    """

    def _build_agent_with_refusal(self, reason: str | None) -> Any:
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = reason
        return agent

    def test_flush_timeout_message_says_compaction_refused(self) -> None:
        """The 2026-06-09 regression: the old message said
        "after automatic context compaction" but the flush
        refused, so compaction NEVER ran. The new message
        must say so.
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = (
            "memory_flush_timeout_before_compaction"
        )
        err = agent._context_overflow_error()
        # The error code reflects the refusal class.
        assert err.code == "compaction_refused_flush_timeout"
        # The message must NOT say "after automatic context
        # compaction" because compaction didn't run.
        assert "after automatic context compaction" not in err.message
        # The message must explicitly say compaction was
        # refused.
        assert "compaction could not run" in err.message.lower()
        assert (
            "NOT" in err.message or "not compacted" in err.message.lower()
        )
        # The message hints at the operator's recourse.
        assert "flush_timeout_seconds" in err.message

    def test_flush_degraded_message_says_compaction_refused(self) -> None:
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = (
            "memory_flush_degraded_before_compaction"
        )
        err = agent._context_overflow_error()
        assert err.code == "compaction_refused_memory_flush"
        # The message must NOT lie about compaction having
        # run.
        assert "after automatic context compaction" not in err.message
        # The message names the operator's recourse.
        assert (
            "flush_compaction_requires_safe_receipt" in err.message
            or "retry" in err.message.lower()
        )

    def test_compaction_not_smaller_message_distinguishes(self) -> None:
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = "compaction_not_smaller"
        err = agent._context_overflow_error()
        # The new code is preserved (backward-compat).
        assert err.code == "compaction_not_smaller"
        # The message must say "did not reduce" or similar
        # (NOT "after compaction" which would be ambiguous).
        assert "did not reduce" in err.message.lower()
        # The new message also references the simple-fallback
        # path so operators know both paths were tried.
        assert "simple-fallback" in err.message.lower() or (
            "fallback" in err.message.lower()
        )

    def test_simple_fallback_not_smaller_has_distinct_code(self) -> None:
        """The simple-fallback failure maps to
        ``provider_request_too_large`` (same as the legacy
        tail-too-large) but the message explicitly names
        the simple-fallback path so operators can tell which
        strategy failed.
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = "simple_fallback_not_smaller"
        err = agent._context_overflow_error()
        assert err.code == "provider_request_too_large"
        # The message names BOTH strategies.
        assert "compaction" in err.message.lower()
        assert "simple-fallback" in err.message.lower() or (
            "simple fallback" in err.message.lower()
        )
        # The message also points to the operator's recourse.
        assert (
            "context_window_tokens" in err.message
            or "smaller model" in err.message.lower()
        )

    def test_provider_recent_tail_too_large_message_explains(self) -> None:
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = (
            "provider_recent_tail_too_large"
        )
        err = agent._context_overflow_error()
        assert err.code == "provider_request_too_large"
        # The new message says the recent tail is the
        # problem, NOT a generic "after compaction".
        assert (
            "recent turn" in err.message.lower()
            or "recent" in err.message.lower()
        )
        # The new message names the simple-fallback path.
        assert "simple-fallback" in err.message.lower() or (
            "fallback" in err.message.lower()
        )

    def test_fallback_error_message_mentions_existing_keyword(
        self,
    ) -> None:
        """Pin a stable keyword the W8 reporting specialist
        can grep for. The legacy error message contained
        "after automatic context compaction and payload
        reduction"; the new message keeps "automatic" or
        "compaction" so log filters still work.
        """
        from opensquilla.engine.agent import Agent

        agent = Agent(provider=None, config=AgentConfig())
        agent._last_compaction_refusal_reason = (
            "provider_request_budget_exhausted"
        )
        err = agent._context_overflow_error()
        # The legacy "after automatic context compaction"
        # phrase is REMOVED in the new message because it was
        # misleading (compaction might not have actually
        # run). Operators searching for "after automatic
        # context compaction" should be aware the message
        # changed; the new keyword is "compaction" + the
        # refusal class name.
        assert "after automatic context compaction" not in err.message
        # The new message still mentions "compaction" so
        # existing log filters still match.
        assert "compaction" in err.message.lower()
        # The new message also names the simple-fallback
        # path so operators can see what was tried.
        assert "simple-fallback" in err.message.lower() or (
            "fallback" in err.message.lower()
        )
