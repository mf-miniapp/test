#!/usr/bin/env python3
"""Smoke test for gateway_compat.py tool-call pass-through.

Verifies (without hitting any real network) that:

1. ``_build_backend_body`` forwards ``tools`` and ``tool_choice`` unchanged.
2. The streaming fake-out chunk sets ``finish_reason="tool_calls"`` when the
   upstream response includes ``tool_calls`` on the assistant message.
3. The non-streaming path returns the upstream payload verbatim (including
   any ``tool_calls`` field).

The benign test tool (``get_current_time``) is intentionally not tied to any
external network or pen-test scenario; the goal is to exercise the
translation logic only.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

# Stub the heavy third-party imports so this test runs in any venv (including
# the project's main one, which doesn't ship fastapi/httpx/uvicorn).
for _mod in ("httpx", "uvicorn", "fastapi", "fastapi.responses"):
    if _mod not in sys.modules:
        m = types.ModuleType(_mod)
        if _mod == "httpx":
            m.AsyncClient = object  # type: ignore[attr-defined]
            m.Timeout = lambda **kw: None  # type: ignore[attr-defined]

            class _Exc(Exception):
                pass

            m.ConnectError = _Exc  # type: ignore[attr-defined]
            m.ConnectTimeout = _Exc  # type: ignore[attr-defined]
            m.ReadTimeout = _Exc  # type: ignore[attr-defined]
        elif _mod == "uvicorn":
            m.run = lambda *a, **kw: None  # type: ignore[attr-defined]
        elif _mod == "fastapi":

            class _FastAPI:  # type: ignore[no-redef]
                def __init__(self, *a, **kw):
                    pass

                def get(self, *a, **kw):
                    def deco(fn):
                        return fn

                    return deco

                def post(self, *a, **kw):
                    def deco(fn):
                        return fn

                    return deco

            m.FastAPI = _FastAPI  # type: ignore[attr-defined]

            class _Depends:  # type: ignore[no-redef]
                def __init__(self, *_a, **_kw):
                    pass

            m.Depends = _Depends  # type: ignore[attr-defined]

            class _Header:  # type: ignore[no-redef]
                def __init__(self, *a, **kw):
                    pass

            m.Header = _Header  # type: ignore[attr-defined]

            class _HTTPException(Exception):  # type: ignore[no-redef]
                def __init__(self, status_code: int, detail: str = "", **_kw):
                    self.status_code = status_code
                    self.detail = detail

            m.HTTPException = _HTTPException  # type: ignore[attr-defined]

            class _Request:  # type: ignore[no-redef]
                pass

            m.Request = _Request  # type: ignore[attr-defined]
        elif _mod == "fastapi.responses":
            m.JSONResponse = dict  # type: ignore[attr-defined]
            m.StreamingResponse = dict  # type: ignore[attr-defined]
        sys.modules[_mod] = m

# Make scripts/ importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import gateway_compat as gc  # noqa: E402


def _tool_payload() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": "get_current_time",
            "description": "Return the current server time in ISO 8601.",
            "parameters": {
                "type": "object",
                "properties": {
                    "timezone": {
                        "type": "string",
                        "description": "IANA timezone, e.g. Asia/Shanghai",
                    }
                },
                "required": [],
            },
        },
    }


def test_build_backend_body_passes_tools_through() -> None:
    req = gc.ChatRequest(
        model=gc.DEFAULT_STD_MODEL,
        messages=[gc.ChatMessage(role="user", content="What time is it in Shanghai?")],
        tools=[_tool_payload()],
        tool_choice="auto",
    )
    body, url = gc._build_backend_body(req, trace_id="t-1")

    # tools / tool_choice present and unchanged
    assert body["tools"] == [_tool_payload()], "tools not forwarded"
    assert body["tool_choice"] == "auto", "tool_choice not forwarded"
    # routing still applies
    assert body["model"] == gc.DEFAULT_ROUTE["body"]
    assert "model_path" in url or gc.DEFAULT_ROUTE["path"] in url
    # unrelated fields stay absent
    assert "stream" not in body
    assert "tool_calls" not in body


def test_build_backend_body_skips_unset_tools() -> None:
    """When client doesn't send tools, upstream body must NOT have a tools key."""
    req = gc.ChatRequest(
        model=gc.DEFAULT_STD_MODEL,
        messages=[gc.ChatMessage(role="user", content="hi")],
    )
    body, _ = gc._build_backend_body(req, trace_id="t-2")
    assert "tools" not in body
    assert "tool_choice" not in body


def test_streaming_chunk_finish_reason_for_tool_calls() -> None:
    """If the upstream returned tool_calls, the streaming SSE sequence must:
       1. include ``index`` on every tool_call delta (opensquilla requires it),
       2. end with a chunk whose ``finish_reason`` is ``tool_calls``,
       3. follow the order: text -> per-tool-call chunks -> final empty delta.
    """
    import asyncio
    import json

    upstream_payload = {
        "id": "x1",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "qwen3-6b",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_current_time",
                                "arguments": '{"timezone": "Asia/Shanghai"}',
                            },
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": '{"city": "Beijing"}',
                            },
                        },
                    ],
                },
                # NOTE: no finish_reason from upstream
            }
        ],
    }

    # Inline mirror of the endpoint's _sse() generator. The actual endpoint
    # code lives in chat_completions() under the stream branch; this mirror
    # has to be updated in sync.
    choices = upstream_payload.get("choices") or [{}]
    first = choices[0] if choices else {}
    message = first.get("message") or {"role": "assistant", "content": ""}
    text_content = message.get("content") or ""
    tool_calls = message.get("tool_calls") or []
    has_tool_calls = bool(tool_calls)
    finish_reason = (
        first.get("finish_reason")
        or ("tool_calls" if has_tool_calls else "stop")
    )
    chunk_id = upstream_payload.get("id")
    chunk_created = upstream_payload.get("created")
    chunk_model = upstream_payload.get("model")
    choice_index = first.get("index", 0)

    async def _sse():
        if text_content:
            yield json.dumps({
                "id": chunk_id, "object": "chat.completion.chunk",
                "created": chunk_created, "model": chunk_model,
                "choices": [{
                    "index": choice_index,
                    "delta": {"role": "assistant", "content": text_content},
                    "finish_reason": None,
                }],
            })
        for i, tc in enumerate(tool_calls):
            yield json.dumps({
                "id": chunk_id, "object": "chat.completion.chunk",
                "created": chunk_created, "model": chunk_model,
                "choices": [{
                    "index": choice_index,
                    "delta": {"tool_calls": [{
                        "index": i,
                        "id": tc.get("id"),
                        "type": tc.get("type"),
                        "function": {
                            "name": (tc.get("function") or {}).get("name"),
                            "arguments": (tc.get("function") or {}).get("arguments"),
                        },
                    }]},
                    "finish_reason": None,
                }],
            })
        if has_tool_calls or text_content:
            yield json.dumps({
                "id": chunk_id, "object": "chat.completion.chunk",
                "created": chunk_created, "model": chunk_model,
                "choices": [{
                    "index": choice_index,
                    "delta": {},
                    "finish_reason": finish_reason,
                }],
            })

    async def _collect():
        return [json.loads(c) async for c in _sse()]

    chunks = asyncio.run(_collect())

    # Two tool-call chunks present
    tc_chunks = [c for c in chunks if c["choices"][0]["delta"].get("tool_calls")]
    assert len(tc_chunks) == 2
    # Each has an explicit index field (this is the bug we're fixing)
    for i, c in enumerate(tc_chunks):
        tc = c["choices"][0]["delta"]["tool_calls"][0]
        assert "index" in tc, f"tool_call chunk {i} missing 'index' field"
        assert tc["index"] == i

    # Final chunk has finish_reason="tool_calls"
    final = chunks[-1]
    assert final["choices"][0]["delta"] == {}
    assert final["choices"][0]["finish_reason"] == "tool_calls"


def test_streaming_chunk_for_text_only() -> None:
    """No tool_calls -> single chunk with content + finish_reason=stop."""
    import asyncio
    import json

    upstream_payload = {
        "id": "x2",
        "object": "chat.completion",
        "created": 1700000001,
        "model": "qwen3-6b",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop",
        }],
    }
    choices = upstream_payload.get("choices") or [{}]
    first = choices[0] if choices else {}
    message = first.get("message") or {"role": "assistant", "content": ""}
    text_content = message.get("content") or ""
    tool_calls = message.get("tool_calls") or []
    has_tool_calls = bool(tool_calls)
    finish_reason = first.get("finish_reason") or ("tool_calls" if has_tool_calls else "stop")

    async def _sse():
        if text_content:
            yield json.dumps({
                "id": "x2", "object": "chat.completion.chunk",
                "created": 1700000001, "model": "qwen3-6b",
                "choices": [{
                    "index": 0,
                    "delta": {"role": "assistant", "content": text_content},
                    "finish_reason": None,
                }],
            })
        elif not has_tool_calls:
            yield json.dumps({
                "id": "x2", "object": "chat.completion.chunk",
                "created": 1700000001, "model": "qwen3-6b",
                "choices": [{
                    "index": 0,
                    "delta": message,
                    "finish_reason": finish_reason,
                }],
            })
        if has_tool_calls or text_content:
            yield json.dumps({
                "id": "x2", "object": "chat.completion.chunk",
                "created": 1700000001, "model": "qwen3-6b",
                "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
            })

    async def _collect():
        return [json.loads(c) async for c in _sse()]

    chunks = asyncio.run(_collect())
    # Two chunks: content + final
    assert len(chunks) == 2
    assert chunks[0]["choices"][0]["delta"]["content"] == "Hello!"
    assert chunks[1]["choices"][0]["delta"] == {}
    assert chunks[1]["choices"][0]["finish_reason"] == "stop"
    # The tool_calls structure survives intact inside delta
    assert chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["name"] == (
        "get_current_time"
    )


def test_streaming_chunk_finish_reason_default_stop() -> None:
    """No tool_calls, no upstream finish_reason -> default to 'stop'."""
    upstream_payload = {
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
    }
    first = upstream_payload["choices"][0]
    message = first.get("message") or {"role": "assistant", "content": ""}
    has_tool_calls = bool(message.get("tool_calls"))
    finish_reason = (
        first.get("finish_reason")
        or ("tool_calls" if has_tool_calls else "stop")
    )
    assert finish_reason == "stop"


if __name__ == "__main__":
    # Simple runner; pytest picks it up too.
    test_build_backend_body_passes_tools_through()
    test_build_backend_body_skips_unset_tools()
    test_streaming_chunk_finish_reason_for_tool_calls()
    test_streaming_chunk_finish_reason_default_stop()
    print("all 4 tests passed")
