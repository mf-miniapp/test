#!/usr/bin/env python3
"""Tests for the OpenAI Responses API <-> Chat Completions translation in
gateway_compat.py. These run without a real upstream: the converters are
pure functions, so we just exercise them directly.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

# Stub heavy third-party imports so this test runs in any venv.
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gateway_compat as gc  # noqa: E402

# Skip the whole file if Responses protocol was disabled.
if not getattr(gc, "ENABLE_OPENAI_RESPONSES", False):
    print("ENABLE_OPENAI_RESPONSES=0; skipping Responses tests")
    sys.exit(0)

import json
import uuid  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════
# Responses request -> Chat Completions request
# ═══════════════════════════════════════════════════════════════════════════

def test_responses_instructions_become_system_message() -> None:
    body = {
        "model": "qwen3.6-35b",
        "instructions": "You are helpful.",
        "input": [{"role": "user", "content": "hi"}],
    }
    req = gc._responses_to_oai(body)
    assert req.messages[0].role == "system"
    assert req.messages[0].content == "You are helpful."
    assert req.messages[1].role == "user"
    assert req.messages[1].content == "hi"


def test_responses_typed_text_part_preserved() -> None:
    body = {
        "model": "x",
        "input": [{
            "role": "user",
            "content": [{"type": "input_text", "text": "hello"}],
        }],
    }
    req = gc._responses_to_oai(body)
    content = req.messages[0].content
    assert isinstance(content, list)
    assert content == [{"type": "text", "text": "hello"}]


def test_responses_function_call_becomes_assistant_tool_calls() -> None:
    body = {
        "model": "x",
        "input": [
            {"role": "user", "content": "what time?"},
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "get_time",
                "arguments": '{"tz": "UTC"}',
            },
        ],
    }
    req = gc._responses_to_oai(body)
    assert len(req.messages) == 2
    m = req.messages[1]
    assert m.role == "assistant"
    assert m.content is None
    assert m.tool_calls is not None and len(m.tool_calls) == 1
    tc = m.tool_calls[0]
    assert tc["id"] == "call_1"
    assert tc["function"]["name"] == "get_time"
    assert tc["function"]["arguments"] == '{"tz": "UTC"}'


def test_responses_function_call_output_becomes_tool_message() -> None:
    body = {
        "model": "x",
        "input": [
            {
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "12:00 UTC",
            }
        ],
    }
    req = gc._responses_to_oai(body)
    assert len(req.messages) == 1
    m = req.messages[0]
    assert m.role == "tool"
    assert m.content == "12:00 UTC"
    assert m.tool_call_id == "call_1"


def test_responses_max_output_tokens_maps_to_max_tokens() -> None:
    body = {
        "model": "x",
        "max_output_tokens": 256,
        "input": [{"role": "user", "content": "hi"}],
    }
    req = gc._responses_to_oai(body)
    assert req.max_tokens == 256


def test_responses_tools_wrapped_into_function_shape() -> None:
    body = {
        "model": "x",
        "input": [{"role": "user", "content": "x"}],
        "tools": [{
            "type": "function",
            "name": "f",
            "description": "...",
            "parameters": {"type": "object", "properties": {"q": {"type": "string"}}},
        }],
    }
    req = gc._responses_to_oai(body)
    assert req.tools is not None
    assert req.tools[0]["type"] == "function"
    assert req.tools[0]["function"]["name"] == "f"
    assert req.tools[0]["function"]["parameters"]["properties"]["q"]["type"] == "string"


# ═══════════════════════════════════════════════════════════════════════════
# Chat Completions response -> Responses API output[]
# ═══════════════════════════════════════════════════════════════════════════

def test_oai_text_response_becomes_message_output_item() -> None:
    payload = {
        "id": "chatcmpl-x",
        "model": "qwen3.6-35b",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
    }
    resp = gc._oai_to_responses(payload, req_model="qwen3.6-35b")
    assert resp["object"] == "response"
    assert resp["status"] == "completed"
    assert resp["model"] == "qwen3.6-35b"
    assert len(resp["output"]) == 1
    item = resp["output"][0]
    assert item["type"] == "message"
    assert item["role"] == "assistant"
    assert item["content"] == [
        {"type": "output_text", "text": "Hello!", "annotations": []}
    ]


def test_oai_tool_call_response_becomes_function_call_items() -> None:
    payload = {
        "id": "chatcmpl-y",
        "model": "qwen3.6-35b",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_a",
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "arguments": '{"q":"hi"}',
                        },
                    },
                    {
                        "id": "call_b",
                        "type": "function",
                        "function": {
                            "name": "save",
                            "arguments": '{"value":1}',
                        },
                    },
                ],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
    }
    resp = gc._oai_to_responses(payload, req_model="qwen3.6-35b")
    assert len(resp["output"]) == 2
    for i, item in enumerate(resp["output"]):
        assert item["type"] == "function_call", f"item {i} not function_call"
        assert item["status"] == "completed"
    # Check call_ids preserved (NOT lost)
    assert resp["output"][0]["call_id"] == "call_a"
    assert resp["output"][0]["name"] == "lookup"
    assert resp["output"][0]["arguments"] == '{"q":"hi"}'
    assert resp["output"][1]["call_id"] == "call_b"
    assert resp["output"][1]["name"] == "save"
    assert resp["output"][1]["arguments"] == '{"value":1}'


def test_oai_mixed_text_and_tool_response() -> None:
    payload = {
        "id": "chatcmpl-z",
        "model": "x",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Let me check.",
                "tool_calls": [{
                    "id": "call_z",
                    "type": "function",
                    "function": {"name": "f", "arguments": "{}"},
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    resp = gc._oai_to_responses(payload, req_model="x")
    assert len(resp["output"]) == 2
    assert resp["output"][0]["type"] == "message"
    assert resp["output"][0]["content"][0]["text"] == "Let me check."
    assert resp["output"][1]["type"] == "function_call"
    assert resp["output"][1]["name"] == "f"


def test_oai_length_finish_becomes_incomplete_status() -> None:
    payload = {
        "id": "chatcmpl-l",
        "model": "x",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "truncated..."},
            "finish_reason": "length",
        }],
    }
    resp = gc._oai_to_responses(payload, req_model="x")
    assert resp["status"] == "incomplete"
    assert resp["output"][0]["status"] == "incomplete"


def test_oai_usage_reshaped_to_responses_shape() -> None:
    payload = {
        "id": "chatcmpl-u",
        "model": "x",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "reasoning_tokens": 2,
            "cached_tokens": 3,
        },
    }
    resp = gc._oai_to_responses(payload, req_model="x")
    u = resp["usage"]
    assert u["input_tokens"] == 10
    assert u["output_tokens"] == 5
    assert u["total_tokens"] == 15
    assert u["input_tokens_details"]["cached_tokens"] == 3
    assert u["output_tokens_details"]["reasoning_tokens"] == 2


def test_oai_response_has_required_top_level_fields() -> None:
    """Sanity check: the opensquilla Responses parser reads these fields
    from the top level of the response. If any are missing, parsing fails."""
    payload = {
        "id": "chatcmpl-q",
        "model": "x",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }],
    }
    resp = gc._oai_to_responses(payload, req_model="x")
    for key in ("id", "object", "status", "model", "output", "usage"):
        assert key in resp, f"missing top-level key: {key}"


if __name__ == "__main__":
    tests = [
        test_responses_instructions_become_system_message,
        test_responses_typed_text_part_preserved,
        test_responses_function_call_becomes_assistant_tool_calls,
        test_responses_function_call_output_becomes_tool_message,
        test_responses_max_output_tokens_maps_to_max_tokens,
        test_responses_tools_wrapped_into_function_shape,
        test_oai_text_response_becomes_message_output_item,
        test_oai_tool_call_response_becomes_function_call_items,
        test_oai_mixed_text_and_tool_response,
        test_oai_length_finish_becomes_incomplete_status,
        test_oai_usage_reshaped_to_responses_shape,
        test_oai_response_has_required_top_level_fields,
    ]
    for t in tests:
        t()
        print(f"  ok: {t.__name__}")
    print(f"all {len(tests)} tests passed")
