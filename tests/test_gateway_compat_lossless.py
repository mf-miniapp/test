#!/usr/bin/env python3
"""Lossless request-conversion tests for gateway_compat.py.

These tests verify that the per-protocol converters preserve all the
information a caller can send. We do NOT make any HTTP calls — we exercise
the converter functions directly. The non-standard upstream is irrelevant
here; what matters is that no inbound field is silently dropped on the
way to the canonical OpenAI ChatRequest.
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


# ═══════════════════════════════════════════════════════════════════════════
# Anthropic -> OAI
# ═══════════════════════════════════════════════════════════════════════════

def test_anthropic_text_block_preserved() -> None:
    body = {
        "model": "claude",
        "max_tokens": 100,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": "hello"}],
            }
        ],
    }
    req = gc._anthropic_to_oai(body) if hasattr(gc, "_anthropic_to_oai") else None
    if req is None:
        # Anthropic protocol disabled by env
        return
    assert len(req.messages) == 1
    assert req.messages[0].role == "user"
    # OAI accepts both shapes; converter returns the parts list.
    content = req.messages[0].content
    if isinstance(content, list):
        assert content == [{"type": "text", "text": "hello"}]
    else:
        assert content == "hello"


def test_anthropic_image_base64_preserved() -> None:
    body = {
        "model": "claude",
        "max_tokens": 100,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is this?"},
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": "iVBORw0KGgo=",
                        },
                    },
                ],
            }
        ],
    }
    req = gc._anthropic_to_oai(body)
    assert len(req.messages) == 1
    content = req.messages[0].content
    assert isinstance(content, list)
    assert content[0] == {"type": "text", "text": "what is this?"}
    assert content[1]["type"] == "image_url"
    assert content[1]["image_url"]["url"] == "data:image/png;base64,iVBORw0KGgo="


def test_anthropic_tool_use_split_into_assistant_message() -> None:
    body = {
        "model": "claude",
        "max_tokens": 100,
        "tools": [
            {
                "name": "get_weather",
                "description": "...",
                "input_schema": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                },
            }
        ],
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "get_weather",
                        "input": {"city": "Beijing"},
                    }
                ],
            }
        ],
    }
    req = gc._anthropic_to_oai(body)
    # 1 message: assistant with tool_calls
    assert len(req.messages) == 1
    m = req.messages[0]
    assert m.role == "assistant"
    assert m.content is None
    assert m.tool_calls is not None and len(m.tool_calls) == 1
    tc = m.tool_calls[0]
    assert tc["id"] == "toolu_1"
    assert tc["function"]["name"] == "get_weather"
    assert json.loads(tc["function"]["arguments"]) == {"city": "Beijing"}
    # Tools list passed through
    assert req.tools is not None and req.tools[0]["function"]["parameters"] == {
        "type": "object",
        "properties": {"city": {"type": "string"}},
    }


def test_anthropic_tool_result_split_into_tool_message() -> None:
    body = {
        "model": "claude",
        "max_tokens": 100,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": "sunny, 25C",
                    }
                ],
            }
        ],
    }
    req = gc._anthropic_to_oai(body)
    assert len(req.messages) == 1
    m = req.messages[0]
    assert m.role == "tool"
    assert m.content == "sunny, 25C"
    assert m.tool_call_id == "toolu_1"


def test_anthropic_tool_choice_mapping() -> None:
    cases = [
        ("auto", "auto"),
        ({"type": "auto"}, "auto"),
        ({"type": "any"}, "required"),
        ({"type": "none"}, "none"),
        ({"type": "tool", "name": "X"}, {"type": "function", "function": {"name": "X"}}),
    ]
    for in_tc, expected in cases:
        body = {"model": "claude", "max_tokens": 10, "tool_choice": in_tc, "messages": []}
        req = gc._anthropic_to_oai(body)
        assert req.tool_choice == expected, f"in={in_tc} out={req.tool_choice}"


# ═══════════════════════════════════════════════════════════════════════════
# Ollama -> OAI
# ═══════════════════════════════════════════════════════════════════════════

def test_ollama_image_becomes_image_url_part() -> None:
    body = {
        "model": "qwen3:6b",
        "messages": [
            {
                "role": "user",
                "content": "what is this?",
                "images": ["base64data"],
            }
        ],
    }
    req = gc._ollama_chat_to_oai(body)
    assert len(req.messages) == 1
    content = req.messages[0].content
    assert isinstance(content, list)
    assert content[0] == {"type": "text", "text": "what is this?"}
    assert content[1] == {
        "type": "image_url",
        "image_url": {"url": "data:image/png;base64,base64data"},
    }


def test_ollama_format_json_object_passthrough() -> None:
    body = {"model": "x", "format": "json", "messages": []}
    req = gc._ollama_chat_to_oai(body)
    assert req.response_format == {"type": "json_object"}


def test_ollama_format_schema_passthrough() -> None:
    schema = {"type": "object", "properties": {"x": {"type": "number"}}}
    body = {"model": "x", "format": schema, "messages": []}
    req = gc._ollama_chat_to_oai(body)
    assert req.response_format == {"type": "json_schema", "json_schema": schema}


def test_ollama_tools_passthrough() -> None:
    tools = [
        {
            "type": "function",
            "function": {
                "name": "f",
                "description": "...",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]
    body = {"model": "x", "tools": tools, "messages": []}
    req = gc._ollama_chat_to_oai(body)
    assert req.tools == tools
    assert req.tool_choice is None


# ═══════════════════════════════════════════════════════════════════════════
# llama.cpp -> OAI  (template detection)
# ═══════════════════════════════════════════════════════════════════════════

def test_llamacpp_chatml_parsed() -> None:
    prompt = (
        "<|im_start|>system\nYou are helpful.<|im_end|>\n"
        "<|im_start|>user\nhi<|im_end|>\n"
        "<|im_start|>assistant\n"
    )
    req = gc._llamacpp_to_oai({"prompt": prompt})
    assert [m.role for m in req.messages] == ["system", "user"]
    assert req.messages[0].content == "You are helpful."
    assert req.messages[1].content == "hi"


def test_llamacpp_llama3_parsed() -> None:
    prompt = (
        "<|start_header_id|>system<|end_header_id|>\nYou are helpful.<|eot_id|>"
        "<|start_header_id|>user<|end_header_id|>\nhi<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>\n"
    )
    req = gc._llamacpp_to_oai({"prompt": prompt})
    assert [m.role for m in req.messages] == ["system", "user"]
    assert req.messages[0].content == "You are helpful."
    assert req.messages[1].content == "hi"


def test_llamacpp_mistral_parsed() -> None:
    prompt = "[INST] What is 2+2? [/INST]Four.[/INST] And 3+3?[/INST]"
    req = gc._llamacpp_to_oai({"prompt": prompt})
    # 1 system preamble + alternating user/assistant pairs
    roles = [m.role for m in req.messages]
    assert "user" in roles and "assistant" in roles
    user_msg = next(m for m in req.messages if m.role == "user")
    assert "2+2" in user_msg.content


def test_llamacpp_alpaca_parsed() -> None:
    prompt = (
        "Below is an instruction that describes a task. "
        "Write a response that appropriately completes the request.\n\n"
        "### Instruction:\nTranslate to French: hello\n\n"
        "### Response:\nbonjour\n"
    )
    req = gc._llamacpp_to_oai({"prompt": prompt})
    roles = [m.role for m in req.messages]
    assert "user" in roles and "assistant" in roles


def test_llamacpp_phi3_parsed() -> None:
    prompt = (
        "<|system|>\nYou are helpful.<|endoftext|>"
        "<|user|>\nhi<|endoftext|>"
        "<|assistant|>\n"
    )
    req = gc._llamacpp_to_oai({"prompt": prompt})
    assert [m.role for m in req.messages] == ["system", "user"]
    assert req.messages[0].content == "You are helpful."
    assert req.messages[1].content == "hi"


def test_llamacpp_fallback_keeps_whole_prompt() -> None:
    """Unknown template -> prompt preserved as a single user message."""
    prompt = "Just some plain text without any chat-template markers."
    req = gc._llamacpp_to_oai({"prompt": prompt})
    assert len(req.messages) == 1
    assert req.messages[0].role == "user"
    assert req.messages[0].content == prompt


# ═══════════════════════════════════════════════════════════════════════════
# Tool-call passthrough on the wire (build_backend_body)
# ═══════════════════════════════════════════════════════════════════════════

def test_build_backend_body_includes_tool_calls_and_call_id() -> None:
    req = gc.ChatRequest(
        model=gc.DEFAULT_STD_MODEL,
        messages=[
            gc.ChatMessage(role="user", content="hi"),
            gc.ChatMessage(
                role="assistant",
                content=None,
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "f", "arguments": "{}"},
                }],
            ),
            gc.ChatMessage(role="tool", content="out", tool_call_id="call_1"),
        ],
    )
    body, _ = gc._build_backend_body(req, trace_id="t")
    msgs = body["messages"]
    assert msgs[0] == {"role": "user", "content": "hi"}
    assert msgs[1]["role"] == "assistant"
    # Pydantic-strict upstream rejects null content on assistant tool_calls
    # messages; we coerce None -> "" to satisfy it. tool_calls still present.
    assert msgs[1]["content"] == ""
    assert msgs[1]["tool_calls"][0]["id"] == "call_1"
    assert msgs[2]["role"] == "tool"
    assert msgs[2]["content"] == "out"
    assert msgs[2]["tool_call_id"] == "call_1"


def test_build_backend_body_text_content_preserved() -> None:
    """Text content (not None) must pass through unchanged."""
    req = gc.ChatRequest(
        model=gc.DEFAULT_STD_MODEL,
        messages=[gc.ChatMessage(role="assistant", content="Hello world")],
    )
    body, _ = gc._build_backend_body(req, trace_id="t")
    assert body["messages"][0]["content"] == "Hello world"


def test_chatmessage_accepts_missing_content_key() -> None:
    """opensquilla's OpenAI Chat Completions client OMITS the `content` key
    on assistant tool_calls messages (real OAI behavior). Our ChatMessage
    Pydantic model must accept that — the body builder then coerces to ""."""
    # Construct ChatMessage without `content` at all (simulating missing key)
    msg = gc.ChatMessage.model_validate(
        {"role": "assistant", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "f", "arguments": "{}"}}
        ]}
    )
    assert msg.content is None

    # And the body builder must emit a non-empty `content` key
    req = gc.ChatRequest(
        model=gc.DEFAULT_STD_MODEL,
        messages=[
            gc.ChatMessage(role="user", content="hi"),
            msg,
        ],
    )
    body, _ = gc._build_backend_body(req, trace_id="t")
    msgs = body["messages"]
    assert msgs[0]["content"] == "hi"
    assert msgs[1]["content"] == ""  # coerced from missing key
    assert msgs[1]["tool_calls"][0]["function"]["name"] == "f"


import json  # noqa: E402  (placed after the other test defs for clarity)


if __name__ == "__main__":
    tests = [
        test_anthropic_text_block_preserved,
        test_anthropic_image_base64_preserved,
        test_anthropic_tool_use_split_into_assistant_message,
        test_anthropic_tool_result_split_into_tool_message,
        test_anthropic_tool_choice_mapping,
        test_ollama_image_becomes_image_url_part,
        test_ollama_format_json_object_passthrough,
        test_ollama_format_schema_passthrough,
        test_ollama_tools_passthrough,
        test_llamacpp_chatml_parsed,
        test_llamacpp_llama3_parsed,
        test_llamacpp_mistral_parsed,
        test_llamacpp_alpaca_parsed,
        test_llamacpp_phi3_parsed,
        test_llamacpp_fallback_keeps_whole_prompt,
        test_build_backend_body_includes_tool_calls_and_call_id,
        test_build_backend_body_text_content_preserved,
        test_chatmessage_accepts_missing_content_key,
    ]
    for t in tests:
        t()
        print(f"  ok: {t.__name__}")
    print(f"all {len(tests)} tests passed")
