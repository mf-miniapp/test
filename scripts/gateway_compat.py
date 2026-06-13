#!/usr/bin/env python3
"""Multi-protocol LLM gateway: OpenAI / Anthropic / Ollama / llama.cpp -> one upstream.

The proxy listens on http://127.0.0.1:9091 (configurable) and exposes a number
of inbound protocol endpoints. Every request is normalized to an OpenAI-
shaped ``chat/completions`` call against a single fixed upstream gateway that
speaks a non-standard dialect:

    POST /{BACKEND_MODEL_PATH}/v1/inference/openai
    {
        "trace_id": "...",
        "model":    "<BACKEND_BODY_MODEL>",
        "messages": [{"role": "user", "content": "...", "name": "..."}],
        "max_tokens": ..., "tools": [...], "tool_choice": "...",
        ...
    }

Inbound protocols (each can be enabled/disabled via env var):

    OpenAI:       /v1/chat/completions  /v1/completions  /v1/models
    Anthropic:    /v1/messages          (Messages API)
    Ollama:       /api/chat  /api/generate  /api/tags
    llama.cpp:    /completion            (native /completion, not /v1/...)

Translation:
    * model name              -> {path_segment, body_model} via MODEL_ROUTES_JSON
    * (no trace_id)           -> auto-generate; honor X-Trace-Id header
    * message.name            -> pass through
    * tools / tool_choice     -> pass through
    * stream=true              -> SSE shaped per inbound protocol
    * 4xx/5xx from upstream    -> shaped per inbound protocol

Usage:
    pip install fastapi uvicorn httpx pydantic
    BACKEND_BASE=https://117.161.174.242 \\
    BACKEND_INSECURE=1 \\
    LOCAL_API_KEY=local-dev-key \\
    python3 scripts/gateway_compat.py

Then point any client at::

    # OpenAI:
    base_url = http://127.0.0.1:9091/v1
    # Anthropic:
    base_url = http://127.0.0.1:9091
    # Ollama:
    base_url = http://127.0.0.1:9091
    # llama.cpp native:
    base_url = http://127.0.0.1:9091
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from typing import Any, AsyncIterator, Optional

import asyncio
import httpx
from httpx import ConnectError, ConnectTimeout, ReadTimeout
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

# ─── Config (env-driven) ──────────────────────────────────────────────────

LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9091"))

BACKEND_BASE = os.environ.get("BACKEND_BASE", "https://117.161.174.242").rstrip("/")
BACKEND_API_KEY = os.environ.get("BACKEND_API_KEY", "local-dev-key")
BACKEND_INSECURE = os.environ.get("BACKEND_INSECURE", "0") == "1"

DEFAULT_STD_MODEL = os.environ.get("DEFAULT_STD_MODEL", "qwen3.6-35b")
DEFAULT_ROUTE: dict[str, str] = {
    "path": os.environ.get(
        "BACKEND_MODEL_PATH", "qwen36_uncensored_q4_k_m_zhanglei_dongzhiwei"
    ),
    "body": os.environ.get("BACKEND_BODY_MODEL", "qwen3_06b_pengzhiyuan_0520"),
}
try:
    MODEL_ROUTES: dict[str, dict[str, str]] = json.loads(
        os.environ.get("MODEL_ROUTES_JSON", "{}")
    )
except json.JSONDecodeError:
    MODEL_ROUTES = {}

LOCAL_API_KEY = os.environ.get("LOCAL_API_KEY", "")
DEBUG_BODY = os.environ.get("DEBUG_BODY", "0") == "1"

# Upstream connection resilience. The fixed upstream at 117.161.174.242 has
# been observed to drop TCP handshakes intermittently; we retry with
# exponential backoff so callers see 502/504 only on a sustained outage.
UPSTREAM_CONNECT_TIMEOUT = float(os.environ.get("UPSTREAM_CONNECT_TIMEOUT", "10"))
UPSTREAM_MAX_RETRIES = int(os.environ.get("UPSTREAM_MAX_RETRIES", "2"))
UPSTREAM_RETRY_BACKOFF = float(os.environ.get("UPSTREAM_RETRY_BACKOFF", "0.5"))

# Per-protocol enable flags. Set ENABLE_<X>=0 to drop those routes entirely.
ENABLE_OPENAI = os.environ.get("ENABLE_OPENAI", "1") == "1"
ENABLE_OPENAI_RESPONSES = os.environ.get("ENABLE_OPENAI_RESPONSES", "1") == "1"
ENABLE_ANTHROPIC = os.environ.get("ENABLE_ANTHROPIC", "1") == "1"
ENABLE_OLLAMA = os.environ.get("ENABLE_OLLAMA", "1") == "1"
ENABLE_LLAMACPP = os.environ.get("ENABLE_LLAMACPP", "1") == "1"


# ─── OpenAI-shape canonical models (used as the internal representation) ─

class ChatMessage(BaseModel):
    role: str
    # str | list[dict] (multimodal) | None. Default None so opensquilla
    # clients that omit `content` on assistant tool_calls messages
    # (real OAI behavior) still parse. _build_backend_body then coerces
    # to "" for strict-Pydantic upstreams.
    content: Any = None
    name: Optional[str] = None
    # OAI: tool_calls on an assistant message. We attach this when converting
    # from Anthropic tool_use blocks (the upstream is OpenAI-shaped, so
    # tool_use becomes assistant.tool_calls rather than content blocks).
    tool_calls: Optional[list[dict[str, Any]]] = None
    # OAI: tool message carries the call id it answers. We stash it in
    # `name` when converting from Anthropic tool_result, but keep this
    # explicit field too for clarity.
    tool_call_id: Optional[str] = None


def _msg_with_tool_calls(msg: ChatMessage, tool_calls: list[dict[str, Any]]) -> ChatMessage:
    """Return a copy of `msg` with tool_calls attached and content cleared."""
    return msg.model_copy(update={"content": None, "tool_calls": tool_calls})


class ChatRequest(BaseModel):
    model: str = DEFAULT_STD_MODEL
    messages: list[ChatMessage]
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    seed: Optional[int] = None
    stop: Optional[list[str] | str] = None
    stream: bool = False
    tools: Optional[list[dict[str, Any]]] = None
    tool_choice: Optional[Any] = None
    response_format: Optional[dict[str, Any]] = None


class CompletionRequest(BaseModel):
    model: str = DEFAULT_STD_MODEL
    prompt: str
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    seed: Optional[int] = None
    stop: Optional[list[str] | str] = None
    stream: bool = False


# ─── Local auth (optional) ────────────────────────────────────────────────

async def require_auth(request: Request) -> None:
    if not LOCAL_API_KEY:
        return
    auth = request.headers.get("authorization", "")
    # Anthropic also accepts x-api-key; accept both for convenience.
    x_api_key = request.headers.get("x-api-key", "")
    expected = f"Bearer {LOCAL_API_KEY}"
    if auth == expected or x_api_key == LOCAL_API_KEY:
        return
    raise HTTPException(status_code=401, detail="invalid api key")


# ─── Routing helpers ─────────────────────────────────────────────────────

def _route_for(std_model: str) -> dict[str, str]:
    return MODEL_ROUTES.get(std_model, DEFAULT_ROUTE)


def _build_backend_body(
    req: ChatRequest, trace_id: str
) -> tuple[dict[str, Any], str]:
    """Translate a canonical OpenAI-shape request into the upstream dialect."""
    route = _route_for(req.model)
    messages_out: list[dict[str, Any]] = []
    for m in req.messages:
        out: dict[str, Any] = {"role": m.role}
        # The upstream is Pydantic-strict: its Message model treats `content`
        # as `str` (required, non-Optional). Real OpenAI sends `content: null`
        # on assistant tool_calls messages, which that schema rejects. Coerce
        # None -> "" to satisfy strict upstreams while still being acceptable
        # to lenient ones.
        out["content"] = m.content if m.content is not None else ""
        if m.name:
            out["name"] = m.name
        if m.tool_calls:
            out["tool_calls"] = m.tool_calls
        if m.tool_call_id:
            out["tool_call_id"] = m.tool_call_id
        messages_out.append(out)
    body: dict[str, Any] = {
        "trace_id": trace_id,
        "model": route["body"],
        "messages": messages_out,
    }
    for k in (
        "max_tokens", "temperature", "top_p", "seed", "stop",
        "tools", "tool_choice", "response_format",
    ):
        v = getattr(req, k)
        if v is not None:
            body[k] = v
    url = f"{BACKEND_BASE}/{route['path']}/v1/inference/openai"
    return body, url


def _upstream_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if BACKEND_API_KEY:
        headers["Authorization"] = f"Bearer {BACKEND_API_KEY}"
    return headers


async def _call_upstream_oai(
    req: ChatRequest, trace_id: str
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Call the upstream with a canonical ChatRequest.

    Returns (status_code, payload_dict_or_text, headers_for_error). For 2xx
    the payload is the upstream's parsed JSON; for 4xx/5xx it's
    {"_raw_text": <string>, "_status": <int>}; for transport-level failures
    it's {"_error": "upstream_unreachable|upstream_timeout", "_message": "..."}.

    Transient network errors (ConnectTimeout, ConnectError, ReadTimeout) are
    retried UPSTREAM_MAX_RETRIES times with exponential backoff before the
    final error is returned as 502/504.
    """
    body, url = _build_backend_body(req, trace_id)
    headers = _upstream_headers()

    for attempt in range(UPSTREAM_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(
                verify=not BACKEND_INSECURE,
                trust_env=False,
                timeout=httpx.Timeout(
                    connect=UPSTREAM_CONNECT_TIMEOUT,
                    read=600.0,
                    write=600.0,
                    pool=10.0,
                ),
            ) as client:
                if DEBUG_BODY and attempt == 0:
                    print(f"\n[DEBUG_BODY] -> upstream POST {url}", file=sys.stderr)
                    print(f"[DEBUG_BODY] -> headers: {headers}", file=sys.stderr)
                    print(
                        f"[DEBUG_BODY] -> body: {json.dumps(body, ensure_ascii=False)}",
                        file=sys.stderr,
                    )
                r = await client.post(url, json=body, headers=headers)
            break  # success
        except (ConnectTimeout, ConnectError) as e:
            if attempt < UPSTREAM_MAX_RETRIES:
                backoff = UPSTREAM_RETRY_BACKOFF * (2 ** attempt)
                if DEBUG_BODY:
                    print(
                        f"[DEBUG_BODY] connect attempt {attempt+1}/{UPSTREAM_MAX_RETRIES+1} "
                        f"failed: {type(e).__name__}; retrying in {backoff:.1f}s",
                        file=sys.stderr,
                    )
                await asyncio.sleep(backoff)
                continue
            return 502, {
                "_error": "upstream_unreachable",
                "_message": f"{type(e).__name__}: {e}",
            }, {}
        except ReadTimeout as e:
            if attempt < UPSTREAM_MAX_RETRIES:
                backoff = UPSTREAM_RETRY_BACKOFF * (2 ** attempt)
                if DEBUG_BODY:
                    print(
                        f"[DEBUG_BODY] read attempt {attempt+1}/{UPSTREAM_MAX_RETRIES+1} "
                        f"timed out; retrying in {backoff:.1f}s",
                        file=sys.stderr,
                    )
                await asyncio.sleep(backoff)
                continue
            return 504, {
                "_error": "upstream_timeout",
                "_message": f"ReadTimeout: {e}",
            }, {}
    if DEBUG_BODY:
        print(f"[DEBUG_BODY] <- status: {r.status_code}", file=sys.stderr)
        try:
            print(
                f"[DEBUG_BODY] <- body: {json.dumps(r.json(), ensure_ascii=False)}",
                file=sys.stderr,
            )
        except Exception as e:  # noqa: BLE001
            print(
                f"[DEBUG_BODY] <- (non-JSON, {e}): {r.text[:500]}",
                file=sys.stderr,
            )

    if r.status_code >= 400:
        return r.status_code, {"_raw_text": r.text}, {}
    return r.status_code, r.json(), dict(r.headers)


# ─── App ───────────────────────────────────────────────────────────────────

app = FastAPI(title="gateway-compat", version="0.2.0")


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "backend_base": BACKEND_BASE,
        "default_route": DEFAULT_ROUTE,
        "model_routes": list(MODEL_ROUTES.keys()),
        "protocols": {
            "openai": ENABLE_OPENAI,
            "anthropic": ENABLE_ANTHROPIC,
            "ollama": ENABLE_OLLAMA,
            "llamacpp": ENABLE_LLAMACPP,
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# OpenAI protocol
# ════════════════════════════════════════════════════════════════════════════

if ENABLE_OPENAI:

    @app.get("/v1/models", dependencies=[Depends(require_auth)])
    async def openai_list_models() -> JSONResponse:
        now = int(time.time())
        seen: set[str] = set()
        data: list[dict[str, Any]] = []
        for mid in (DEFAULT_STD_MODEL, *MODEL_ROUTES.keys()):
            if mid in seen:
                continue
            seen.add(mid)
            data.append(
                {
                    "id": mid,
                    "object": "model",
                    "created": now,
                    "owned_by": "gateway-compat",
                }
            )
        return JSONResponse({"object": "list", "data": data})

    @app.post("/v1/chat/completions", dependencies=[Depends(require_auth)])
    async def openai_chat_completions(
        req: ChatRequest,
        x_trace_id: Optional[str] = Header(default=None, alias="X-Trace-Id"),
    ) -> Any:
        trace_id = x_trace_id or uuid.uuid4().hex
        status, payload, _ = await _call_upstream_oai(req, trace_id)
        if status >= 400:
            return JSONResponse(
                status_code=status,
                content={
                    "error": {
                        "message": payload.get("_raw_text") or payload.get("_message", ""),
                        "type": "upstream_error",
                        "trace_id": trace_id,
                    }
                },
            )
        if not req.stream:
            return JSONResponse(content=payload)

        # Streaming fake-out. We have to emit OpenAI-shaped SSE chunks that
        # the client (e.g. opensquilla) can parse losslessly. Two important
        # requirements the upstream's full-message response doesn't satisfy:
        #   1. Each `delta.tool_calls[i]` MUST carry an `index` field
        #      (clients use it to merge partial deltas across chunks).
        #   2. Tool calls come AFTER any text content, one chunk per call,
        #      followed by an empty-delta final chunk carrying finish_reason.
        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        message = first.get("message") or {"role": "assistant", "content": ""}
        text_content = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []
        has_tool_calls = bool(tool_calls)
        finish_reason = (
            first.get("finish_reason")
            or ("tool_calls" if has_tool_calls else "stop")
        )
        chunk_id = payload.get("id") or f"chatcmpl-{trace_id}"
        chunk_created = payload.get("created") or int(time.time())
        chunk_model = payload.get("model") or req.model
        choice_index = first.get("index", 0)

        async def _sse() -> AsyncIterator[bytes]:
            # 1) Role + any text content (only if both are non-empty).
            if text_content:
                yield f"data: {json.dumps({
                    'id': chunk_id,
                    'object': 'chat.completion.chunk',
                    'created': chunk_created,
                    'model': chunk_model,
                    'choices': [{
                        'index': choice_index,
                        'delta': {'role': 'assistant', 'content': text_content},
                        'finish_reason': None,
                    }],
                }, ensure_ascii=False)}\n\n".encode("utf-8")
            elif not has_tool_calls:
                # Plain text completion: collapse to a single chunk.
                yield f"data: {json.dumps({
                    'id': chunk_id,
                    'object': 'chat.completion.chunk',
                    'created': chunk_created,
                    'model': chunk_model,
                    'choices': [{
                        'index': choice_index,
                        'delta': message,
                        'finish_reason': finish_reason,
                    }],
                }, ensure_ascii=False)}\n\n".encode("utf-8")

            # 2) One chunk per tool call, each carrying its `index`.
            for i, tc in enumerate(tool_calls):
                # Normalize: OpenAI streaming-delta tool_call has
                # {index, id, type, function: {name, arguments}} with all
                # fields present. The upstream message-form has id/type at
                # top level, so we keep both shapes compatible.
                delta_tc = {
                    "index": i,
                    "id": tc.get("id") or f"call_{i}",
                    "type": tc.get("type") or "function",
                    "function": {
                        "name": (tc.get("function") or {}).get("name") or "",
                        "arguments": (tc.get("function") or {}).get("arguments") or "",
                    },
                }
                yield f"data: {json.dumps({
                    'id': chunk_id,
                    'object': 'chat.completion.chunk',
                    'created': chunk_created,
                    'model': chunk_model,
                    'choices': [{
                        'index': choice_index,
                        'delta': {'tool_calls': [delta_tc]},
                        'finish_reason': None,
                    }],
                }, ensure_ascii=False)}\n\n".encode("utf-8")

            # 3) Final chunk: empty delta, finish_reason set.
            if has_tool_calls or text_content:
                yield f"data: {json.dumps({
                    'id': chunk_id,
                    'object': 'chat.completion.chunk',
                    'created': chunk_created,
                    'model': chunk_model,
                    'choices': [{
                        'index': choice_index,
                        'delta': {},
                        'finish_reason': finish_reason,
                    }],
                }, ensure_ascii=False)}\n\n".encode("utf-8")

            yield b"data: [DONE]\n\n"

        return StreamingResponse(_sse(), media_type="text/event-stream")

    @app.post("/v1/completions", dependencies=[Depends(require_auth)])
    async def openai_completions(req: CompletionRequest) -> Any:
        chat = ChatRequest(
            model=req.model,
            messages=[ChatMessage(role="user", content=req.prompt)],
            max_tokens=req.max_tokens,
            temperature=req.temperature,
            top_p=req.top_p,
            seed=req.seed,
            stop=req.stop,
            stream=req.stream,
        )
        return await openai_chat_completions(chat)


# ════════════════════════════════════════════════════════════════════════════
# OpenAI Responses API  (/v1/responses)  — the NEW native OpenAI protocol
# ════════════════════════════════════════════════════════════════════════════
#
# Different from Chat Completions. opensquilla's `OpenAIResponsesProvider`
# (provider_kind="openai_responses") hits this endpoint, NOT chat/completions.
# Response shape uses `output: [{type, ...}]` with item types "message" and
# "function_call" rather than `choices: [{message: {tool_calls: []}}]`.
#
# We translate Responses <-> canonical Chat Completions and reuse the same
# upstream call as everywhere else.
#
# Non-streaming only (Responses streaming events are NOT yet wired — the
# opensquilla client sends Accept: application/json, so this is enough for now).

if ENABLE_OPENAI_RESPONSES:

    def _responses_to_oai(body: dict[str, Any]) -> ChatRequest:
        """OpenAI Responses API request -> canonical Chat Completions shape.

        Translation:
            instructions                  -> system message
            input[].message               -> user/assistant message
            input[].function_call         -> assistant message w/ tool_calls
            input[].function_call_output  -> role=tool message w/ tool_call_id
            max_output_tokens             -> max_tokens
            tools[].parameters            -> tools[].function.parameters
        """
        msgs: list[ChatMessage] = []

        # 1) `instructions` (system prompt) -> system message
        if body.get("instructions"):
            msgs.append(
                ChatMessage(role="system", content=body["instructions"])
            )

        # 2) `input` items
        for item in body.get("input", []):
            if not isinstance(item, dict):
                continue
            itype = item.get("type")

            if itype == "function_call":
                # Assistant tool call in conversation history
                call_id = item.get("call_id") or f"call_{uuid.uuid4().hex[:24]}"
                tcall = {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": item.get("name", ""),
                        "arguments": item.get("arguments", ""),
                    },
                }
                cm = ChatMessage(
                    role="assistant", content=None, name=item.get("name")
                )
                cm = _msg_with_tool_calls(cm, [tcall])
                msgs.append(cm)

            elif itype == "function_call_output":
                # Tool result message
                call_id = item.get("call_id") or ""
                msgs.append(
                    ChatMessage(
                        role="tool",
                        content=item.get("output", ""),
                        name=call_id,
                        tool_call_id=call_id,
                    )
                )

            elif itype == "message" or "role" in item:
                # Message item: text-only or typed parts
                role = item.get("role", "user")
                content = item.get("content", "")
                if isinstance(content, list):
                    parts: list[dict[str, Any]] = []
                    for p in content:
                        ptype = p.get("type")
                        if ptype in ("input_text", "output_text", "text"):
                            parts.append(
                                {"type": "text", "text": p.get("text", "")}
                            )
                        elif ptype in ("input_image", "image_url"):
                            url = p.get("image_url") or ""
                            if isinstance(url, dict):
                                url = url.get("url", "")
                            parts.append(
                                {
                                    "type": "image_url",
                                    "image_url": {"url": url},
                                }
                            )
                        elif ptype in ("input_image_base64",):
                            parts.append(
                                {
                                    "type": "image_url",
                                    "image_url": {
                                        "url": (
                                            f"data:{p.get('media_type', 'image/png')};"
                                            f"base64,{p.get('data', '')}"
                                        )
                                    },
                                }
                            )
                    content = parts
                msgs.append(ChatMessage(role=role, content=content))

        # 3) tools -> OAI function shape
        oai_tools: Optional[list[dict[str, Any]]] = None
        for t in body.get("tools") or []:
            oai_tools = oai_tools or []
            oai_tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.get("name"),
                        "description": t.get("description", ""),
                        "parameters": t.get(
                            "parameters", {"type": "object", "properties": {}}
                        ),
                    },
                }
            )

        # 4) tool_choice passes through unchanged (Responses uses OAI shape).
        # 5) top_k, parallel_tool_calls, etc. are dropped (not representable
        #    in canonical Chat Completions). Add as needed.

        return ChatRequest(
            model=body.get("model") or DEFAULT_STD_MODEL,
            messages=msgs,
            max_tokens=body.get("max_output_tokens"),
            temperature=body.get("temperature"),
            top_p=body.get("top_p"),
            stop=body.get("stop") or body.get("stop_sequences"),
            stream=bool(body.get("stream")),
            tools=oai_tools,
            tool_choice=body.get("tool_choice"),
        )

    def _oai_to_responses(
        payload: dict[str, Any], req_model: str
    ) -> dict[str, Any]:
        """Upstream Chat Completions payload -> Responses API output[].

        Chat Completions `choices[0].message` becomes:
            - output[] message item      (text content)
            - output[] function_call item (one per tool_call)
        """
        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        msg = first.get("message") or {}
        oai_finish = first.get("finish_reason") or "stop"

        # status mapping: Responses uses "completed" | "incomplete" | ...
        status = "incomplete" if oai_finish == "length" else "completed"

        output: list[dict[str, Any]] = []

        # 1) Text content -> message item
        text = msg.get("content")
        if text:
            if isinstance(text, str):
                output.append(
                    {
                        "type": "message",
                        "role": "assistant",
                        "status": status,
                        "content": [
                            {"type": "output_text", "text": text, "annotations": []}
                        ],
                    }
                )
            elif isinstance(text, list):
                text_str = "".join(
                    p.get("text", "")
                    for p in text
                    if p.get("type") == "text"
                )
                if text_str:
                    output.append(
                        {
                            "type": "message",
                            "role": "assistant",
                            "status": status,
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": text_str,
                                    "annotations": [],
                                }
                            ],
                        }
                    )

        # 2) Tool calls -> function_call items
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            output.append(
                {
                    "type": "function_call",
                    "call_id": tc.get("id")
                    or f"call_{uuid.uuid4().hex[:24]}",
                    "name": fn.get("name") or "",
                    "arguments": fn.get("arguments") or "",
                    "status": status,
                }
            )

        # 3) usage -> Responses shape
        usage = payload.get("usage") or {}
        out_usage = {
            "input_tokens": usage.get("prompt_tokens", 0),
            "input_tokens_details": {
                "cached_tokens": usage.get("cached_tokens", 0)
            },
            "output_tokens": usage.get("completion_tokens", 0),
            "output_tokens_details": {
                "reasoning_tokens": usage.get("reasoning_tokens", 0)
            },
            "total_tokens": usage.get(
                "total_tokens",
                usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0),
            ),
        }

        return {
            "id": payload.get("id") or f"resp_{uuid.uuid4().hex[:24]}",
            "object": "response",
            "created_at": int(time.time()),
            "status": status,
            "model": payload.get("model") or req_model,
            "output": output,
            "usage": out_usage,
        }

    @app.post("/v1/responses", dependencies=[Depends(require_auth)])
    async def openai_responses_endpoint(request: Request) -> Any:
        body = await request.json()
        req = _responses_to_oai(body)
        trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex
        status, payload, _ = await _call_upstream_oai(req, trace_id)
        if status >= 400:
            return JSONResponse(
                status_code=status,
                content={
                    "error": {
                        "message": payload.get("_raw_text") or payload.get("_message", ""),
                        "type": "upstream_error",
                        "code": str(status),
                    }
                },
            )
        return JSONResponse(content=_oai_to_responses(payload, req.model))


# ════════════════════════════════════════════════════════════════════════════
# Anthropic Messages API  (/v1/messages)
# ════════════════════════════════════════════════════════════════════════════

if ENABLE_ANTHROPIC:

    def _anthropic_block_to_oai_parts(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert Anthropic content blocks (text/image) to OAI content parts.

        tool_use and tool_result blocks are NOT handled here; the caller
        splits them out as separate messages so the OAI representation
        stays semantically clean (assistant w/ tool_calls and role=tool).
        """
        parts: list[dict[str, Any]] = []
        for b in blocks:
            btype = b.get("type")
            if btype == "text":
                parts.append({"type": "text", "text": b.get("text", "")})
            elif btype == "image":
                # Anthropic image: {"type": "image", "source": {"type": "base64", "media_type": "...", "data": "..."}}
                # or {"type": "url", "url": "..."}
                src = b.get("source") or {}
                if src.get("type") == "base64":
                    mt = src.get("media_type", "image/png")
                    data = src.get("data", "")
                    parts.append(
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{mt};base64,{data}"},
                        }
                    )
                elif src.get("type") == "url":
                    parts.append(
                        {
                            "type": "image_url",
                            "image_url": {"url": src.get("url", "")},
                        }
                    )
                # unknown image source -> dropped
            elif btype == "document":
                # PDFs etc. - drop, OAI multimodal support is image-only.
                pass
            elif btype in ("thinking", "redacted_thinking"):
                # Internal chain-of-thought; not representable in OAI.
                # The Anthropic-side caller asked for it; we drop here.
                pass
            # tool_use / tool_result handled by caller
        return parts

    def _anthropic_to_oai(body: dict[str, Any]) -> ChatRequest:
        """Convert an Anthropic Messages request to canonical OpenAI shape.

        Lossless on content:
            * text / image blocks  -> OAI content parts (text, image_url)
            * tool_use blocks      -> assistant message with tool_calls
            * tool_result blocks   -> role=tool message
            * thinking blocks      -> dropped (no OAI equivalent)
        Lossless on tools/tool_choice via the OAI function-calling shape.
        """
        msgs: list[ChatMessage] = []
        sys = body.get("system")
        if sys:
            if isinstance(sys, list):
                sys = "\n".join(
                    b.get("text", "") for b in sys if b.get("type") == "text"
                )
            msgs.append(ChatMessage(role="system", content=sys))

        for m in body.get("messages", []):
            role = m.get("role")
            content = m.get("content")

            if isinstance(content, str) or content is None:
                msgs.append(ChatMessage(role=role, content=content or ""))
                continue

            if not isinstance(content, list):
                msgs.append(ChatMessage(role=role, content=str(content)))
                continue

            # Split content blocks: media/text parts vs tool_* blocks.
            media_parts = _anthropic_block_to_oai_parts(
                [b for b in content if b.get("type") in ("text", "image", "document")]
            )
            tool_uses = [b for b in content if b.get("type") == "tool_use"]
            tool_results = [b for b in content if b.get("type") == "tool_result"]

            # 1) Carry any media/text content (may be empty if this message
            #    is purely tool_use / tool_result).
            if media_parts:
                msgs.append(ChatMessage(role=role, content=media_parts))
            elif not tool_uses and not tool_results:
                # Pure text list with no recognized blocks: keep as empty str
                msgs.append(ChatMessage(role=role, content=""))

            # 2) tool_use -> assistant message with tool_calls
            for tu in tool_uses:
                tcall = {
                    "id": tu.get("id") or f"toolu_{uuid.uuid4().hex[:24]}",
                    "type": "function",
                    "function": {
                        "name": tu.get("name", ""),
                        "arguments": json.dumps(tu.get("input") or {}),
                    },
                }
                msgs.append(
                    ChatMessage(
                        role="assistant",
                        content=None,  # OAI: null content when tool_calls present
                        name=tu.get("name"),
                    )
                )
                # Attach tool_calls via the raw dict path (Pydantic model needs
                # to allow extra; we do this by writing a small "tool_calls"
                # shim in the body builder).
                # Simpler: we stash tool_calls in the message's `name` field as
                # a JSON envelope - NO, that's lossy. Use the extra field:
                # replace last message with one that carries tool_calls.
                # (Pydantic BaseModel here doesn't allow extra; we patch below.)
                msgs[-1] = _msg_with_tool_calls(msgs[-1], [tcall])

            # 3) tool_result -> role=tool message
            for tr in tool_results:
                tr_content = tr.get("content")
                if isinstance(tr_content, list):
                    tr_content = "\n".join(
                        b.get("text", "")
                        for b in tr_content
                        if b.get("type") == "text"
                    )
                msgs.append(
                    ChatMessage(
                        role="tool",
                        content=tr_content or "",
                        name=tr.get("tool_use_id"),  # also exposed as `name`
                        tool_call_id=tr.get("tool_use_id"),
                    )
                )

        # Tools: convert Anthropic input_schema -> OpenAI function.parameters.
        oai_tools: Optional[list[dict[str, Any]]] = None
        for t in body.get("tools", []) or []:
            oai_tools = oai_tools or []
            oai_tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.get("name"),
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                    },
                }
            )

        # tool_choice mapping:
        #   "auto" / None                       -> "auto"
        #   {"type": "any"}                     -> "required"
        #   {"type": "tool", "name": "X"}       -> {"type": "function", "function": {"name": "X"}}
        #   {"type": "none"}                    -> "none"
        oai_tool_choice: Optional[Any] = body.get("tool_choice")
        if isinstance(oai_tool_choice, dict):
            t = oai_tool_choice.get("type")
            if t == "tool":
                name = oai_tool_choice.get("name")
                oai_tool_choice = (
                    {"type": "function", "function": {"name": name}} if name else "auto"
                )
            elif t == "any":
                oai_tool_choice = "required"
            elif t == "none":
                oai_tool_choice = "none"
            elif t == "auto":
                oai_tool_choice = "auto"

        return ChatRequest(
            model=body.get("model") or DEFAULT_STD_MODEL,
            messages=msgs,
            max_tokens=body.get("max_tokens"),
            temperature=body.get("temperature"),
            top_p=body.get("top_p"),
            stop=body.get("stop_sequences"),
            stream=bool(body.get("stream")),
            tools=oai_tools,
            tool_choice=oai_tool_choice,
        )

    def _oai_to_anthropic_message(
        payload: dict[str, Any], req_model: str
    ) -> dict[str, Any]:
        """Convert an OpenAI chat.completion payload to an Anthropic message."""
        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        msg = first.get("message") or {}
        oai_finish = first.get("finish_reason") or "stop"
        # OpenAI -> Anthropic stop_reason mapping
        stop_reason_map = {
            "stop": "end_turn",
            "length": "max_tokens",
            "tool_calls": "tool_use",
            "content_filter": "end_turn",  # Anthropic has no exact equivalent
        }
        stop_reason = stop_reason_map.get(oai_finish, "end_turn")

        # Build Anthropic content blocks from the OpenAI message
        content_blocks: list[dict[str, Any]] = []
        text = msg.get("content")
        # OAI assistant content can be a string OR a list of multimodal parts.
        if isinstance(text, str):
            if text:
                content_blocks.append({"type": "text", "text": text})
        elif isinstance(text, list):
            for part in text:
                ptype = part.get("type")
                if ptype == "text":
                    content_blocks.append({"type": "text", "text": part.get("text", "")})
                elif ptype == "image_url":
                    url = (part.get("image_url") or {}).get("url", "")
                    if url.startswith("data:") and ";base64," in url:
                        mt, data = url.split(";base64,", 1)
                        mt = mt[len("data:"):]
                        content_blocks.append(
                            {
                                "type": "image",
                                "source": {"type": "base64", "media_type": mt, "data": data},
                            }
                        )
                    elif url:
                        content_blocks.append(
                            {"type": "image", "source": {"type": "url", "url": url}}
                        )
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            try:
                inp = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                inp = {"_raw": fn.get("arguments")}
            content_blocks.append(
                {
                    "type": "tool_use",
                    "id": tc.get("id") or f"toolu_{uuid.uuid4().hex[:24]}",
                    "name": fn.get("name") or "",
                    "input": inp,
                }
            )

        # Token usage
        usage = payload.get("usage") or {}
        in_t = usage.get("prompt_tokens", 0)
        out_t = usage.get("completion_tokens", 0)

        return {
            "id": payload.get("id") or f"msg_{uuid.uuid4().hex[:24]}",
            "type": "message",
            "role": "assistant",
            "model": payload.get("model") or req_model,
            "content": content_blocks or [{"type": "text", "text": ""}],
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": {
                "input_tokens": in_t,
                "output_tokens": out_t,
            },
        }

    async def _oai_to_anthropic_stream(
        payload: dict[str, Any], req_model: str, trace_id: str
    ) -> AsyncIterator[bytes]:
        """Build the Anthropic SSE event sequence for a single (fake) chunk.

        Anthropic streaming sequence (simplified):
            event: message_start
            data: {"message": {...initial message with empty content...}}

            event: content_block_start
            data: {"index": 0, "content_block": {"type": "text", "text": ""}}

            event: content_block_delta
            data: {"index": 0, "delta": {"type": "text_delta", "text": "..."}}

            event: content_block_stop
            data: {"index": 0}

            event: message_delta
            data: {"delta": {"stop_reason": "end_turn"}}

            event: message_stop
            data: {}
        """
        msg = _oai_to_anthropic_message(payload, req_model)
        msg_id = msg["id"]
        model = msg["model"]
        blocks = msg["content"]

        def sse(event: str, data: dict[str, Any]) -> bytes:
            return (
                f"event: {event}\n"
                f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            ).encode("utf-8")

        # message_start with empty content, real id/model/usage
        initial_message = {
            "id": msg_id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": msg["usage"]["input_tokens"], "output_tokens": 0},
        }
        yield sse("message_start", {"type": "message_start", "message": initial_message})

        for i, blk in enumerate(blocks):
            btype = blk.get("type")
            yield sse(
                "content_block_start",
                {"type": "content_block_start", "index": i, "content_block": blk if btype != "tool_use" else {"type": "tool_use", "id": blk.get("id"), "name": blk.get("name"), "input": {}}},
            )
            if btype == "text":
                yield sse(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": i,
                        "delta": {"type": "text_delta", "text": blk.get("text", "")},
                    },
                )
            elif btype == "tool_use":
                yield sse(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": i,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps(blk.get("input") or {}),
                        },
                    },
                )
            yield sse("content_block_stop", {"type": "content_block_stop", "index": i})

        yield sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": msg["stop_reason"], "stop_sequence": None},
                "usage": {"output_tokens": msg["usage"]["output_tokens"]},
            },
        )
        yield sse("message_stop", {"type": "message_stop"})

    @app.post("/v1/messages", dependencies=[Depends(require_auth)])
    async def anthropic_messages(request: Request) -> Any:
        body = await request.json()
        # Anthropic requires max_tokens; default if missing.
        if "max_tokens" not in body:
            body["max_tokens"] = 1024
        req = _anthropic_to_oai(body)
        trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex
        status, payload, _ = await _call_upstream_oai(req, trace_id)
        if status >= 400:
            return JSONResponse(
                status_code=status,
                content={
                    "type": "error",
                    "error": {
                        "type": "upstream_error",
                        "message": payload.get("_raw_text") or payload.get("_message", ""),
                    },
                },
            )
        if not req.stream:
            return JSONResponse(content=_oai_to_anthropic_message(payload, req.model))

        async def _sse() -> AsyncIterator[bytes]:
            async for chunk in _oai_to_anthropic_stream(payload, req.model, trace_id):
                yield chunk

        return StreamingResponse(_sse(), media_type="text/event-stream")


# ════════════════════════════════════════════════════════════════════════════
# Ollama native  (/api/chat, /api/generate, /api/tags)
# ════════════════════════════════════════════════════════════════════════════

if ENABLE_OLLAMA:

    def _ollama_chat_to_oai(body: dict[str, Any]) -> ChatRequest:
        """Ollama /api/chat -> canonical OpenAI shape (lossless on request).

        Translation:
            * messages[].images  (list[base64]) -> OAI image_url content parts
            * messages[].tool_calls (Ollama 0.5+) -> passthrough on assistant
            * options            (Ollama sampling dict) -> flat OAI params
            * format             ("json" | json-schema)  -> OAI response_format
            * tools              (Ollama 0.5+, OAI-shaped) -> passthrough
            * keep_alive / raw   -> dropped (model lifecycle / flag, not request data)
        """
        opts = body.get("options") or {}

        msgs: list[ChatMessage] = []
        for m in body.get("messages", []):
            role = m.get("role", "user")
            text = m.get("content", "") or ""
            images = m.get("images") or []

            content: Any = text
            if images:
                parts: list[dict[str, Any]] = []
                if text:
                    parts.append({"type": "text", "text": text})
                for img in images:
                    # Ollama: each image is a base64 string (no media_type).
                    # We default to image/png; the upstream can sniff if needed.
                    if isinstance(img, str):
                        parts.append(
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/png;base64,{img}"},
                            }
                        )
                    elif isinstance(img, dict) and "data" in img:
                        mt = img.get("media_type", "image/png")
                        parts.append(
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:{mt};base64,{img['data']}"},
                            }
                        )
                content = parts

            cm = ChatMessage(role=role, content=content, name=m.get("name"))
            if m.get("tool_calls"):
                cm = _msg_with_tool_calls(cm, m["tool_calls"])
            msgs.append(cm)

        # response_format: Ollama `format` -> OAI `response_format`
        oai_response_format: Optional[dict[str, Any]] = None
        fmt = body.get("format")
        if fmt == "json":
            oai_response_format = {"type": "json_object"}
        elif isinstance(fmt, dict):
            oai_response_format = {"type": "json_schema", "json_schema": fmt}

        # Tools: Ollama 0.5+ uses the OAI shape directly; passthrough.
        oai_tools = body.get("tools")

        return ChatRequest(
            model=body.get("model") or DEFAULT_STD_MODEL,
            messages=msgs,
            max_tokens=opts.get("num_predict"),
            temperature=opts.get("temperature"),
            top_p=opts.get("top_p"),
            seed=opts.get("seed"),
            stop=opts.get("stop"),
            stream=bool(body.get("stream")),
            tools=oai_tools,
            tool_choice=body.get("tool_choice"),
            response_format=oai_response_format,
        )

    def _oai_to_ollama_chat(
        payload: dict[str, Any], req_model: str
    ) -> dict[str, Any]:
        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        msg = first.get("message") or {}
        oai_finish = first.get("finish_reason") or "stop"
        done_reason = "length" if oai_finish == "length" else "stop"
        usage = payload.get("usage") or {}
        return {
            "model": payload.get("model") or req_model,
            "created_at": time.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()
            ),
            "message": {"role": "assistant", "content": msg.get("content") or ""},
            "done_reason": done_reason,
            "done": True,
            "total_duration": 0,
            "load_duration": 0,
            "prompt_eval_count": usage.get("prompt_tokens", 0),
            "eval_count": usage.get("completion_tokens", 0),
            "eval_duration": 0,
        }

    def _oai_to_ollama_stream_chunk(
        payload: dict[str, Any], req_model: str, done: bool
    ) -> dict[str, Any]:
        """One NDJSON line for Ollama's streaming response."""
        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        msg = first.get("message") or {}
        out: dict[str, Any] = {
            "model": payload.get("model") or req_model,
            "created_at": time.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()
            ),
            "message": {"role": "assistant", "content": msg.get("content") or ""},
        }
        if done:
            oai_finish = first.get("finish_reason") or "stop"
            usage = payload.get("usage") or {}
            out["done_reason"] = "length" if oai_finish == "length" else "stop"
            out["done"] = True
            out["total_duration"] = 0
            out["prompt_eval_count"] = usage.get("prompt_tokens", 0)
            out["eval_count"] = usage.get("completion_tokens", 0)
        else:
            out["done"] = False
        return out

    @app.post("/api/chat", dependencies=[Depends(require_auth)])
    async def ollama_chat(request: Request) -> Any:
        body = await request.json()
        req = _ollama_chat_to_oai(body)
        trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex
        status, payload, _ = await _call_upstream_oai(req, trace_id)
        if status >= 400:
            return JSONResponse(
                status_code=status, content={"error": payload.get("_raw_text") or payload.get("_message", "")}
            )
        if not req.stream:
            return JSONResponse(content=_oai_to_ollama_chat(payload, req.model))

        # NDJSON streaming: emit one intermediate "done: false" line, then
        # the final "done: true" line. Clients expect NDJSON, not SSE.
        async def _ndjson() -> AsyncIterator[bytes]:
            mid = _oai_to_ollama_stream_chunk(payload, req.model, done=False)
            yield (json.dumps(mid, ensure_ascii=False) + "\n").encode("utf-8")
            fin = _oai_to_ollama_stream_chunk(payload, req.model, done=True)
            yield (json.dumps(fin, ensure_ascii=False) + "\n").encode("utf-8")

        return StreamingResponse(_ndjson(), media_type="application/x-ndjson")

    @app.post("/api/generate", dependencies=[Depends(require_auth)])
    async def ollama_generate(request: Request) -> Any:
        """Single-prompt variant: convert to a one-message chat request."""
        body = await request.json()
        prompt = body.get("prompt") or ""
        opts = body.get("options") or {}
        req = ChatRequest(
            model=body.get("model") or DEFAULT_STD_MODEL,
            messages=[ChatMessage(role="user", content=prompt)],
            max_tokens=opts.get("num_predict"),
            temperature=opts.get("temperature"),
            top_p=opts.get("top_p"),
            seed=opts.get("seed"),
            stop=opts.get("stop"),
            stream=bool(body.get("stream")),
        )
        trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex
        status, payload, _ = await _call_upstream_oai(req, trace_id)
        if status >= 400:
            return JSONResponse(
                status_code=status, content={"error": payload.get("_raw_text") or payload.get("_message", "")}
            )

        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        msg = first.get("message") or {}
        oai_finish = first.get("finish_reason") or "stop"
        usage = payload.get("usage") or {}
        base = {
            "model": payload.get("model") or req.model,
            "created_at": time.strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()
            ),
            "response": msg.get("content") or "",
            "done_reason": "length" if oai_finish == "length" else "stop",
            "done": True,
            "total_duration": 0,
            "prompt_eval_count": usage.get("prompt_tokens", 0),
            "eval_count": usage.get("completion_tokens", 0),
        }
        if not req.stream:
            return JSONResponse(content=base)

        async def _ndjson() -> AsyncIterator[bytes]:
            mid = {**base, "response": "", "done": False}
            yield (json.dumps(mid, ensure_ascii=False) + "\n").encode("utf-8")
            yield (json.dumps(base, ensure_ascii=False) + "\n").encode("utf-8")

        return StreamingResponse(_ndjson(), media_type="application/x-ndjson")

    @app.get("/api/tags", dependencies=[Depends(require_auth)])
    async def ollama_tags() -> JSONResponse:
        now = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
        seen: set[str] = set()
        models: list[dict[str, Any]] = []
        for mid in (DEFAULT_STD_MODEL, *MODEL_ROUTES.keys()):
            if mid in seen:
                continue
            seen.add(mid)
            models.append(
                {
                    "name": mid,
                    "model": mid,
                    "modified_at": now,
                    "size": 0,
                    "digest": "sha256:gatewaycompat",
                    "details": {
                        "format": "gguf",
                        "family": "qwen",
                        "parameter_size": "?",
                        "quantization_level": "?",
                    },
                }
            )
        return JSONResponse({"models": models})


# ════════════════════════════════════════════════════════════════════════════
# llama.cpp native  (/completion)
# ════════════════════════════════════════════════════════════════════════════

if ENABLE_LLAMACPP:

    def _llamacpp_to_oai(body: dict[str, Any]) -> ChatRequest:
        """llama.cpp /completion -> canonical OpenAI shape (lossless on prompt).

        llama.cpp takes a single `prompt` string. We auto-detect common chat
        templates and parse them into messages; if none match, the whole
        prompt is carried as a single user message (still lossless on
        content, just loses role structure).

        Supported templates:
            * ChatML       (Qwen, Yi, OpenChat)        <|im_start|>/<|im_end|>
            * Llama-3      (Meta Llama 3/3.1/3.2)      <|start_header_id|>/<|end_header_id|>
            * Mistral      (Mistral Instruct)          [INST] ... [/INST]
            * Alpaca       (Stanford Alpaca)           ### Instruction:/### Response:
            * Phi-3        (Microsoft Phi)             <|user|>/<|assistant|>/<|system|>
        """
        import re
        prompt: str = body.get("prompt") or ""
        msgs: list[ChatMessage] = []

        # 1) ChatML
        if "<|im_start|>" in prompt:
            for m in re.finditer(
                r"<\|im_start\|>(\w+)\n(.*?)<\|im_end\|>", prompt, re.DOTALL
            ):
                role = m.group(1)
                if role in ("system", "user", "assistant"):
                    msgs.append(ChatMessage(role=role, content=m.group(2)))

        # 2) Llama-3
        if not msgs and "<|start_header_id|>" in prompt:
            for m in re.finditer(
                r"<\|start_header_id\|>(\w+)<\|end_header_id\|>\n(.*?)<\|eot_id\|>",
                prompt,
                re.DOTALL,
            ):
                role = m.group(1)
                if role in ("system", "user", "assistant"):
                    msgs.append(ChatMessage(role=role, content=m.group(2)))

        # 3) Mistral [INST] ... [/INST]
        if not msgs and "[INST]" in prompt:
            # Mistral typically has no system; just user/assistant pairs.
            chunks = re.split(r"\[/?INST\]", prompt)
            # chunks pattern: ['preamble', ' user ', ' assistant ', ' user ', ...]
            i = 0
            # The first chunk is the system preamble (optional).
            if chunks and chunks[0].strip():
                msgs.append(ChatMessage(role="system", content=chunks[0].strip()))
                i = 1
            # Then alternating user/assistant.
            role = "user"
            for c in chunks[i:]:
                if c.strip():
                    msgs.append(ChatMessage(role=role, content=c.strip()))
                    role = "assistant" if role == "user" else "user"

        # 4) Alpaca
        if not msgs and "### Instruction:" in prompt:
            for blk in re.split(r"\n### (?:Instruction|Response|Input):\n", prompt):
                blk = blk.strip()
                if not blk:
                    continue
                # First block is implicit Instruction; we map:
                #   "Instruction: foo" -> user, "Response: foo" -> assistant
                # Since we stripped the prefix, we infer from the section
                # using a 2nd pass.
            # Re-parse with prefix context:
            msgs = []
            cur_role: Optional[str] = None
            for line in prompt.splitlines():
                if line.startswith("### Instruction:"):
                    cur_role = "user"
                    msgs.append(
                        ChatMessage(role="user", content=line[len("### Instruction:"):].strip())
                    )
                elif line.startswith("### Response:"):
                    cur_role = "assistant"
                    msgs.append(
                        ChatMessage(role="assistant", content=line[len("### Response:"):].strip())
                    )
                elif line.startswith("### Input:"):
                    # extra context, attach to last user
                    if msgs and msgs[-1].role == "user":
                        msgs[-1] = msgs[-1].model_copy(
                            update={"content": msgs[-1].content + "\n" + line[len("### Input:"):].strip()}
                        )
                elif cur_role:
                    msgs[-1] = msgs[-1].model_copy(
                        update={"content": msgs[-1].content + "\n" + line}
                    )

        # 5) Phi-3
        if not msgs and "<|user|>" in prompt:
            for m in re.finditer(
                r"<\|(system|user|assistant)\|>\s*(.*?)(?=<\|(?:endoftext|user|assistant|system)\|>|$)",
                prompt,
                re.DOTALL,
            ):
                role = m.group(1)
                if role in ("system", "user", "assistant"):
                    msgs.append(ChatMessage(role=role, content=m.group(2).strip()))

        # Strip trailing empty assistant placeholder (chat templates commonly
        # end with `<|role|>\n` waiting for the model to fill in). OAI doesn't
        # need a sentinel like that.
        while msgs and msgs[-1].role == "assistant" and not (msgs[-1].content or "").strip():
            msgs.pop()

        # Fallback: keep whole prompt as a single user message.
        if not msgs:
            msgs = [ChatMessage(role="user", content=prompt)]

        # llama.cpp sampling: n_predict, top_k, repeat_penalty, etc. OAI only
        # supports a subset. We forward what's mappable.
        return ChatRequest(
            model=body.get("model") or DEFAULT_STD_MODEL,
            messages=msgs,
            max_tokens=body.get("n_predict"),
            temperature=body.get("temperature"),
            top_p=body.get("top_p"),
            seed=body.get("seed"),
            stop=body.get("stop"),
            stream=bool(body.get("stream")),
        )

    def _oai_to_llamacpp_completion(
        payload: dict[str, Any], req_model: str
    ) -> dict[str, Any]:
        choices = payload.get("choices") or [{}]
        first = choices[0] if choices else {}
        msg = first.get("message") or {}
        oai_finish = first.get("finish_reason") or "stop"
        # llama.cpp `stop` is a bool: true when the model emitted a stop token
        stop = oai_finish == "stop"
        usage = payload.get("usage") or {}
        return {
            "content": msg.get("content") or "",
            "id": payload.get("id") or f"cmpl-{uuid.uuid4().hex[:24]}",
            "model": payload.get("model") or req_model,
            "created": payload.get("created") or int(time.time()),
            "object": "text_completion",
            "stop": stop,
            "stop_type": oai_finish,
            "tokens_predicted": usage.get("completion_tokens", 0),
            "tokens_evaluated": usage.get("prompt_tokens", 0),
            "truncation": False,
        }

    @app.post("/completion", dependencies=[Depends(require_auth)])
    async def llamacpp_completion(request: Request) -> Any:
        body = await request.json()
        req = _llamacpp_to_oai(body)
        trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex
        status, payload, _ = await _call_upstream_oai(req, trace_id)
        if status >= 400:
            return JSONResponse(
                status_code=status,
                content={
                    "content": "",
                    "stop": True,
                    "stop_type": "upstream_error",
                    "error": payload.get("_raw_text") or payload.get("_message", ""),
                },
            )
        if not req.stream:
            return JSONResponse(content=_oai_to_llamacpp_completion(payload, req.model))

        # llama.cpp streams `data: {...}\n\n` SSE with `content` and `stop`
        base = _oai_to_llamacpp_completion(payload, req.model)
        async def _sse() -> AsyncIterator[bytes]:
            mid = {**base, "content": base["content"], "stop": False}
            yield f"data: {json.dumps(mid, ensure_ascii=False)}\n\n".encode("utf-8")
            yield f"data: {json.dumps(base, ensure_ascii=False)}\n\n".encode("utf-8")
            yield b"data: [DONE]\n\n"
        return StreamingResponse(_sse(), media_type="text/event-stream")


# ─── Main ─────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[gateway-compat] listen  http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[gateway-compat] backend {BACKEND_BASE}")
    print(
        f"[gateway-compat] default route: {DEFAULT_ROUTE} "
        f"(std model: {DEFAULT_STD_MODEL!r})"
    )
    if MODEL_ROUTES:
        print(f"[gateway-compat] extra routes: {list(MODEL_ROUTES.keys())}")
    enabled = []
    if ENABLE_OPENAI:
        enabled.append("openai(/v1/chat/completions,/v1/completions,/v1/models)")
    if ENABLE_OPENAI_RESPONSES:
        enabled.append("openai_responses(/v1/responses)")
    if ENABLE_ANTHROPIC:
        enabled.append("anthropic(/v1/messages)")
    if ENABLE_OLLAMA:
        enabled.append("ollama(/api/chat,/api/generate,/api/tags)")
    if ENABLE_LLAMACPP:
        enabled.append("llamacpp(/completion)")
    print(f"[gateway-compat] enabled protocols: {', '.join(enabled)}")
    if BACKEND_INSECURE:
        print("[gateway-compat] WARN: TLS verification disabled for backend")
    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT, log_level="info")


if __name__ == "__main__":
    main()
