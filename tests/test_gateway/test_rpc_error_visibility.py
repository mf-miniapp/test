"""When the browser's WebSocket fails to establish, the user must be
able to tell.  These tests pin the wiring that:

  * ``RpcClient._ws.onerror`` is no longer a silent no-op — it logs
    the failure and emits an ``_error`` event with the URL we tried.
  * ``App._autoConnect`` logs the URL and a masked token so a stuck
    DISCONNECTED pill is easy to diagnose from devtools.
  * ``App._bindConnectionState`` listens for ``_error`` and after 3
    failures upgrades the pill's ``title`` to a clear "WebSocket
    unreachable" hint with the URL that was tried.
"""
from __future__ import annotations

import re
from pathlib import Path

RPC_JS = Path("src/opensquilla/gateway/static/js/rpc.js")
APP_JS = Path("src/opensquilla/gateway/static/js/app.js")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function(source: str, name: str) -> str:
    """Return the body of ``function NAME(...) { ... }`` from a JS file.

    The body can contain nested braces (template strings with ${...},
    object literals, function expressions) so we match them by
    counting ``{`` vs ``}`` from the opening brace while ignoring
    braces inside string/regular-expression literals and line/block
    comments.
    """
    pat = re.compile(
        r"(?:function\s+)?" + re.escape(name) + r"\s*\([^)]*\)?\s*\{"
    )
    m = pat.search(source)
    if not m:
        raise AssertionError("function " + name + " not found")
    start = m.end() - 1  # position of opening '{'
    depth = 0
    in_str = None  # '"' | "'" | '`'
    i = start
    while i < len(source):
        c = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if in_str == "/" :
            # regex literal
            if c == "\\":
                i += 2
                continue
            if c == "/":
                in_str = None
                i += 1
                continue
            i += 1
            continue
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == "/" and nxt == "/":
            j = source.find("\n", i)
            i = j if j != -1 else len(source)
            continue
        if c == "/" and nxt == "*":
            j = source.find("*/", i + 2)
            i = j + 2 if j != -1 else len(source)
            continue
        if c == "/" and nxt == "/":
            j = source.find("\n", i)
            i = j if j != -1 else len(source)
            continue
        if c == "\"":
            in_str = "\""
            i += 1
            continue
        if c == "'":
            in_str = "'"
            i += 1
            continue
        if c == "`":
            in_str = "`"
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise AssertionError("unterminated function " + name)



# ── rpc.js onerror visibility ────────────────────────────────


def test_rpc_onerror_no_longer_silent() -> None:
    """A pre-v6.0.1 bug left ``_ws.onerror = () => {}`` swallowing
    every WebSocket failure.  This test pins the post-fix shape: the
    handler must log, must emit ``_error``, and must include the
    connection URL in the detail so the operator can compare against
    the gateway's actual listen address."""
    src = _read(RPC_JS)
    # Use the onerror assignment line as the anchor and grab a small
    # window after it (the handler is a short arrow function).
    idx = src.index("this._ws.onerror")
    body = src[idx:idx + 1500]
    assert "() => {}" not in body, "onerror is still a silent no-op"
    assert "console" in body.lower() or "log" in body.lower(), (
        "onerror must log the failure"
    )
    assert "url" in body, "onerror must include the connection URL"
    assert "_error" in body, "onerror must emit an _error event"


# ── app.js auto-connect logging ──────────────────────────────


def test_auto_connect_logs_url_and_masked_token() -> None:
    src = _read(APP_JS)
    body = _extract_function(src, "_autoConnect")
    assert "console.log" in body, "_autoConnect must log the URL"
    assert "URL=" in body
    # Token must be masked, not printed verbatim.
    assert "***" in body, "token must be masked before logging"
    assert "token.slice" in body or "tokenMasked" in body, (
        "token masking helper missing"
    )


# ── app.js connection-state error count + tooltip ────────────


def test_connection_state_subscribes_to_error_event() -> None:
    src = _read(APP_JS)
    body = _extract_function(src, "_bindConnectionState")
    assert "rpc.on('_error'" in body, (
        "_bindConnectionState must listen for the _error event"
    )
    assert "_errorCount" in body, (
        "_bindConnectionState must track consecutive error count"
    )
    assert "WebSocket unreachable" in body, (
        "_bindConnectionState must surface a 'WebSocket unreachable' "
        "tooltip after multiple failures"
    )


def test_connection_state_resets_error_count_on_connect() -> None:
    """A single transient blip must not lock the pill into the
    'unreachable' state forever — the counter resets on every
    successful 'connected' transition."""
    src = _read(APP_JS)
    body = _extract_function(src, "_bindConnectionState")
    # The reset branch must guard on 'connected'.
    assert "state === 'connected'" in body or "'connected'" in body, (
        "error counter must reset on 'connected' state"
    )
    assert "_errorCount = 0" in body


# ── rpc.js debug-friendly state logging ─────────────────────


def test_rpc_logs_state_transitions() -> None:
    """The pill alone tells the operator *what* state we're in, not
    *why* we got there.  Logging every state change with the URL we
    tried is the cheapest way to make a stuck DISCONNECTED
    diagnosable from devtools."""
    src = _read(RPC_JS)
    body = _extract_function(src, "_setState")
    assert "console.log" in body, (
        "_setState must log transitions so a stuck state is debuggable"
    )
    assert "[rpc] state" in body or "state " in body


def test_rpc_logs_websocket_creation() -> None:
    """Before a WebSocket can fail, it has to be *created*.  If
    ``new WebSocket(url)`` never fires, ``init()`` never reached
    ``_autoConnect`` and the chat view is stuck for a totally
    different reason.  Logging the construction is the cheapest
    sentinel for that."""
    src = _read(RPC_JS)
    body = _extract_function(src, "_doConnect")
    assert "new WebSocket" in body
    assert "console.log" in body
    assert "_doConnect" in body or "creating new WebSocket" in body
