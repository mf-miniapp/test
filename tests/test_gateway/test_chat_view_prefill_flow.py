"""Static-source tests for the cross-surface attack-paths prefill flow.

The dashboard's "▶ Run" button navigates the user into chat with
``?prefill=/attack-paths run <tree_id>``.  This file pins the JS contract
that:

  * ``_readPrefillFromUrl`` consumes ``?prefill=`` and the ``?tree=``
    fallback, and rewrites the URL so reloads don't replay the dispatch.
  * ``_consumePrefill`` opens a fresh chat session, surfaces the synthetic
    user message in the thread, and dispatches attack_paths.run.
  * ``_dispatchAttackPaths`` waits for the WebSocket connection before
    calling the RPC and surfaces clear errors when the connection is
    not yet up.
  * ``_resetForNewSession`` is a real implementation (mirrors the
    ``/new`` slash case) and not an empty stub.

If any of these contracts regress, the dashboard's "▶ Run" button will
silently stop firing — exactly the bug this file is here to prevent.
"""
from __future__ import annotations

import re
from pathlib import Path

CHAT_JS = Path("src/opensquilla/gateway/static/js/views/chat.js")
DASHBOARD_HTML = Path("src/opensquilla/attack_paths/web/templates/dashboard.html")


def _read_chat_js() -> str:
    return CHAT_JS.read_text(encoding="utf-8")


def _read_dashboard() -> str:
    return DASHBOARD_HTML.read_text(encoding="utf-8")


def _extract_function(source: str, name: str) -> str:
    """Best-effort extraction of a top-level ``function NAME(...) { ... }``
    block from chat.js.  Greedy match is OK because the file is well-
    formatted with consistent indentation and we only need the *body* of
    each function for substring assertions.
    """
    # Match: optional `async `, then `function NAME(` and capture the body
    # up to the next blank-line-then-non-indented ``function`` or end of
    # file.  We use a relaxed match — the chat.js functions we target
    # are 2-space indented.
    pattern = re.compile(
        r"^\s{2}(async\s+)?function\s+" + re.escape(name) + r"\(.*?^\s{2}\}\s*$",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(source)
    if not m:
        raise AssertionError(f"function {name!r} not found in chat.js")
    return m.group(0)


# ── _readPrefillFromUrl contract ──────────────────────────────


def test_read_prefill_parses_prefill_and_tree_params() -> None:
    src = _read_chat_js()
    fn = _extract_function(src, "_readPrefillFromUrl")
    assert "params.get('prefill')" in fn
    assert "params.get('tree')" in fn
    assert "params.delete('prefill')" in fn
    assert "params.delete('tree')" in fn
    assert "history.replaceState" in fn
    # Decodes percent-encoding so a prefill like
    # "%2Fattack-paths%20run%20foo" round-trips correctly.
    assert "decodeURIComponent" in fn
    # Synthesizes a fallback slash command when only ?tree= is present.
    assert "'/attack-paths run '" in fn


# ── _consumePrefill contract ──────────────────────────────────


def test_consume_prefill_calls_reset_dispatch_user_msg() -> None:
    src = _read_chat_js()
    fn = _extract_function(src, "_consumePrefill")
    # Order matters: reset → add user message → dispatch.
    assert fn.index("_resetForNewSession()") < fn.index("_addUserMessageToThread(text)")
    assert fn.index("_addUserMessageToThread(text)") < fn.index("_dispatchAttackPaths(")
    # Dispatches the parsed.kind result, not just _onSend.
    assert "parsed.kind === 'attack_paths.run'" in fn
    # Logs the rpc state so console debugging shows whether the WS is up.
    assert "rpcState" in fn
    # Aborts early if the textarea is not wired (defensive).
    assert "ABORT: no textarea" in fn


# ── _dispatchAttackPaths contract ─────────────────────────────


def test_dispatch_attack_paths_waits_for_ws_connection() -> None:
    src = _read_chat_js()
    fn = _extract_function(src, "_dispatchAttackPaths")
    # Must wait for the WebSocket before calling the RPC.  Without this,
    # the very first cross-surface handoff races the auto-connect and
    # silently fails with "Not connected".
    assert "_rpc.waitForConnection()" in fn
    # Must guard the no-RPC case with a clear user-visible error.
    assert "RPC not available" in fn
    # Must surface the connection failure in the chat thread so the user
    # sees something instead of a silently empty transcript.
    assert "WebSocket RPC not connected" in fn
    # Must include the tree_id in the success summary for traceability.
    assert "params?.tree_id" in fn
    # Logs the result so the user can confirm the RPC actually fired.
    assert "[prefill] result =" in fn


# ── _resetForNewSession contract (regression test for empty stub) ─


def test_reset_for_new_session_is_a_real_implementation() -> None:
    """Before the v6 fix, ``_resetForNewSession`` was an empty function —
    the JSDoc comment was followed by a bare ``function NAME() {`` with
    no body, and the next ``function`` declaration swallowed the closing
    brace.  That made the cross-surface handoff a no-op and the user
    saw an empty chat thread.

    This test pins the post-fix shape: the function body must call
    unsubscribe + park + genKey + updateSessionChip + persistSession,
    and must clear the messages array + reset the thread DOM.
    """
    src = _read_chat_js()
    fn = _extract_function(src, "_resetForNewSession")
    # Each of these is part of the ``/new`` slash command body that we
    # are mirroring — a regression to "empty function" would drop them.
    for needle in (
        "_unsubscribeSession",
        "_parkCurrentSessionStreamState",
        "_genKey",
        "_updateSessionChip",
        "_persistSession",
        "_messages = []",
        "_emptyStateHTML",
        "_subscribeSession",
    ):
        assert needle in fn, f"_resetForNewSession missing required call: {needle!r}"


def test_reset_for_new_session_returns_the_new_key() -> None:
    src = _read_chat_js()
    fn = _extract_function(src, "_resetForNewSession")
    # The new function returns the generated key so callers (e.g. a
    # future test harness) can use it.
    assert "return key" in fn


# ── Dashboard hand-off contract ───────────────────────────────


def test_dashboard_run_in_chat_uses_same_tab_navigation() -> None:
    """The dashboard's "▶ Run" button must NOT use ``window.open(_blank)``.

    A new tab races the WebSocket connect with the prefill, leading to a
    silent failure where the user lands on an empty chat with a
    DISCONNECTED pill.  Same-tab navigation lets the SPA + WebSocket
    reconnect cleanly and gives chat.js a chance to
    ``await _rpc.waitForConnection()`` before dispatching.
    """
    src = _read_dashboard()
    fn_match = re.search(
        r"function _runInChat\(command\)\s*\{.*?^\s*\}",
        src,
        re.MULTILINE | re.DOTALL,
    )
    assert fn_match, "_runInChat not found in dashboard.html"
    fn = fn_match.group(0)
    assert "window.open" not in fn, "dashboard must not use window.open for handoff"
    assert "window.location.href" in fn
    # Still includes both prefill= and tree= in the URLSearchParams so
    # chat.js can fall back if the slash catalog hasn't finished loading.
    assert "prefill:" in fn
    assert "'tree'" in fn
    assert "params.set('tree'" in fn
