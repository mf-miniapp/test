"""Regression test: ``chat.js`` must not contain Python-style
triple-quote docstrings.

When the prefill flow was first added, the docstring for
``_readPrefillFromUrl`` was inadvertently written as ``\"\"\"...\"\"\"``
instead of ``/* ... */`` or ``// ...``.  JavaScript doesn't have a
triple-quote string syntax, so the entire file failed to parse with
``SyntaxError: Invalid or unexpected token``.

The downstream effect was severe:

  * ``window.ChatView`` was never assigned, because the parse error
    aborted the whole module.
  * The router's ``/chat`` route threw ``ReferenceError: ChatView is
    not defined``, so the chat view never rendered.
  * The topbar pill showed the **initial** ``DISCONNECTED`` value
    baked into the HTML, and the user was stuck on a blank page
    looking at a permanent DISCONNECTED state.
  * No JS error was visible in the user's devtools unless they
    scrolled the page (the error fired on script load, before
    devtools was opened).

This test is a guard against anyone (human or model) re-introducing
that mistake.  We assert zero ``\"\"\"`` occurrences anywhere in the
file, plus a happy-path check that ``_readPrefillFromUrl`` is
parseable.
"""
from __future__ import annotations

import re
from pathlib import Path

CHAT_JS = Path("src/opensquilla/gateway/static/js/views/chat.js")


def _read() -> str:
    return CHAT_JS.read_text(encoding="utf-8")


def test_chat_js_has_no_python_triple_quotes() -> None:
    """Any ``\"\"\"`` is a fatal JS syntax error.  The whole prefill
    flow falls over if even one sneaks in."""
    src = _read()
    # Count both styles (""" and ''').  Both would crash the parser.
    triple_double = src.count('"""')
    triple_single = src.count("'''")
    assert triple_double == 0, (
        f"chat.js contains {triple_double} triple-double-quote sequences; "
        "these are Python docstrings, NOT valid JavaScript.  Use /* */ "
        "or // instead."
    )
    assert triple_single == 0, (
        f"chat.js contains {triple_single} triple-single-quote sequences; "
        "these are Python docstrings, NOT valid JavaScript."
    )


def test_read_prefill_from_url_is_documented() -> None:
    """The function that was broken by the original bug must still
    exist and have a JS-compatible comment block (either // or /* */)
    describing its purpose.  If the file is unparseable, the regex
    itself will fail to find anything and assert."""
    src = _read()
    fn = re.search(
        r"function\s+_readPrefillFromUrl\s*\([^)]*\)\s*\{",
        src,
    )
    assert fn, "_readPrefillFromUrl not found"
    # The first 600 bytes after the opening brace must be a JS
    # comment (// or /* */), not a Python-style triple-quote.
    body_start = src[fn.end():fn.end() + 600]
    has_js_comment = (
        "//" in body_start[:200] or "/*" in body_start[:200]
    )
    assert has_js_comment, (
        "_readPrefillFromUrl must have a JS-compatible comment block "
        "(// or /* */) describing its purpose"
    )
    assert '"""' not in body_start, (
        "_readPrefillFromUrl body contains triple-quote — this is the "
        "original bug.  Replace with // or /* */."
    )
