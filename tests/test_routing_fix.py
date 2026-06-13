"""Routing fix (A + B + C) contract tests.

Regression suite for the 3-layer fix applied after the user observed that:

  @hack-deep 全面深度的攻击51ifind.com
  → routed to SQUILLA (main)
  → SQUILLA produced an "attack plan" and started executing it itself
  → hack-deep was never invoked

Layer A: SQUILLA system_prompt hard-rules "never execute, only delegate".
Layer B: hack-deep SOUL hard-rules "never execute any tool, only sessions_spawn".
Layer C: chat.js parses `@<agent_id>` and dispatches directly to that agent's
         session, bypassing SQUILLA.

These tests pin those 3 contracts so a future regression (e.g. someone
removes the SQUILLA prompt, or someone edits chat.js to not parse the
@-prefix) is caught immediately.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REAL_HOME = Path.home() / ".opensquilla"
CONFIG_PATH = REAL_HOME / "config.toml"
HACK_DEEP_SOUL = REAL_HOME / "agents" / "hack-deep" / "SOUL.md"
CHAT_JS = (
    Path("/Users/zlpc/data/zspace/hack/opensquilla")
    / "src/opensquilla/gateway/static/js/views/chat.js"
)


# ---------------------------------------------------------------------------
# Layer A — SQUILLA "只做路由, 绝不执行" system_prompt
# ---------------------------------------------------------------------------


def _load_main_entry() -> dict:
    """Load the live main entry from config.toml."""
    # Local import to keep this file's collection fast
    from opensquilla.onboarding.config_store import load_config
    cfg = load_config(CONFIG_PATH)
    for entry in cfg.agents:
        if entry.id == "main":
            return entry.model_dump()
    raise RuntimeError("main entry missing from config.toml")


class TestSquillaRoutingPrompt:
    def test_main_entry_exists_in_config(self) -> None:
        entry = _load_main_entry()
        assert entry["id"] == "main"

    def test_main_has_nonempty_system_prompt(self) -> None:
        entry = _load_main_entry()
        sp = entry.get("system_prompt") or ""
        assert len(sp) > 200, "main system_prompt is suspiciously short"

    def test_main_prompt_forbids_direct_execution(self) -> None:
        """SQUILLA must be told it cannot run scan/probe/attack tools."""
        sp = _load_main_entry().get("system_prompt") or ""
        # Chinese: "绝对不做" / "自己绝不调用"
        assert "绝对不做" in sp or "绝不调用" in sp or "never" in sp.lower()
        # Tools explicitly forbidden
        for forbidden in ("nmap", "port-scan", "curl", "exploit"):
            assert forbidden in sp, f"forbidden tool {forbidden!r} not mentioned"

    def test_main_prompt_routes_at_mention_via_sessions_spawn(self) -> None:
        sp = _load_main_entry().get("system_prompt") or ""
        assert "sessions_spawn" in sp
        # The @-mention rule
        assert "@" in sp

    def test_main_prompt_prefers_hack_deep_for_deep_penetration(self) -> None:
        """The default routing for 'deep attack' requests is hack-deep, not
        cyberstrike-deep. SQUILLA must not let the LLM heuristic flip this."""
        sp = _load_main_entry().get("system_prompt") or ""
        assert "hack-deep" in sp
        # Strongly worded — must not be a weak "may prefer"
        assert "默认" in sp or "default" in sp.lower()
        # Must explicitly warn against the LLM-误判
        assert "代名词" in sp or "不要把" in sp or "avoid" in sp.lower()


# ---------------------------------------------------------------------------
# Layer B — hack-deep "绝不做执行" SOUL constraint
# ---------------------------------------------------------------------------


def _read_hack_deep_soul() -> str:
    if not HACK_DEEP_SOUL.is_file():
        pytest.skip(f"{HACK_DEEP_SOUL} missing — run clone_cyberstrike_to_hack_deep.py first")
    return HACK_DEEP_SOUL.read_text(encoding="utf-8")


class TestHackDeepNoExecuteConstraint:
    def test_soul_has_identification_header(self) -> None:
        """The first lines identify hack-deep as the NEW deep orchestrator."""
        soul = _read_hack_deep_soul()
        head = soul[:400]
        # The 2026-06-05 routing fix header
        assert "HACK-DEEP" in head or "新型 Deep 编排者" in head

    def test_soul_forbids_direct_tool_execution(self) -> None:
        soul = _read_hack_deep_soul()
        # The 强制约束 block must exist
        assert "强制约束" in soul, "SOUL.md is missing the 强制约束 block"
        # The forbidden-tools list
        for forbidden in ("nmap", "curl", "exploit", "port-scan"):
            assert forbidden in soul, f"forbidden tool {forbidden!r} not enumerated in SOUL"

    def test_soul_lists_allowed_tools(self) -> None:
        soul = _read_hack_deep_soul()
        # The "唯一允许的工具" list
        assert "唯一允许的工具" in soul
        # The allowed tools
        assert "sessions_spawn" in soul
        assert "sessions_yield" in soul
        assert "write_todos" in soul

    def test_soul_mandates_sessions_spawn_for_all_work(self) -> None:
        """Every kind of execution work must be delegated, not done by hack-deep."""
        soul = _read_hack_deep_soul()
        for work_kind in ("扫描", "枚举", "利用", "持久化", "取数", "影响证明"):
            assert work_kind in soul, f"work kind {work_kind!r} not in SOUL"


# ---------------------------------------------------------------------------
# Layer C — chat.js @-mention parser
# ---------------------------------------------------------------------------


def _read_chat_js() -> str:
    if not CHAT_JS.is_file():
        pytest.skip(f"{CHAT_JS} not found")
    return CHAT_JS.read_text(encoding="utf-8")


class TestChatJsMentionRouting:
    def test_mention_regex_present(self) -> None:
        """The @-mention regex exists in chat.js."""
        js = _read_chat_js()
        # The regex pattern: /^\s*@([a-zA-Z0-9_-]+)\s+([\s\S]*?)\s*$/
        assert "/^\\s*@([a-zA-Z0-9_-]+)\\s+([\\s\\S]*?)\\s*$/" in js, (
            "chat.js is missing the @-mention regex"
        )

    def test_mention_routes_via_webchat_session_key(self) -> None:
        """When @-mention matched, chat.js builds a new webchat session key
        for the mentioned agent (not for 'main')."""
        js = _read_chat_js()
        # The block must call _webchatSessionKey(mentionedAgent, ...)
        assert "_webchatSessionKey(" in js
        # And it must guard against routing to "main"
        assert "mentionedAgent !== 'main'" in js or 'mentionedAgent != "main"' in js, (
            "chat.js must reject @main as a target"
        )

    def test_provider_text_stripped_after_mention(self) -> None:
        """After the @agent_id prefix, the message body is sent without the prefix."""
        js = _read_chat_js()
        # The block reassigns providerText to bodyAfterMention
        assert "providerText = bodyAfterMention" in js, (
            "chat.js does not strip the @-prefix from the message body"
        )

    def test_session_key_persisted_after_mention(self) -> None:
        """After @-mention routing, _sessionKey is updated + persisted."""
        js = _read_chat_js()
        assert "_persistSession(_sessionKey)" in js

    def test_provider_text_is_let_not_const(self) -> None:
        """providerText must be `let` (we reassign it after stripping the @-prefix)."""
        js = _read_chat_js()
        # Find the line that declares providerText (allow leading whitespace).
        m = re.search(r"^\s*(let|const)\s+providerText\s*=", js, re.MULTILINE)
        assert m is not None, "providerText declaration not found"
        assert m.group(1) == "let", (
            f"providerText declared as {m.group(1)!r} but the @-mention block reassigns it"
        )
