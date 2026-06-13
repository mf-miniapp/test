"""Spawn-time contract tests for hack-deep.

Three assertions:

1. The SOUL explicitly mandates that every ``sessions_spawn`` task must start
   with a HANDOFF Envelope header.
2. A regex derived from the SOUL's contract accepts valid Envelopes and
   rejects malformed ones.
3. A live ``sessions_spawn`` call (against a stubbed SessionManager and
   TaskRuntime, modeled on ``tests/test_tools/test_sessions_spawn_regressions.py``)
   accepts an Envelope-shaped task and produces a ``run_kind="subagent"`` enqueue.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

REAL_HOME = Path.home() / ".opensquilla"
HACK_DEEP_DIR = REAL_HOME / "agents" / "hack-deep"
SOUL_PATH = HACK_DEEP_DIR / "SOUL.md"


def _read_soul() -> str:
    if not SOUL_PATH.is_file():
        import pytest
        pytest.skip(f"{SOUL_PATH} missing — run clone_cyberstrike_to_hack_deep.py first")
    return SOUL_PATH.read_text(encoding="utf-8")


SOUL = _read_soul()

# Regex captured from the SOUL contract (verbatim):
#   ^HANDOFF\s+\S+\s*\|\s*deps=\S+\s*\|\s*schema=\S+\s*\|\s*eta=\d+
ENVELOPE_REGEX = re.compile(
    r"^\s*HANDOFF\s+\S+\s*\|\s*deps=\S+\s*\|\s*schema=\S+\s*\|\s*eta=\d+"
)


# ---------------------------------------------------------------------------
# 1. SOUL mandates the envelope header
# ---------------------------------------------------------------------------


def test_soul_mandates_envelope_header_on_every_spawn() -> None:
    """SOUL contains a sentence that every sessions_spawn task MUST start
    with the HANDOFF Envelope header."""
    # Lowercase normalize so we tolerate casing differences.
    lower = SOUL.lower()
    # Phrases the SOUL is allowed to use (Chinese or English)
    patterns = [
        "must start with this 4-field envelope header",
        "首行**必须是这个 4 字段 envelope header",
        "首行**必须是这个 4 字段 envelope header".lower(),
        "首行**必须是".lower(),
        "must start with this 4-field envelope".lower(),
    ]
    assert any(p.lower() in lower for p in patterns), (
        "SOUL does not mandate the Envelope header on every sessions_spawn task"
    )


def test_soul_documented_regex_matches_inline_regex() -> None:
    """The regex shown in the SOUL matches the one we compile here."""
    # SOUL contains: ^HANDOFF\s+\S+\s*\|\s*deps=\S+\s*\|\s*schema=\S+\s*\|\s*eta=\d+
    needle = r"^HANDOFF\\s+\\S+\\s*\\|\\s*deps=\\S+\\s*\\|\\s*schema=\\S+\\s*\\|\\s*eta=\\d+"
    # The SOUL escapes the backslashes in the markdown body. Strip them for the match.
    unescaped = needle.replace("\\\\", "\\")
    assert unescaped in SOUL, (
        "SOUL's documented regex doesn't match the test's compiled regex"
    )


# ---------------------------------------------------------------------------
# 2. Envelope regex: valid / malformed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "task",
    [
        "HANDOFF W1.recon.1 | deps=empty | schema=recon-v1 | eta=180",
        "HANDOFF W1.recon.1 | deps=W0.engagement-planning.1 | schema=recon-v1 | eta=300",
        "HANDOFF W4.penetration.1 | deps=W2.vulnerability-triage.1,W3.opsec-evasion.1 | schema=pentest-v1 | eta=600",
        # leading whitespace is OK because we use re.match (anchored)
        "  HANDOFF W1.recon.1 | deps=empty | schema=recon-v1 | eta=180",
    ],
)
def test_envelope_regex_accepts_valid_handoff(task: str) -> None:
    assert ENVELOPE_REGEX.match(task), f"regex should accept valid envelope: {task!r}"


@pytest.mark.parametrize(
    "task",
    [
        "do recon on 51ifind.com",  # no HANDOFF
        "HANDOFF W1.recon.1",  # missing deps/schema/eta
        "HANDOFF W1.recon.1 | deps=empty | schema=recon-v1",  # missing eta
        "HANDOFF W1.recon.1 | schema=recon-v1 | eta=180",  # missing deps
        "HANDOFF W1.recon.1 | deps=empty | schema=recon-v1 | eta=abc",  # eta non-numeric
    ],
)
def test_envelope_regex_rejects_malformed(task: str) -> None:
    assert not ENVELOPE_REGEX.match(task), f"regex should reject malformed: {task!r}"


# ---------------------------------------------------------------------------
# 3. Live sessions_spawn with a stubbed manager + runtime
# ---------------------------------------------------------------------------


@dataclass
class _StubRow:
    spawned_by: str | None
    status: str = "running"


class _StubSessionManager:
    """Minimal SessionManager that returns hack-deep as caller and recon as target."""

    has_agent_registry = True

    def __init__(self) -> None:
        self.created: list[dict] = []
        self.agents = {
            "hack-deep": {
                "id": "hack-deep",
                "enabled": True,
                "subagents": {
                    "allow_agents": [
                        "recon",
                        "intel-collection",
                        "attack-surface-enumeration",
                        "vulnerability-triage",
                        "opsec-evasion",
                        "penetration",
                        "privilege-escalation",
                        "lateral-movement",
                        "persistence-maintenance",
                        "impact-exfiltration",
                        "cleanup-rollback",
                        "reporting-remediation",
                        "engagement-planning",
                    ],
                    "max_children_per_session": 6,
                },
            },
            "recon": {
                "id": "recon",
                "enabled": True,
                "subagents": None,
            },
            # cyberstrike-deep is in the registry (to bypass the agent-not-found
            # check) but is NOT in hack-deep's allow_agents list, so the
            # allowlist gate must fire.
            "cyberstrike-deep": {
                "id": "cyberstrike-deep",
                "enabled": True,
                "subagents": None,
            },
        }

    async def get_agent_config(self, agent_id: str):
        return self.agents.get(agent_id)

    async def get_current_session(self):
        return None

    async def list_sessions(self, **kwargs):
        return []

    async def create(self, **kwargs):
        self.created.append(kwargs)

    async def append_message(self, *args, **kwargs):
        return True


class _StubTaskRuntime:
    def __init__(self) -> None:
        self.enqueued: list[dict] = []

    async def enqueue(self, envelope, message, mode="followup", run_kind="default"):
        self.enqueued.append(
            {
                "envelope": envelope,
                "message": message,
                "run_kind": run_kind,
                "mode": mode,
            }
        )

        @dataclass
        class _Handle:
            task_id: str = "task-stub"

        return _Handle()


@pytest.fixture(autouse=True)
def _wire():
    """Wire the stub session manager + task runtime into the sessions tool."""
    from opensquilla.tools.builtin import sessions as sessions_tool
    from opensquilla.tools.types import CallerKind, ToolContext

    # Minimal gateway config for sessions_spawn to load subagents config from
    class _SubagentsBlock:
        enforce_disabled_agents = False

    class _Config:
        subagents = _SubagentsBlock()
        agents_defaults = None

    sessions_tool.set_gateway_config(_Config())
    sessions_tool._spawn_locks.clear()
    yield
    sessions_tool.set_session_manager(None)
    sessions_tool.set_task_runtime(None)
    sessions_tool.set_gateway_config(None)
    sessions_tool._spawn_locks.clear()


def _ctx() -> "ToolContext":
    from opensquilla.tools.types import CallerKind, ToolContext

    return ToolContext(
        is_owner=True,
        caller_kind=CallerKind.AGENT,
        subagent_depth=0,
        agent_id="hack-deep",
        session_key="agent:hack-deep:main",
        task_id="task-hack-deep-parent",
    )


def test_sessions_spawn_with_envelope_header_is_accepted_by_stub() -> None:
    """A real sessions_spawn call (against stubs) accepts an Envelope-shaped
    task and produces a run_kind='subagent' enqueue."""
    from opensquilla.tools.builtin import sessions as sessions_tool
    from opensquilla.tools.types import current_tool_context

    mgr = _StubSessionManager()
    rt = _StubTaskRuntime()
    sessions_tool.set_session_manager(mgr)
    sessions_tool.set_task_runtime(rt)

    task = (
        "HANDOFF W1.recon.1 | deps=W0.engagement-planning.1 | schema=recon-v1 | eta=180\n\n"
        "对 51ifind.com 做被动侦察:子域枚举 / 端口扫描 / 技术栈指纹。"
    )

    token = current_tool_context.set(_ctx())
    try:
        asyncio.run(sessions_tool.sessions_spawn(agent_id="recon", task=task))
    finally:
        current_tool_context.reset(token)

    # 1) The runtime received one enqueue with run_kind=subagent
    assert len(rt.enqueued) == 1, f"expected 1 enqueue, got {len(rt.enqueued)}"
    assert rt.enqueued[0]["run_kind"] == "subagent", (
        f"expected run_kind='subagent', got {rt.enqueued[0]['run_kind']!r}"
    )
    # 2) The envelope is for the recon agent
    assert rt.enqueued[0]["envelope"].agent_id == "recon"
    # 3) The task string preserved the HANDOFF envelope header
    assert "HANDOFF W1.recon.1" in rt.enqueued[0]["message"]
    assert "schema=recon-v1" in rt.enqueued[0]["message"]
    # 4) The session was actually created
    assert len(mgr.created) == 1
    assert mgr.created[0]["agent_id"] == "recon"
    assert mgr.created[0]["spawn_depth"] == 1  # caller is depth 0, child is 1


def test_sessions_spawn_rejects_target_outside_allow_agents() -> None:
    """hack-deep's allow_agents list excludes cyberstrike-deep; spawning it
    must raise. This is the runtime-level enforcement of the SOUL contract."""
    from opensquilla.tools.builtin import sessions as sessions_tool
    from opensquilla.tools.types import current_tool_context

    mgr = _StubSessionManager()
    rt = _StubTaskRuntime()
    sessions_tool.set_session_manager(mgr)
    sessions_tool.set_task_runtime(rt)

    task = "HANDOFF W0.engagement-planning.1 | deps=empty | schema=roe-v1 | eta=60\n\nX"

    token = current_tool_context.set(_ctx())
    try:
        with pytest.raises(Exception, match="not allowed"):
            asyncio.run(
                sessions_tool.sessions_spawn(
                    agent_id="cyberstrike-deep", task=task
                )
            )
    finally:
        current_tool_context.reset(token)
    # The runtime was NOT enqueued (the allowlist check rejected before enqueue)
    assert len(rt.enqueued) == 0


def test_sessions_spawn_rejects_self_spawn_when_not_in_allow_agents() -> None:
    """Coordinator agents (hack-deep, cyberstrike-deep) MUST NOT spawn
    themselves — the sub-agent would lose the coordinator's SOUL context
    and gain the generic _SUBAGENT_SYSTEM_PROMPT instead, which caused
    the 2026-06-05 incident where hack-deep spawned itself and then
    10 tool calls were denied.

    2026-06-05 fix: ``if resolved_agent_id == caller_agent_id`` now goes
    through the allowlist check (must contain self or '*').
    """
    from opensquilla.tools.builtin import sessions as sessions_tool
    from opensquilla.tools.types import current_tool_context

    mgr = _StubSessionManager()
    rt = _StubTaskRuntime()
    sessions_tool.set_session_manager(mgr)
    sessions_tool.set_task_runtime(rt)

    # hack-deep's allow_agents (from _StubSessionManager) does NOT include
    # itself. So hack-deep trying to spawn hack-deep must be rejected.
    task = "HANDOFF W1.recon.1 | deps=empty | schema=recon-v1 | eta=180\n\nX"

    token = current_tool_context.set(_ctx())
    try:
        with pytest.raises(Exception, match="[Ss]elf-spawn not allowed"):
            asyncio.run(
                sessions_tool.sessions_spawn(
                    agent_id="hack-deep", task=task  # ← same as caller
                )
            )
    finally:
        current_tool_context.reset(token)
    assert len(rt.enqueued) == 0


def test_sessions_spawn_allows_self_spawn_when_in_allow_agents() -> None:
    """The inverse case: if the agent explicitly lists itself in
    allow_agents (or has '*'), self-spawn IS allowed. This preserves
    the option for agents that genuinely need to clone themselves for
    parallel processing.
    """
    from opensquilla.tools.builtin import sessions as sessions_tool
    from opensquilla.tools.types import current_tool_context

    # Build a manager where the caller has self in allow_agents.
    class _SelfAllowMgr(_StubSessionManager):
        def __init__(self) -> None:
            super().__init__()
            self.agents = dict(self.agents)  # copy
            self.agents["hack-deep"] = {
                "id": "hack-deep",
                "enabled": True,
                "subagents": {
                    "allow_agents": [
                        "hack-deep",  # ← explicit self-allow
                        "recon", "intel-collection",
                    ],
                },
            }

    mgr = _SelfAllowMgr()
    rt = _StubTaskRuntime()
    sessions_tool.set_session_manager(mgr)
    sessions_tool.set_task_runtime(rt)

    task = "HANDOFF W1.recon.1 | deps=empty | schema=recon-v1 | eta=180\n\nX"

    token = current_tool_context.set(_ctx())
    try:
        asyncio.run(
            sessions_tool.sessions_spawn(
                agent_id="hack-deep", task=task
            )
        )
    finally:
        current_tool_context.reset(token)
    assert len(rt.enqueued) == 1
    assert rt.enqueued[0]["run_kind"] == "subagent"
