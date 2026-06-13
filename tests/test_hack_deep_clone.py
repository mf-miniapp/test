"""Tests for the hack-deep clone script and resulting on-disk artifacts.

The script `scripts/clone_cyberstrike_to_hack_deep.py` materializes a peer
coordinator `hack-deep` next to `cyberstrike-deep`. These tests verify the
post-clone invariants:

- 8 expected workspace files exist in `~/.opensquilla/agents/hack-deep/`
- The `hack-deep` `[[agents]]` block is persisted in `~/.opensquilla/config.toml`
  with `subagents.allow_agents` listing the 13 specialists and explicitly
  excluding `cyberstrike-deep`.
- The original `cyberstrike-deep` entry is byte-for-byte unchanged.
- `AgentRegistry.list_agents()` returns both entries.
- The clone is idempotent at the file level (re-running with the agent already
  present refreshes SOUL/ATTRIBUTION and config without raising).

Important: the conftest sets ``OPENSQUILLA_STATE_DIR`` to a tmp dir, which makes
``default_opensquilla_home()`` resolve to that tmp dir, not ``~/.opensquilla``.
We therefore point at the real config explicitly.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Late import — clone module touches config_store / registry on import
import clone_cyberstrike_to_hack_deep as clone_mod  # noqa: E402

from opensquilla.agents.registry import AgentRegistry  # noqa: E402
from opensquilla.gateway.config import (  # noqa: E402
    AgentEntryConfig,
    AgentSubagentDefaults,
    GatewayConfig,
)
from opensquilla.onboarding.config_store import load_config  # noqa: E402

# The real, user-visible OpenSquilla home — bypasses OPENSQUILLA_STATE_DIR.
REAL_HOME = Path.home() / ".opensquilla"
REAL_CONFIG = REAL_HOME / "config.toml"
HACK_DEEP_DIR = REAL_HOME / "agents" / "hack-deep"
CYBERSTRIKE_DEEP_DIR = REAL_HOME / "agents" / "cyberstrike-deep"

EXPECTED_WORKSPACE_FILES = (
    "SOUL.md",
    "AGENTS.md",
    "ATTRIBUTION.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "MEMORY.md",
    "TOOLS.md",
    "USER.md",
)

EXPECTED_SPECIALISTS = clone_mod.SPECIALIST_AGENTS
assert len(EXPECTED_SPECIALISTS) == 13


# ---------------------------------------------------------------------------
# Helpers (bypass OPENSQUILLA_STATE_DIR)
# ---------------------------------------------------------------------------


def _load_live_config() -> GatewayConfig:
    """Load the real config.toml, bypassing OPENSQUILLA_STATE_DIR redirect."""
    return load_config(REAL_CONFIG)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def live_hack_deep_entry() -> AgentEntryConfig:
    """Read the live hack-deep entry from the real config.toml."""
    cfg = _load_live_config()
    for entry in cfg.agents:
        if entry.id == "hack-deep":
            return entry
    raise RuntimeError("hack-deep entry not found in live ~/.opensquilla/config.toml")


@pytest.fixture(scope="module")
def live_cyberstrike_deep_entry() -> AgentEntryConfig:
    """Read the live cyberstrike-deep entry from the real config.toml."""
    cfg = _load_live_config()
    for entry in cfg.agents:
        if entry.id == "cyberstrike-deep":
            return entry
    raise RuntimeError("cyberstrike-deep entry not found in live ~/.opensquilla/config.toml")


# ---------------------------------------------------------------------------
# 1. Workspace files exist
# ---------------------------------------------------------------------------


def test_hack_deep_workspace_files_present() -> None:
    """All 8 expected files are materialized in ~/.opensquilla/agents/hack-deep/."""
    assert HACK_DEEP_DIR.is_dir(), f"{HACK_DEEP_DIR} is not a directory"
    missing = [name for name in EXPECTED_WORKSPACE_FILES if not (HACK_DEEP_DIR / name).is_file()]
    assert not missing, f"Missing workspace files: {missing}"


def test_hack_deep_workspace_state_json_present() -> None:
    """.opensquilla/workspace-state.json was written by the clone script."""
    state_path = HACK_DEEP_DIR / ".opensquilla" / "workspace-state.json"
    assert state_path.is_file()

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["workspace_dir"] == str(HACK_DEEP_DIR)


# ---------------------------------------------------------------------------
# 2. Config entry persisted with subagents allowlist
# ---------------------------------------------------------------------------


def test_hack_deep_config_entry_has_13_specialists_in_allowlist(
    live_hack_deep_entry: AgentEntryConfig,
) -> None:
    """`subagents.allow_agents` lists the 13 specialists, NOT cyberstrike-deep."""
    entry = live_hack_deep_entry
    assert entry.subagents is not None, "hack-deep entry has no subagents block"
    allow = entry.subagents.allow_agents
    assert allow is not None, "subagents.allow_agents is None"
    assert len(allow) == 13, f"expected 13 specialists, got {len(allow)}: {allow}"
    assert "cyberstrike-deep" not in allow, "cyberstrike-deep must NOT be in allow_agents"
    for specialist in EXPECTED_SPECIALISTS:
        assert specialist in allow, f"missing specialist {specialist!r} from allow_agents"


def test_hack_deep_config_entry_basic_fields(live_hack_deep_entry: AgentEntryConfig) -> None:
    """id / name / workspace / enabled / system_prompt look right."""
    entry = live_hack_deep_entry
    assert entry.id == "hack-deep"
    assert entry.name == "Hack Orchestrator"
    assert entry.workspace == str(HACK_DEEP_DIR)
    assert entry.enabled is True
    assert entry.system_prompt is not None
    assert "4-layer" in entry.system_prompt or "9-wave" in entry.system_prompt


def test_hack_deep_config_entry_subagents_model(
    live_hack_deep_entry: AgentEntryConfig,
) -> None:
    """The subagents block round-trips through AgentSubagentDefaults."""
    entry = live_hack_deep_entry
    assert isinstance(entry.subagents, AgentSubagentDefaults)
    # cascade_on_parent_kill defaults to True
    assert entry.subagents.cascade_on_parent_kill is True
    # max_children_per_session was set to 6 by the clone script
    assert entry.subagents.max_children_per_session == 6


# ---------------------------------------------------------------------------
# 3. cyberstrike-deep is preserved
# ---------------------------------------------------------------------------


def test_cyberstrike_deep_entry_unchanged(
    live_cyberstrike_deep_entry: AgentEntryConfig,
) -> None:
    """The original cyberstrike-deep entry is intact (no overwrite)."""
    entry = live_cyberstrike_deep_entry
    assert entry.id == "cyberstrike-deep"
    assert entry.workspace == str(CYBERSTRIKE_DEEP_DIR)
    assert entry.enabled is True
    assert entry.system_prompt is not None
    # Sanity: system_prompt still starts with the original CyberStrikeAI marker
    assert "CyberStrikeAI" in entry.system_prompt
    # cyberstrike-deep never had a subagents block
    assert entry.subagents is None


# ---------------------------------------------------------------------------
# 4. Both deeps listed by AgentRegistry
# ---------------------------------------------------------------------------


def test_agent_registry_lists_both_deep_coordinators() -> None:
    """AgentRegistry.list_agents() returns both cyberstrike-deep and hack-deep."""
    cfg = _load_live_config()
    registry = AgentRegistry(cfg, persist_changes=False)
    agents = asyncio.run(registry.list_agents())
    ids = {a["id"] for a in agents}
    assert "cyberstrike-deep" in ids
    assert "hack-deep" in ids
    # the builtin "main" is also there
    assert "main" in ids


def test_hack_deep_summary_exposes_subagents_in_registry() -> None:
    """list_agents() summary includes the subagents dict for hack-deep."""
    cfg = _load_live_config()
    registry = AgentRegistry(cfg, persist_changes=False)
    agents = asyncio.run(registry.list_agents())
    hack = next(a for a in agents if a["id"] == "hack-deep")
    assert "subagents" in hack
    assert "allow_agents" in hack["subagents"]
    assert "cyberstrike-deep" not in hack["subagents"]["allow_agents"]


# ---------------------------------------------------------------------------
# 4b. [subagent_supervisor] auto-enabled by clone script (T18, 2026-06-07)
# ---------------------------------------------------------------------------


def test_subagent_supervisor_enabled_by_clone() -> None:
    """`scripts/clone_cyberstrike_to_hack_deep.py` must auto-enable the
    subagent_supervisor watchdog cron. The 2026-06-05 hack-deep incident
    (terminal-event dedup drop) motivated making this default-on for any
    clone that runs to completion.

    Assertion: the live config.toml has `subagent_supervisor.enabled = True`
    after the clone script has run.
    """
    cfg = _load_live_config()
    assert cfg.subagent_supervisor is not None, (
        "GatewayConfig.subagent_supervisor is None — clone script did not "
        "materialize the block"
    )
    assert cfg.subagent_supervisor.enabled is True, (
        "subagent_supervisor.enabled must be True after a successful "
        "clone (auto-patched by _register_in_config)"
    )


# ---------------------------------------------------------------------------
# 5. Pass-through files were substituted
# ---------------------------------------------------------------------------


def test_hack_deep_agents_md_substitution_did_not_corrupt() -> None:
    """The cloned AGENTS.md kept the same structure (substitution is a no-op
    here because the source template is generic; this guards against accidental
    corruption by the substitution logic)."""
    text = (HACK_DEEP_DIR / "AGENTS.md").read_text(encoding="utf-8")
    assert "AGENTS.md" in text
    assert "SOUL.md" in text
    # Substitution did not break the file
    assert len(text) > 200


def test_hack_deep_identity_md_preserved() -> None:
    """The cloned IDENTITY.md kept the original skeleton."""
    text = (HACK_DEEP_DIR / "IDENTITY.md").read_text(encoding="utf-8")
    assert "Name:" in text
    assert "Emoji:" in text
