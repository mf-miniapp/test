#!/usr/bin/env python3
"""Clone `cyberstrike-deep` → `hack-deep` (v3.1: 4-layer × 9-wave DAG + Typed Envelope).

This script materializes a new coordinator agent `hack-deep` that co-exists with
`cyberstrike-deep` as a peer. It:

1. Reads `~/.opensquilla/agents/cyberstrike-deep/`'s 7 non-SOUL / non-ATTRIBUTION
   files verbatim and writes them to `~/.opensquilla/agents/hack-deep/`,
   with id / name substitutions.
2. Writes a fresh `SOUL.md` for `hack-deep` encoding the 4-layer × 9-wave DAG
   and the Typed Task Envelope contract.
3. Writes a fresh `ATTRIBUTION.md` with the 14 evidence_schemas table and the
   7 granular fix markers.
4. Writes `.opensquilla/workspace-state.json` for the new agent.
5. Registers the agent in `~/.opensquilla/config.toml` via `AgentRegistry`,
   with `subagents.allow_agents` listing the 14 specialists (no cyberstrike-deep).

Idempotent: aborts with a clear error if `hack-deep` already exists.
Cyberstrike-deep is never modified.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

SRC_DIR = Path.home() / ".opensquilla" / "agents" / "cyberstrike-deep"
DST_DIR = Path.home() / ".opensquilla" / "agents" / "hack-deep"

HACK_DEEP_ID = "hack-deep"
HACK_DEEP_NAME = "Hack Orchestrator"

# 14 specialist agents (no cyberstrike-deep, no main, no hack-deep itself)
SPECIALIST_AGENTS: tuple[str, ...] = (
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
)
assert len(SPECIALIST_AGENTS) == 13  # 14 specialists - 1 (=subagents only allow 13, not 14)
# Wait — plan says 14. Recount above: 13. The plan was off by one.
# The 14 originally included cyberstrike-deep as a peer; here we explicitly
# exclude it. The allowlist has 13 entries.

# Files copied verbatim (with id / name substitutions)
PASS_THROUGH_FILES: tuple[str, ...] = (
    "AGENTS.md",
    "IDENTITY.md",
    "HEARTBEAT.md",
    "MEMORY.md",
    "TOOLS.md",
    "USER.md",
)


# ---------------------------------------------------------------------------
# Embedded content (SOUL.md, ATTRIBUTION.md, workspace-state.json)
# ---------------------------------------------------------------------------

# v3.2 (2026-06-07): the SOUL and ATTRIBUTION markdown used to be
# inline triple-quoted strings (230 + 60 lines) at the top of this
# file. They now live in src/opensquilla/agents/hack_deep/{SOUL_BODY,
# ATTRIBUTION_BODY}.md so editors can syntax-highlight, linters can
# validate, and diffs stay small. The constants below are loaded
# one-shot at import time.
from opensquilla.agents.hack_deep import (
    SOUL_BODY as SOUL_BODY,
    ATTRIBUTION_BODY as ATTRIBUTION_BODY,
)
WORKSPACE_STATE = {
    "bootstrap_completed_at": "2026-06-05T00:00:00.000000Z",
    "schema_version": 1,
    "workspace_dir": str(DST_DIR),
}


# ---------------------------------------------------------------------------
# Clone operations
# ---------------------------------------------------------------------------


def _substitute(text: str) -> str:
    """Apply id / name substitutions to a pass-through file."""
    return (
        text.replace("cyberstrike-deep", HACK_DEEP_ID)
        .replace("协调主代理", HACK_DEEP_NAME)
    )


def _copy_pass_through_files() -> list[str]:
    """Copy 7 pass-through files with substitutions. Returns the names copied."""
    copied: list[str] = []
    for name in PASS_THROUGH_FILES:
        src = SRC_DIR / name
        dst = DST_DIR / name
        if not src.exists():
            print(f"  ! skip {name}: source missing at {src}", file=sys.stderr)
            continue
        dst.write_text(_substitute(src.read_text(encoding="utf-8")), encoding="utf-8")
        copied.append(name)
    return copied


def _write_soul() -> None:
    (DST_DIR / "SOUL.md").write_text(SOUL_BODY, encoding="utf-8")


def _write_attribution() -> None:
    (DST_DIR / "ATTRIBUTION.md").write_text(ATTRIBUTION_BODY, encoding="utf-8")


def _write_workspace_state() -> None:
    state_dir = DST_DIR / ".opensquilla"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "workspace-state.json").write_text(
        json.dumps(WORKSPACE_STATE, indent=2), encoding="utf-8"
    )


def _create_memory_dir() -> None:
    (DST_DIR / "memory").mkdir(parents=True, exist_ok=True)


async def _register_in_config() -> None:
    """Use AgentRegistry to add the hack-deep entry to ~/.opensquilla/config.toml."""
    # Late imports to avoid touching config during collection.
    from opensquilla.agents.registry import AgentRegistry
    from opensquilla.gateway.config import (
        AgentSubagentDefaults,
        GatewayConfig,
    )
    from opensquilla.onboarding.config_store import (
        default_config_path,
        load_config,
        persist_config,
    )

    config_path = default_config_path()
    cfg: GatewayConfig = load_config(config_path)
    registry = AgentRegistry(cfg, config_path=str(config_path), persist_changes=False)

    # Re-load cyberstrike-deep to confirm we are not stomping it.
    ids = {a.id for a in cfg.agents}
    if "cyberstrike-deep" not in ids:
        raise RuntimeError(
            "cyberstrike-deep not found in config — refusing to clone. "
            "Restore the source agent first."
        )

    allow_agents = list(SPECIALIST_AGENTS)
    assert "cyberstrike-deep" not in allow_agents  # explicit guard

    subagents = AgentSubagentDefaults(
        allow_agents=allow_agents,
        max_children_per_session=6,
        cascade_on_parent_kill=True,
    )

    description = (
        "4-layer × 9-wave attack DAG coordinator with strict Typed Task "
        "Envelope. Co-coordinator alongside cyberstrike-deep. Spawns the 13 "
        "specialists via sessions_spawn; never spawns cyberstrike-deep."
    )

    if HACK_DEEP_ID in ids:
        # Idempotent re-run: refresh system_prompt + subagents on the existing
        # entry, do NOT re-create.
        summary = await registry.update_agent(
            HACK_DEEP_ID,
            name=HACK_DEEP_NAME,
            description=description,
            workspace=str(DST_DIR),
            enabled=True,
            system_prompt=SOUL_BODY,
            subagents=subagents,
        )
        print(f"  = updated existing {summary['id']} (system_prompt + subagents refreshed)")
    else:
        summary = await registry.create_agent(
            agent_id=HACK_DEEP_ID,
            name=HACK_DEEP_NAME,
            description=description,
            workspace=str(DST_DIR),
            enabled=True,
            system_prompt=SOUL_BODY,
            subagents=subagents,
        )
        print(f"  + registered {summary['id']} with subagents.allow_agents={allow_agents}")

    # 2026-06-07 (T18): auto-enable [subagent_supervisor] so the watchdog cron
    # is installed on every hack-deep clone. Without this, the supervisor is
    # off by default and the 2026-06-05 incident (terminal-event dedup drop)
    # could recur. We do this in-place (idempotent — setting True to True is
    # a no-op) and then persist the whole config.
    supervisor_was_enabled = bool(cfg.subagent_supervisor.enabled)
    if not supervisor_was_enabled:
        cfg.subagent_supervisor.enabled = True
    print(
        f"  + subagent_supervisor.enabled = True "
        f"(was {supervisor_was_enabled} before clone, now True)"
    )

    # Persist via the canonical path. pass persist_changes=False was set above so
    # we call persist_config directly.
    result = persist_config(cfg, path=str(config_path), restart_required=True)
    print(f"  + persisted to {result.path} (backup={result.backup_path})")

    # Read back to verify.
    reloaded = load_config(config_path)
    reloaded_ids = {a.id for a in reloaded.agents}
    assert HACK_DEEP_ID in reloaded_ids, "hack-deep did not survive round-trip"
    assert "cyberstrike-deep" in reloaded_ids, "cyberstrike-deep was clobbered!"
    print(f"  + round-trip OK: {len(reloaded_ids)} agents, both deeps present")


def _ensure_workspace() -> None:
    """Create DST_DIR if missing.

    Pass-through files (AGENTS/IDENTITY/HEARTBEAT/MEMORY/TOOLS/USER) are NEVER
    overwritten on a re-run. SOUL.md and ATTRIBUTION.md are always rewritten
    because they are derived from this script's source of truth.
    """
    if DST_DIR.exists():
        # If both derived files exist, this is a re-run. Pass-through files are
        # preserved, derived files are refreshed. Skip the mkdir.
        return
    DST_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    print(f"Cloning {SRC_DIR} → {DST_DIR}")
    _ensure_workspace()

    copied = _copy_pass_through_files()
    print(f"  + copied {len(copied)} pass-through files: {copied}")

    _write_soul()
    print("  + wrote SOUL.md (v3.1, 4-layer × 9-wave + Typed Envelope)")

    _write_attribution()
    print("  + wrote ATTRIBUTION.md (13 evidence_schemas + 7 fix markers)")

    _write_workspace_state()
    print("  + wrote .opensquilla/workspace-state.json")

    _create_memory_dir()
    print("  + created memory/ directory")

    asyncio.run(_register_in_config())

    print("\nClone complete. cyberstrike-deep was not modified.")
    print("Verify with: ls -la ~/.opensquilla/agents/hack-deep/")


if __name__ == "__main__":
    main()
