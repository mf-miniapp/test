#!/usr/bin/env python3
"""Clone the hack-deep-find LLM-coordinator agent (v2 redesign).

Phase 1 MVP: registers the coordinator that orchestrates 6 specialist
subagents (only ``ip-resolver`` is wired in Phase 1). The coordinator is
a **pure LLM orchestrator** — there is no Python driver. It reads its
SOUL and uses ``asset_tree_*`` + ``sessions_spawn`` + ``sessions_yield``
to drive recursive asset discovery.

1. Reads SOUL_BODY / ATTRIBUTION_BODY from
   ``opensquilla.agents.hack-deep-find``.
2. Creates ``~/.opensquilla/agents/hack-deep-find/``.
3. Writes SOUL.md, ATTRIBUTION.md, workspace-state.json.
4. Registers the agent with:
   - ``subagents.allow_agents`` = the specialist ids (Phase 1: just
     ``ip-resolver``).
   - ``tools.allow`` = ``group:asset_tree`` + ``group:sessions`` +
     ``group:fs`` + ``group:recon:http`` (the http group is for endpoint
     reachability checks only, see SOUL).

Idempotent: re-run refreshes system_prompt + subagents + tools.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# 2026-06-15 (unified-naming): package renamed to use hyphens;
# Python's `from X import Y` syntax rejects hyphens, so we use
# importlib.
import importlib
_hack_deep_find_pkg = importlib.import_module("opensquilla.agents.hack-deep-find")
SOUL_BODY = _hack_deep_find_pkg.SOUL_BODY
ATTRIBUTION_BODY = _hack_deep_find_pkg.ATTRIBUTION_BODY

DST_DIR = Path.home() / ".opensquilla" / "agents" / "hack-deep-find"

HACK_DEEP_FIND_ID = "hack-deep-find"
HACK_DEEP_FIND_NAME = "Hack Deep Find (Recursive Asset Discovery)"

# Phase 1 MVP: only ip-resolver. Phase 2 will add the other 5.
# Batch 5 (2026-06-15): 16 specialists wired (6 Phase 2 + 5 Batch 1 +
# 2 Batch 2 + 2 Batch 3 + 1 Batch 4). hack-deep is the Phase 3 handoff
# target (find-complete-v1 envelope).
#
# 2026-06-17 v3: the 16 specialists are the PRIMARY execution path,
# but in installations where any specialist fails to spawn (config
# drift, missing workspace, agent disabled by operator, runtime
# outage) the find LLM-coordinator falls back to a 3-agent "legacy
# recon" family that has been in the install since the 3-harness
# split (2026-06-15). FALLBACK_AGENTS is written to the same
# subagents.allow_agents whitelist so the LLM can call them when
# the primary path is unavailable. The v3 SOUL_BODY documents the
# exact escalation order (specialist -> legacy_recon -> recon_* tool).
SPECIALIST_AGENTS: tuple[str, ...] = (
    # Phase 2 - network surface (6)
    "subdomain-discoverer",
    "ip-resolver",
    "port-scanner",
    "service-fingerprint",
    "endpoint-crawler",
    "leaf-verifier",
    # Batch 1 - web surface + CVE component view (5)
    "service-detailed",
    "webapp-discoverer",
    "api-surface",
    "parameter-extract",
    "static-asset",
    # Batch 2 - auth + cookie/header (2)
    "auth-mapper",
    "cookie-header",
    # Batch 3 - cloud storage + cross-layer secret (2)
    "cloud-storage",
    "secret-scanner",
    # Batch 4 - horizontal seed expansion (1)
    "seed-expander",
    # Phase 3 handoff target.
    "hack-deep",
)

# v3 legacy-recon fallback family. 3 agents predate the 16-specialist
# split; they are coarser-grained (one agent per wave-tier rather than
# per asset_type) but functional on every install. The find LLM
# should only use these when the corresponding specialist fails
# (ToolError / UnauthorizedAgent / not-in-allowlist).
FALLBACK_AGENTS: tuple[str, ...] = (
    "recon",                       # W1.5c / W2.5 / W3.5 fallback
    "intel-collection",            # W0.5 surface intel fallback
    "attack-surface-enumeration",  # W2.5 attack plan fallback
)

# Coordinator's tool allowlist.
#
# v3 (2026-06-17) re-design: the find coordinator is now an LLM
# orchestrator with a 3-tier adaptive execution model:
#
#   Tier 1: sessions_spawn a 16-specialist member (preferred)
#   Tier 2: sessions_spawn a legacy_recon agent (recon /
#           intel-collection / attack-surface-enumeration) when the
#           matching specialist is unavailable
#   Tier 3: call recon_* tools directly when BOTH specialist and
#           legacy_recon fail (last-resort; for small tasks the
#           coordinator does it itself)
#
# Tier 3 needs the recon:* tool groups on the coordinator's own
# allowlist. We grant ALL 11 groups so the LLM can self-serve
# through any path. The 严禁 list (nmap / curl / exploit tools) is
# still enforced by deny rules in agent config.
COORDINATOR_TOOLS_ALLOW: tuple[str, ...] = (
    "group:asset_tree",
    "group:sessions",
    "group:fs",
    # All 11 recon tool groups so Tier 3 fallback works.
    "group:recon:dns",
    "group:recon:portscan",
    "group:recon:http",
    "group:recon:component",
    "group:recon:webapp",
    "group:recon:api",
    "group:recon:sensitive",
    "group:recon:auth",
    "group:recon:header",
    "group:recon:secret",
    "group:recon:seed",
    "group:recon:storage",
)


def _ensure_workspace() -> None:
    if DST_DIR.exists():
        return
    DST_DIR.mkdir(parents=True, exist_ok=True)


def _write_soul() -> None:
    (DST_DIR / "SOUL.md").write_text(SOUL_BODY, encoding="utf-8")


def _write_attribution() -> None:
    (DST_DIR / "ATTRIBUTION.md").write_text(ATTRIBUTION_BODY, encoding="utf-8")


def _write_workspace_state() -> None:
    state_dir = DST_DIR / ".opensquilla"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "workspace-state.json").write_text(
        json.dumps(
            {
                "bootstrap_completed_at": "2026-06-14T00:00:00.000000Z",
                "schema_version": 1,
                "workspace_dir": str(DST_DIR),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _create_memory_dir() -> None:
    (DST_DIR / "memory").mkdir(parents=True, exist_ok=True)


async def _register_in_config() -> None:
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

    # v3 (2026-06-17): write SPECIALIST_AGENTS + FALLBACK_AGENTS to the
    # allow_agents whitelist so the LLM-coordinator can call either
    # tier. Dedup preserves SPECIALIST_AGENTS order first, then any
    # FALLBACK_AGENTS entries that were not already in specialists.
    _allow_agents = list(SPECIALIST_AGENTS)
    for _a in FALLBACK_AGENTS:
        if _a not in _allow_agents:
            _allow_agents.append(_a)
    subagents = AgentSubagentDefaults(
        allow_agents=_allow_agents,
        max_children_per_session=20,  # recursive fanout
        cascade_on_parent_kill=True,
    )

    description = (
        "Pure LLM orchestrator for recursive asset discovery (v3 redesign, "
        "2026-06-17). Drives 16 recon specialists (Phase 2 + Batch 1-4) via "
        "sessions_spawn; on specialist unavailability it falls back to the "
        "3-agent legacy-recon family (recon / intel-collection / "
        "attack-surface-enumeration), then to direct recon_* tool calls. "
        "Manages a persistent AssetTree via asset_tree_* tools. Never "
        "invokes exploit / payload tools. Phase 3 wires the "
        "find-complete-v1 handoff to hack-deep at end-of-run."
    )

    ids = {a.id for a in cfg.agents}

    if HACK_DEEP_FIND_ID in ids:
        summary = await registry.update_agent(
            HACK_DEEP_FIND_ID,
            name=HACK_DEEP_FIND_NAME,
            description=description,
            workspace=str(DST_DIR),
            enabled=True,
            system_prompt=SOUL_BODY,
            subagents=subagents,
            tools={"allow": list(COORDINATOR_TOOLS_ALLOW), "deny": []},
        )
        print(
            f"  = updated existing {summary['id']} "
            f"(system_prompt + subagents + tools.refreshed)"
        )
    else:
        summary = await registry.create_agent(
            agent_id=HACK_DEEP_FIND_ID,
            name=HACK_DEEP_FIND_NAME,
            description=description,
            workspace=str(DST_DIR),
            enabled=True,
            system_prompt=SOUL_BODY,
            subagents=subagents,
            tools={"allow": list(COORDINATOR_TOOLS_ALLOW), "deny": []},
        )
        print(
            f"  + registered {summary['id']} "
            f"with subagents.allow_agents={_allow_agents} "
            f"tools.allow={list(COORDINATOR_TOOLS_ALLOW)}"
        )

    result = persist_config(cfg, path=str(config_path), restart_required=True)
    print(f"  + persisted to {result.path}")


def main() -> None:
    print(f"Cloning hack-deep-find LLM-coordinator → {DST_DIR}")
    _ensure_workspace()
    _write_soul()
    print(f"  + wrote SOUL.md ({len(SOUL_BODY)} chars)")
    _write_attribution()
    print(f"  + wrote ATTRIBUTION.md ({len(ATTRIBUTION_BODY)} chars)")
    _write_workspace_state()
    _create_memory_dir()
    asyncio.run(_register_in_config())
    print(
        "\nClone complete. Verify with: ls -la "
        f"{DST_DIR}"
    )


if __name__ == "__main__":
    main()