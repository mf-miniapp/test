#!/usr/bin/env python3
"""Clone the hack-deep-ex LLM-coordinator agent (3-harness split v1.0).

This script materializes the **post-exploitation** owner in the
2026-06-15 3-harness split (see
``opensquilla.attack_dispatch.waves.OwnerAgent``). The coordinator
is a **pure LLM orchestrator** — there is no Python driver. It
reads its SOUL and uses ``sessions_spawn`` + ``sessions_yield``
to drive the W5-W8 post-exploitation waves.

The 3-harness split rationale (full version in
``docs/agent_system_3harness.md``, forthcoming):

  hack-deep-find  : asset discovery only (W0.5 W1 W1.5 W1.5c W2.5 W3.5)
  hack-deep       : attack only         (W0 W1.6* W2 W3 W4 W4.5*)
  hack-deep-ex    : post-exploitation   (W5 W6 W6.5* W7 W8)

hack-deep-ex:

1. Reads SOUL_BODY / ATTRIBUTION_BODY from
   ``opensquilla.agents.hack-deep-ex``.
2. Creates ``~/.opensquilla/agents/hack-deep-ex/``.
3. Writes SOUL.md, ATTRIBUTION.md, workspace-state.json.
4. Registers the agent with:
   - ``subagents.allow_agents`` = the 5 post-exploitation
     specialist ids (privilege-escalation, lateral-movement,
     persistence-maintenance, impact-exfiltration, cleanup-rollback,
     reporting-remediation). The ``hack-deep`` allow entry is NOT
     needed for normal flow; the operator can spawn hack-deep-ex
     directly. If a reverse-handoff is needed, the LLM should
     issue a typed `POST-EXPLOIT-COMPLETE.ex.1 -> hack-deep` envelope.
   - ``tools.allow`` = ``group:sessions`` + ``group:fs``.

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
_hack_deep_ex_pkg = importlib.import_module("opensquilla.agents.hack-deep-ex")
SOUL_BODY = _hack_deep_ex_pkg.SOUL_BODY
ATTRIBUTION_BODY = _hack_deep_ex_pkg.ATTRIBUTION_BODY

DST_DIR = Path.home() / ".opensquilla" / "agents" / "hack-deep-ex"

HACK_DEEP_EX_ID = "hack-deep-ex"
HACK_DEEP_EX_NAME = "Hack Deep Ex (Post-Exploitation Orchestrator)"

# 6 post-exploitation specialists (the only agents hack-deep-ex can spawn).
# This is a STRICT subset of the original 13 specialists; the attack
# (W0-W4) and recon (W0.5-W3.5) specialists are NOT in the allowlist.
SPECIALIST_AGENTS: tuple[str, ...] = (
    "privilege-escalation",
    "lateral-movement",
    "persistence-maintenance",
    "impact-exfiltration",
    "cleanup-rollback",
    "reporting-remediation",
)

# Coordinator's tool allowlist. recon:* and attack tools are explicitly
# denied (they belong to hack-deep-find / hack-deep respectively).
COORDINATOR_TOOLS_ALLOW: tuple[str, ...] = (
    "group:sessions",
    "group:fs",
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
                "bootstrap_completed_at": "2026-06-15T00:00:00.000000Z",
                "schema_version": 1,
                "workspace_dir": str(DST_DIR),
                "owner_role": "post-exploitation",
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

    subagents = AgentSubagentDefaults(
        allow_agents=list(SPECIALIST_AGENTS),
    )

    description = (
        "Post-exploitation orchestrator. 3-harness split (2026-06-15). "
        "Consumes post-exploit-complete-v1 handoff from hack-deep and "
        "drives W5 (privesc) -> W6 (lateral) -> W7 (persist + impact, "
        "2-way fan-out) -> W8 (cleanup + report, 2-way fan-out). "
        "Cannot spawn attack or recon specialists; runtime "
        "check_authorization() rejects such attempts."
    )

    existing = registry._find_entry(HACK_DEEP_EX_ID)  # type: ignore[attr-defined]
    if existing is not None:
        await registry.update_agent(
            HACK_DEEP_EX_ID,
            name=HACK_DEEP_EX_NAME,
            description=description,
            workspace=str(DST_DIR),
            provider="mimo",
            model="mimo-v2.5-pro",
            tier="c1",
            allowed_tiers=["c1", "c2"],
            max_history_turns=8,
            enabled=True,
            system_prompt=SOUL_BODY,
            subagents=subagents,
        )
        print(
            f"  = updated existing {HACK_DEEP_EX_ID} "
            f"(system_prompt + subagents refreshed)"
        )
    else:
        await registry.create_agent(
            agent_id=HACK_DEEP_EX_ID,
            name=HACK_DEEP_EX_NAME,
            description=description,
            workspace=str(DST_DIR),
            enabled=True,
            system_prompt=SOUL_BODY,
            subagents=subagents,
        )
        print(
            f"  + registered {HACK_DEEP_EX_ID} "
            f"with subagents.allow_agents={list(SPECIALIST_AGENTS)}"
        )

    # The tool allowlist lives on the config, not on AgentEntryConfig;
    # mirror it via persist_config so the gateway's policy layer picks
    # it up. We look for the [tools] section in the existing config
    # and add a per-agent override if not present.
    await _set_tool_allowlist(cfg, HACK_DEEP_EX_ID, COORDINATOR_TOOLS_ALLOW)

    result = persist_config(cfg, path=str(config_path), restart_required=True)
    print(f"  + persisted to {result.path}")


async def _set_tool_allowlist(
    cfg: "GatewayConfig", agent_id: str, allow: tuple[str, ...]
) -> None:
    """Best-effort: set ``[subagents.<agent_id>.tools.allow]`` on the config.

    The GatewayConfig is a Pydantic model; we set the field via
    ``model_copy`` to avoid mutating the shared config. If the
    config model doesn't expose this field, we silently skip —
    the operator can set it via the config.toml directly.
    """
    try:
        from opensquilla.gateway.config import AgentSubagentDefaults
    except ImportError:
        return
    # The AgentEntryConfig has a `tools` field that accepts
    # ``{"allow": [...], "deny": [...]}``. We re-set it on the entry.
    entry = next(
        (a for a in cfg.agents if a.id == agent_id), None
    )
    if entry is None:
        return
    entry.tools = {"allow": list(allow), "deny": []}


def main() -> None:
    print(f"Cloning hack-deep-ex LLM-coordinator → {DST_DIR}")
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
