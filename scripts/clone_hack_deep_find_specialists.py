#!/usr/bin/env python3
"""Clone the 6 specialist agents for hack-deep-find.

Phase 2 ships all 6 recon specialists. Each gets its own agent_id,
workspace, registry entry, and tool allowlist.

Specialists and their tools:
  - subdomain-discoverer : group:recon:dns
  - ip-resolver          : group:recon:dns
  - port-scanner         : group:recon:portscan
  - service-fingerprint  : group:recon:portscan + group:recon:http
  - endpoint-crawler     : group:recon:http
  - leaf-verifier        : group:recon:http

For each specialist:
1. Creates ``~/.opensquilla/agents/<specialist>/`` workspace.
2. Writes SOUL.md from the bundled ``opensquilla.agents.hack-deep-find.specialists.<name>``.
3. Writes a per-specialist ATTRIBUTION.md.
4. Writes ``.opensquilla/workspace-state.json``.
5. Registers the specialist with ``subagents.allow_agents=[]`` (no spawning).

Idempotent: re-run updates an existing entry's system_prompt + subagents +
tools instead of recreating.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# 2026-06-15 (unified-naming refactor): the specialists package
# directory now uses hyphens (``endpoint-crawler`` etc.). Python's
# `from X-Y import Z` syntax is illegal, so we import via
# importlib and pull the snake_case attribute aliases the package
# sets up in its __init__.py.
import importlib
_specialists_pkg = importlib.import_module(
    "opensquilla.agents.hack-deep-find.specialists"
)
endpoint_crawler = _specialists_pkg.endpoint_crawler
ip_resolver = _specialists_pkg.ip_resolver
leaf_verifier = _specialists_pkg.leaf_verifier
port_scanner = _specialists_pkg.port_scanner
service_fingerprint = _specialists_pkg.service_fingerprint
subdomain_discoverer = _specialists_pkg.subdomain_discoverer

HACK_DEEP_FIND_ID = "hack-deep-find"


def _specialist_spec(
    agent_id: str,
    name: str,
    description: str,
    soul_body: str,
    tools_allow: tuple[str, ...],
) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "name": name,
        "description": description,
        "tools_allow": tools_allow,
        "soul_body": soul_body,
    }


SPECIALISTS: tuple[dict[str, object], ...] = (
    _specialist_spec(
        "subdomain-discoverer",
        "Subdomain Discoverer",
        "ROOT_DOMAIN → SUB_DOMAIN enumeration specialist (Phase 2). "
        "Active DNS bruteforce with resolvable validation. "
        "allow_agents=[]. Tools: group:recon:dns.",
        subdomain_discoverer.SOUL_BODY,
        ("group:recon:dns", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "ip-resolver",
        "IP Resolver",
        "SUB_DOMAIN → IP resolution specialist. System resolver + DoH fallback. "
        "allow_agents=[]. Tools: group:recon:dns.",
        ip_resolver.SOUL_BODY,
        ("group:recon:dns", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "port-scanner",
        "Port Scanner",
        "IP → PORT discovery specialist. Stdlib asyncio + masscan / nmap fallback. "
        "allow_agents=[]. Tools: group:recon:portscan.",
        port_scanner.SOUL_BODY,
        ("group:recon:portscan", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "service-fingerprint",
        "Service Fingerprint",
        "PORT → SERVICE fingerprint specialist. Banner grab + HTTP probe + nmap service. "
        "allow_agents=[]. Tools: group:recon:portscan + group:recon:http.",
        service_fingerprint.SOUL_BODY,
        ("group:recon:portscan", "group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "endpoint-crawler",
        "Endpoint Crawler",
        "SERVICE → ENDPOINT discovery specialist. Directory bruteforce + JS analysis. "
        "allow_agents=[]. Tools: group:recon:http.",
        endpoint_crawler.SOUL_BODY,
        ("group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "leaf-verifier",
        "Leaf Verifier",
        "Any-type → reachability verifier. Confirms whether a node is a true leaf. "
        "allow_agents=[]. Tools: group:recon:http.",
        leaf_verifier.SOUL_BODY,
        ("group:recon:http", "group:fs", "group:sessions"),
    ),
)


def _write_soul(dst_dir: Path, soul_body: str) -> None:
    (dst_dir / "SOUL.md").write_text(soul_body, encoding="utf-8")


def _write_attribution(dst_dir: Path, agent_name: str, schema_name: str) -> None:
    body = (
        f"# ATTRIBUTION.md — {agent_name}\n\n"
        f"Specialist of hack-deep-find. Output evidence schema: `{schema_name}`.\n\n"
        "See the parent agent's `ATTRIBUTION.md` for the full evidence schema catalog.\n"
    )
    (dst_dir / "ATTRIBUTION.md").write_text(body, encoding="utf-8")


def _write_workspace_state(dst_dir: Path) -> None:
    state_dir = dst_dir / ".opensquilla"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "workspace-state.json").write_text(
        json.dumps(
            {
                "bootstrap_completed_at": "2026-06-14T00:00:00.000000Z",
                "schema_version": 1,
                "workspace_dir": str(dst_dir),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _create_memory_dir(dst_dir: Path) -> None:
    (dst_dir / "memory").mkdir(parents=True, exist_ok=True)


def _ensure_workspace(dst_dir: Path) -> None:
    if dst_dir.exists():
        return
    dst_dir.mkdir(parents=True, exist_ok=True)


# Per-specialist schema name (matches the evidence_schema they emit)
_SCHEMA_FOR_SPECIALIST = {
    "subdomain-discoverer": "subdomain-v1",
    "ip-resolver": "ip-v1",
    "port-scanner": "port-v1",
    "service-fingerprint": "service-v1",
    "endpoint-crawler": "endpoint-v1",
    "leaf-verifier": "leaf-v1",
}


async def _register_specialist(spec: dict[str, object]) -> None:
    """Register or update one specialist agent in ~/.opensquilla/config.toml."""
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

    agent_id = str(spec["agent_id"])
    name = str(spec["name"])
    description = str(spec["description"])
    tools_allow = list(spec["tools_allow"])  # type: ignore[arg-type]
    soul_body = str(spec["soul_body"])

    dst_dir = Path.home() / ".opensquilla" / "agents" / agent_id

    config_path = default_config_path()
    cfg: GatewayConfig = load_config(config_path)
    registry = AgentRegistry(cfg, config_path=str(config_path), persist_changes=False)

    subagents = AgentSubagentDefaults(
        allow_agents=[],  # specialists do not spawn
        max_children_per_session=0,
        cascade_on_parent_kill=True,
    )

    ids = {a.id for a in cfg.agents}

    if agent_id in ids:
        summary = await registry.update_agent(
            agent_id,
            name=name,
            description=description,
            workspace=str(dst_dir),
            enabled=True,
            system_prompt=soul_body,
            subagents=subagents,
            tools={"allow": list(tools_allow), "deny": ["group:asset_tree"]},
        )
        print(f"  = updated existing {summary['id']} (system_prompt + subagents + tools)")
    else:
        summary = await registry.create_agent(
            agent_id=agent_id,
            name=name,
            description=description,
            workspace=str(dst_dir),
            enabled=True,
            system_prompt=soul_body,
            subagents=subagents,
            tools={"allow": list(tools_allow), "deny": ["group:asset_tree"]},
        )
        print(f"  + registered {summary['id']} (tools.allow={tools_allow})")

    result = persist_config(cfg, path=str(config_path), restart_required=True)
    print(f"  + persisted to {result.path}")


def main() -> None:
    print(f"Cloning hack-deep-find specialists ({len(SPECIALISTS)} total)")
    for spec in SPECIALISTS:
        agent_id = str(spec["agent_id"])
        dst_dir = Path.home() / ".opensquilla" / "agents" / agent_id
        schema = _SCHEMA_FOR_SPECIALIST[agent_id]
        print(f"\n→ {agent_id} (schema={schema})")
        _ensure_workspace(dst_dir)
        _write_soul(dst_dir, str(spec["soul_body"]))
        print(f"  + wrote SOUL.md ({len(str(spec['soul_body']))} chars)")
        _write_attribution(dst_dir, str(spec["name"]), schema)
        _write_workspace_state(dst_dir)
        _create_memory_dir(dst_dir)
        asyncio.run(_register_specialist(spec))

    print(
        f"\nClone complete ({len(SPECIALISTS)} specialists). "
        "Run scripts/clone_hack_deep_find.py next to refresh the "
        "LLM-coordinator's subagents.allow_agents list."
    )


if __name__ == "__main__":
    main()