#!/usr/bin/env python3
"""Clone the 13 specialist agents for hack-deep-find (v4.5, 2026-06-18).

v4.5 contract: hack-deep-find is "discover every asset + verify real",
NOT "rank attack surfaces". v4.5 changes vs v4:

  - REMOVED: vuln-prioritizer (越界: nuclei scan is attack-side work)
  - RENAMED: surface-aggregator -> tree-finalizer
    (output schema attack-priority-v1 -> asset-tree-v1; no attack scoring)
  - CLEANED: secret-scanner blast_radius field marked v4.5 DEPRECATED
  - Active specialist count: 13

vs the v3-era this script originally supported (16 specialists, with
8 retired in v4 due to 3-way merges), v4.5 has 13 active specialists
organized in 5 tiers.

Tier 1 (network surface, 5):
  - domain-expander       : group:recon:dns + group:recon:seed
  - port-scanner          : group:recon:portscan
  - service-fingerprint   : group:recon:portscan + group:recon:http
  - endpoint-crawler      : group:recon:http
  - storage-discoverer    : group:recon:storage + group:recon:dns

Tier 2 (web surface, 4):
  - webapp-discoverer     : group:recon:webapp
  - component-detector    : group:recon:component
  - api-surface-mapper    : group:recon:api + group:recon:http
  - content-classifier    : group:recon:http + group:recon:sensitive
                             + group:recon:auth + group:recon:header

Tier 3 (horizontal / cross-layer, 2):
  - osint-collector       : group:recon:seed (+ external bins)
  - secret-scanner        : group:recon:secret + group:recon:http

Tier 4 (synthesis, 1):
  - tree-finalizer        : (read_file only + recon_http_probe for HEAD
                             liveness recheck; no recon_nuclei_scan,
                             no exploitability scoring)

Tier 5 (terminal, 1):
  - leaf-verifier         : group:recon:http

Total: 13 specialists.

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
# directory uses hyphens (``endpoint-crawler`` etc.). Python's
# `from X-Y import Z` syntax is illegal, so we import via
# importlib and pull the snake_case attribute aliases the package
# sets up in its __init__.py.
import importlib
_specialists_pkg = importlib.import_module(
    "opensquilla.agents.hack-deep-find.specialists"
)

# v4.5 active specialists (13). The 8 v3 retired names + 1 v4 retired
# vuln-prioritizer + 1 v4 renamed surface-aggregator are NOT imported
# here; their directories have been physically removed.
domain_expander = _specialists_pkg.domain_expander
port_scanner = _specialists_pkg.port_scanner
service_fingerprint = _specialists_pkg.service_fingerprint
endpoint_crawler = _specialists_pkg.endpoint_crawler
storage_discoverer = _specialists_pkg.storage_discoverer
webapp_discoverer = _specialists_pkg.webapp_discoverer
component_detector = _specialists_pkg.component_detector
api_surface_mapper = _specialists_pkg.api_surface_mapper
content_classifier = _specialists_pkg.content_classifier
osint_collector = _specialists_pkg.osint_collector
secret_scanner = _specialists_pkg.secret_scanner
tree_finalizer = _specialists_pkg.tree_finalizer
leaf_verifier = _specialists_pkg.leaf_verifier

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
    # ── Tier 1 (network surface, 5) ────────────────────────────
    _specialist_spec(
        "domain-expander",
        "Domain Expander",
        "ROOT_DOMAIN -> subdomains + IPs + extra_seeds specialist (v4 merge "
        "of subdomain-discoverer + ip-resolver + seed-expander). One sessions_spawn "
        "completes F0 horizontal expansion. allow_agents=[]. "
        "Tools: group:recon:dns + group:recon:seed.",
        domain_expander.SOUL_BODY,
        ("group:recon:dns", "group:recon:seed", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "port-scanner",
        "Port Scanner",
        "IP -> PORT discovery specialist. Stdlib asyncio + masscan / nmap fallback. "
        "allow_agents=[]. Tools: group:recon:portscan.",
        port_scanner.SOUL_BODY,
        ("group:recon:portscan", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "service-fingerprint",
        "Service Fingerprint",
        "PORT -> SERVICE fingerprint specialist. Banner grab + HTTP probe + nmap service. "
        "allow_agents=[]. Tools: group:recon:portscan + group:recon:http.",
        service_fingerprint.SOUL_BODY,
        ("group:recon:portscan", "group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "endpoint-crawler",
        "Endpoint Crawler",
        "SERVICE -> ENDPOINT discovery specialist. Directory bruteforce + JS analysis. "
        "allow_agents=[]. Tools: group:recon:http.",
        endpoint_crawler.SOUL_BODY,
        ("group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "storage-discoverer",
        "Storage Discoverer",
        "SUB_DOMAIN -> STORAGE + STORAGE_OBJECT specialist (v4 rename of cloud-storage). "
        "Discover public S3/OSS/GCS/Azure Blob buckets via naming variants. "
        "allow_agents=[]. Tools: group:recon:storage + group:recon:dns.",
        storage_discoverer.SOUL_BODY,
        ("group:recon:storage", "group:recon:dns", "group:fs", "group:sessions"),
    ),
    # ── Tier 2 (web surface, 4) ────────────────────────────────
    _specialist_spec(
        "webapp-discoverer",
        "WebApp Discoverer",
        "SERVICE -> URL specialist. Identify distinct web applications behind a "
        "single ip:port via vhost / port / path modes. Tech stack + app type + "
        "auth context. allow_agents=[]. Tools: group:recon:webapp.",
        webapp_discoverer.SOUL_BODY,
        ("group:recon:webapp", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "component-detector",
        "Component Detector (CVE Component View)",
        "SERVICE -> COMPONENT specialist (v4 rename of service-detailed). "
        "Component-level fingerprinting (product + version + CPE 2.3) for NVD CVE "
        "matching. Multi-source: CPE resolve, JS extract, TLS cert, favicon hash. "
        "Note: cpe_resolve is a static dictionary lookup, NOT a vulnerability scan. "
        "NVD correlation is done by hack-deep W2, not by find. allow_agents=[]. "
        "Tools: group:recon:component.",
        component_detector.SOUL_BODY,
        ("group:recon:component", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "api-surface-mapper",
        "API Surface Mapper",
        "URL -> API_SCHEMA + ENDPOINT + PARAMETER specialist (v4 merge of api-surface "
        "+ parameter-extract). OpenAPI/Swagger parse, GraphQL introspection, "
        "recursive JS crawl, path normalization, auth probe, parameter extraction "
        "in one wave barrier. allow_agents=[]. "
        "Tools: group:recon:api + group:recon:http.",
        api_surface_mapper.SOUL_BODY,
        ("group:recon:api", "group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "content-classifier",
        "Content Classifier",
        "URL -> STATIC_ASSET + AUTH_SURFACE + COOKIE + HEADER specialist (v4 merge "
        "of static-asset + auth-mapper + cookie-header). One HTTP pass produces all 4 "
        "cross-cutting signals. allow_agents=[]. "
        "Tools: group:recon:http + group:recon:sensitive + group:recon:auth + group:recon:header.",
        content_classifier.SOUL_BODY,
        (
            "group:recon:http",
            "group:recon:sensitive",
            "group:recon:auth",
            "group:recon:header",
            "group:fs",
            "group:sessions",
        ),
    ),
    # ── Tier 3 (horizontal / cross-layer, 2) ──────────────────
    _specialist_spec(
        "osint-collector",
        "OSINT Collector",
        "ROOT_DOMAIN -> external-source breadth specialist (v4 NEW; legacy "
        "intel-collection's external bins). Shodan / Censys / FOFA / VirusTotal / "
        "Hunter / passive DNS / cert-transparency. allow_agents=[]. "
        "Tools: group:recon:seed (+ external bins: subfinder, amass, shodan, "
        "censys, fofa, quake, virustotal, hunter).",
        osint_collector.SOUL_BODY,
        ("group:recon:seed", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "secret-scanner",
        "Secret Scanner",
        "Cross-layer -> SECRET specialist. Scan URL/ENDPOINT/STATIC_ASSET/"
        "API_SCHEMA/STORAGE/STORAGE_OBJECT children for leaked credentials, "
        "private keys, internal hosts, JWTs, GitHub PATs, etc. Regex + "
        "entropy + source-specific (JS bundle, git history, env dump). "
        "v4.5: blast_radius field is DEPRECATED (attack-side view). "
        "allow_agents=[]. Tools: group:recon:secret + group:recon:http.",
        secret_scanner.SOUL_BODY,
        ("group:recon:secret", "group:recon:http", "group:fs", "group:sessions"),
    ),
    # ── Tier 4 (synthesis, 1) ──────────────────────────────────
    _specialist_spec(
        "tree-finalizer",
        "Tree Finalizer",
        "AssetTree -> asset-tree-v1 specialist (v4.5 RENAME from surface-aggregator). "
        "Read-only coverage report + URL liveness recheck. "
        "v4.5: NO attack-priority-v1, NO exploitability_score, NO CVE correlation, "
        "NO specialist recommendation. Those tasks belong to hack-deep W2. "
        "allow_agents=[]. Tools: group:fs only (read_file) + group:recon:http "
        "(recon_http_probe HEAD-only for liveness recheck). "
        "Explicitly DENIES: recon_nuclei_scan, recon_directory_bruteforce, any "
        "active discovery / vulnerability tool.",
        tree_finalizer.SOUL_BODY,
        ("group:fs", "group:recon:http", "group:sessions"),
    ),
    # ── Tier 5 (terminal, 1) ──────────────────────────────────
    _specialist_spec(
        "leaf-verifier",
        "Leaf Verifier",
        "Any-type -> reachability verifier. Confirms whether a node is a true leaf. "
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


# Per-specialist schema name (matches the evidence_schema they emit).
# v4.5 contract: 13 active specialists, no attack-priority-v1 (moved
# to hack-deep W2), vuln-priority-v1 (v4.4) removed entirely.
_SCHEMA_FOR_SPECIALIST = {
    # Tier 1
    "domain-expander": "domain-expansion-v1",
    "port-scanner": "port-v1",
    "service-fingerprint": "service-v1",
    "endpoint-crawler": "endpoint-v1",
    "storage-discoverer": "cloud-storage-v1",
    # Tier 2
    "webapp-discoverer": "webapp-v1",
    "component-detector": "component-v1",
    "api-surface-mapper": "api-surface-v1",
    "content-classifier": "content-classification-v1",
    # Tier 3
    "osint-collector": "osint-v1",
    "secret-scanner": "secret-v1",
    # Tier 4
    "tree-finalizer": "asset-tree-v1",
    # Tier 5
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

    # v4.5: tree-finalizer is the only specialist that needs
    # `deny: ["group:asset_tree"]` lifted (it reads AssetTree but does
    # not write). All other specialists keep asset_tree denied.
    deny_list = ["group:asset_tree"]

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
            tools={"allow": list(tools_allow), "deny": deny_list},
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
            tools={"allow": list(tools_allow), "deny": deny_list},
        )
        print(f"  + registered {summary['id']} (tools.allow={tools_allow})")

    result = persist_config(cfg, path=str(config_path), restart_required=True)
    print(f"  + persisted to {result.path}")


def main() -> None:
    print(f"Cloning hack-deep-find specialists ({len(SPECIALISTS)} total, v4.5)")
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
        f"\nClone complete ({len(SPECIALISTS)} specialists, v4.5). "
        "Run scripts/clone_hack_deep_find.py next to refresh the "
        "LLM-coordinator's subagents.allow_agents list."
    )


if __name__ == "__main__":
    main()
