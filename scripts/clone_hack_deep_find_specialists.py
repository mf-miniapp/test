#!/usr/bin/env python3
"""Clone the 13 specialist agents for hack-deep-find.

Phase 2 ships 6 recon specialists (network surface).
Batch 1 (2026-06-15) adds 5 more (web surface + component-level CVE view).
Batch 2 (2026-06-15) adds 2 more (auth + cookie/header security posture).
Batch 3 (2026-06-15) adds 2 more (cloud storage + cross-layer secret scanner).
Batch 4 (2026-06-15) adds 1 more (horizontal seed expansion).

Total 16 specialists, each gets its own agent_id, workspace, registry entry,
and tool allowlist.

Network surface (Phase 2, 6):
  - subdomain-discoverer : group:recon:dns
  - ip-resolver          : group:recon:dns
  - port-scanner         : group:recon:portscan
  - service-fingerprint  : group:recon:portscan + group:recon:http
  - endpoint-crawler     : group:recon:http
  - leaf-verifier        : group:recon:http

Web surface + CVE component view (Batch 1, 5):
  - service-detailed     : group:recon:component
  - webapp-discoverer    : group:recon:webapp
  - api-surface          : group:recon:api
  - parameter-extract    : group:recon:api (read-only)
  - static-asset         : group:recon:sensitive

Web surface + CVE component view (Batch 1, 5):
  - service-detailed     : group:recon:component
  - webapp-discoverer    : group:recon:webapp
  - api-surface          : group:recon:api
  - parameter-extract    : group:recon:api (read-only)
  - static-asset         : group:recon:sensitive

Auth + cookie/header security posture (Batch 2, 2):
  - auth-mapper          : group:recon:auth
  - cookie-header        : group:recon:header

Cloud storage + cross-layer secret (Batch 3, 2):
  - cloud-storage        : group:recon:storage
  - secret-scanner       : group:recon:secret

Horizontal seed expansion (Batch 4, 1):
  - seed-expander        : group:recon:seed

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
# Batch 1 (2026-06-15): web surface + CVE component view
api_surface = _specialists_pkg.api_surface
parameter_extract = _specialists_pkg.parameter_extract
service_detailed = _specialists_pkg.service_detailed
static_asset = _specialists_pkg.static_asset
webapp_discoverer = _specialists_pkg.webapp_discoverer
# Batch 2 (2026-06-15): auth + cookie/header
auth_mapper = _specialists_pkg.auth_mapper
cookie_header = _specialists_pkg.cookie_header
# Batch 3 (2026-06-15): cloud storage + cross-layer secret
cloud_storage = _specialists_pkg.cloud_storage
secret_scanner = _specialists_pkg.secret_scanner
# Batch 4 (2026-06-15): horizontal seed expansion
seed_expander = _specialists_pkg.seed_expander

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
    # ── Batch 1 (2026-06-15) ────────────────────────────────────
    _specialist_spec(
        "service-detailed",
        "Service Detailed (CVE Component View)",
        "SERVICE → COMPONENT specialist. Component-level fingerprinting (product + "
        "version + CPE 2.3) for NVD CVE matching. Multi-source: CPE resolve, JS "
        "extract, TLS cert, favicon hash. allow_agents=[]. Tools: group:recon:component.",
        service_detailed.SOUL_BODY,
        ("group:recon:component", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "webapp-discoverer",
        "WebApp Discoverer",
        "SERVICE → URL specialist. Identify distinct web applications behind a "
        "single ip:port via vhost / port / path modes. Tech stack + app type + "
        "auth context. allow_agents=[]. Tools: group:recon:webapp.",
        webapp_discoverer.SOUL_BODY,
        ("group:recon:webapp", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "api-surface",
        "API Surface Mapper",
        "URL → API_SCHEMA + ENDPOINT specialist. Structured API surface "
        "extraction: OpenAPI/Swagger parse, GraphQL introspection, recursive "
        "JS crawl, path normalization, auth probe. allow_agents=[]. "
        "Tools: group:recon:api + group:recon:http (read-only).",
        api_surface.SOUL_BODY,
        ("group:recon:api", "group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "parameter-extract",
        "Parameter Extractor",
        "ENDPOINT → PARAMETER specialist. Parameter-level extraction from "
        "OpenAPI/GraphQL schemas, path patterns, query strings, and body "
        "fields. Heuristic type inference + sensitivity tagging. "
        "allow_agents=[]. Tools: group:recon:api (read-only).",
        parameter_extract.SOUL_BODY,
        ("group:recon:api", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "static-asset",
        "Static Asset Finder",
        "URL → STATIC_ASSET specialist. High-value static file discovery: "
        "config / backup / VCS / debug / docs / admin / metadata. 80-word "
        "wordlist + variant probing (403/401 → .bak/.old/.swp/~) + secret "
        "extraction. allow_agents=[]. Tools: group:recon:sensitive + group:recon:http.",
        static_asset.SOUL_BODY,
        ("group:recon:sensitive", "group:recon:http", "group:fs", "group:sessions"),
    ),
    # ── Batch 2 (2026-06-15) ────────────────────────────────────
    _specialist_spec(
        "auth-mapper",
        "Auth Mapper",
        "URL → AUTH_SURFACE specialist. Identify auth entry points: login, "
        "register, SSO, OAuth/OIDC, API key, JWT, reset, MFA. OAuth flow "
        "probe + JWT analysis + default-credential heuristic. "
        "allow_agents=[]. Tools: group:recon:auth + group:recon:http.",
        auth_mapper.SOUL_BODY,
        ("group:recon:auth", "group:recon:http", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "cookie-header",
        "Cookie & Header Auditor",
        "URL → COOKIE + HEADER specialist. Browser security posture: "
        "Set-Cookie flag audit (HttpOnly/Secure/SameSite), security-header "
        "presence audit (CSP/HSTS/X-Frame-Options/...), info-disclosure "
        "header detection. allow_agents=[]. Tools: group:recon:header + group:recon:http.",
        cookie_header.SOUL_BODY,
        ("group:recon:header", "group:recon:http", "group:fs", "group:sessions"),
    ),
    # ── Batch 3 (2026-06-15) ────────────────────────────────────
    _specialist_spec(
        "cloud-storage",
        "Cloud Storage Finder",
        "SUB_DOMAIN → STORAGE + STORAGE_OBJECT specialist. Discover public "
        "S3 / OSS / GCS / Azure Blob buckets via naming variants and "
        "anonymous ListBucket probes. Flag sensitive objects (db dumps, "
        "credentials, keys). allow_agents=[]. Tools: group:recon:storage + group:recon:dns.",
        cloud_storage.SOUL_BODY,
        ("group:recon:storage", "group:recon:dns", "group:fs", "group:sessions"),
    ),
    _specialist_spec(
        "secret-scanner",
        "Secret Scanner",
        "Cross-layer → SECRET specialist. Scan URL/ENDPOINT/STATIC_ASSET/"
        "API_SCHEMA/STORAGE/STORAGE_OBJECT children for leaked credentials, "
        "private keys, internal hosts, JWTs, GitHub PATs, etc. Regex + "
        "entropy + source-specific (JS bundle, git history, env dump). "
        "allow_agents=[]. Tools: group:recon:secret + group:recon:http.",
        secret_scanner.SOUL_BODY,
        ("group:recon:secret", "group:recon:http", "group:fs", "group:sessions"),
    ),
    # ── Batch 4 (2026-06-15) ────────────────────────────────────
    _specialist_spec(
        "seed-expander",
        "Seed Expander",
        "ROOT_DOMAIN → seed list (orchestrator-level). Discover horizontally-"
        "related seeds: WHOIS registrant / ASN + BGP prefix / cert-transparency "
        "related domains / passive DNS history. Returns a list of seeds "
        "(domain / asn / ip_range / org_name / keyword) for the orchestrator "
        "to feed into asset_tree_create(extra_seeds=...) or run as separate "
        "trees + asset_tree_merge. allow_agents=[]. Tools: group:recon:seed.",
        seed_expander.SOUL_BODY,
        ("group:recon:seed", "group:fs", "group:sessions"),
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
    # Phase 2
    "subdomain-discoverer": "subdomain-v1",
    "ip-resolver": "ip-v1",
    "port-scanner": "port-v1",
    "service-fingerprint": "service-v1",
    "endpoint-crawler": "endpoint-v1",
    "leaf-verifier": "leaf-v1",
    # Batch 1
    "service-detailed": "component-v1",
    "webapp-discoverer": "webapp-v1",
    "api-surface": "api-surface-v1",
    "parameter-extract": "parameter-v1",
    "static-asset": "static-asset-v1",
    # Batch 2
    "auth-mapper": "auth-surface-v1",
    "cookie-header": "cookie-header-v1",
    # Batch 3
    "cloud-storage": "cloud-storage-v1",
    "secret-scanner": "secret-v1",
    # Batch 4
    "seed-expander": "seed-v1",
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