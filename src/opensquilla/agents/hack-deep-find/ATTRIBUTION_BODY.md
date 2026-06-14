# ATTRIBUTION.md — HACK-DEEP-FIND Evidence Schemas

## Specialist Output Schemas (Phase 2: all 6 wired)

### `subdomain-v1` — subdomain-discoverer
Output of ROOT_DOMAIN → SUB_DOMAIN enumeration (active DNS bruteforce).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"subdomain-v1"` | yes | Schema discriminator |
| `root_domain` | `str` | yes | The input root domain |
| `subdomains` | `list[SubdomainEntry]` | yes | Discovered subdomains |
| `SubdomainEntry.subdomain` | `str` | yes | Full subdomain (e.g. "api.example.com") |
| `SubdomainEntry.source` | `str` | yes | Discovery source: `dns_bruteforce` / `crtsh` / `passive_dns` |
| `SubdomainEntry.confidence` | `str` | yes | `high` / `medium` / `low` |

### `ip-v1` — ip-resolver
Output of SUB_DOMAIN → IP resolution.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"ip-v1"` | yes | Schema discriminator |
| `subdomain` | `str` | yes | Input subdomain |
| `ips` | `list[str]` | yes | Resolved IP addresses (A + AAAA) |
| `ttl` | `int \| null` | no | DNS TTL if DoH provider exposes it |
| `error` | `str \| null` | no | Error message if resolution failed |

### `port-v1` — port-scanner
Output of IP → PORT discovery.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"port-v1"` | yes | Schema discriminator |
| `ip` | `str` | yes | Input IP |
| `ports` | `list[PortEntry]` | yes | Discovered open ports |
| `PortEntry.port` | `int` | yes | Port number |
| `PortEntry.protocol` | `str` | no | `tcp` (default) / `udp` |
| `PortEntry.state` | `str` | yes | `open` / `closed` / `filtered` |
| `PortEntry.banner` | `str \| null` | no | Service banner if grabbed |

### `service-v1` — service-fingerprint
Output of PORT → SERVICE fingerprinting.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"service-v1"` | yes | Schema discriminator |
| `services` | `list[ServiceEntry]` | yes | Identified services |
| `ServiceEntry.ip` | `str` | yes | IP address |
| `ServiceEntry.port` | `int` | yes | Port number |
| `ServiceEntry.service_name` | `str` | yes | Service identifier (e.g. "HTTPS/nginx") |
| `ServiceEntry.version` | `str \| null` | no | Detected version |
| `ServiceEntry.technology` | `str \| null` | no | Tech stack (PHP / Node.js / etc.) |
| `ServiceEntry.extra_info` | `dict` | no | Server header, TLS info, etc. |

### `endpoint-v1` — endpoint-crawler
Output of SERVICE → ENDPOINT discovery.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"endpoint-v1"` | yes | Schema discriminator |
| `service` | `str` | yes | Input service identifier |
| `endpoints` | `list[EndpointEntry]` | yes | Discovered endpoints |
| `EndpointEntry.url` | `str` | yes | Full URL |
| `EndpointEntry.method` | `str` | no | HTTP method (default: GET) |
| `EndpointEntry.status_code` | `int` | no | Response status code |
| `EndpointEntry.content_type` | `str \| null` | no | Content-Type header |
| `EndpointEntry.title` | `str \| null` | no | HTML `<title>` if present |

### `leaf-v1` — leaf-verifier
Output of leaf verification (no children produced).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"leaf-v1"` | yes | Schema discriminator |
| `nodes` | `list[LeafEntry]` | yes | Verification results |
| `LeafEntry.node_id` | `str` | yes | Verified node id |
| `LeafEntry.is_leaf` | `bool` | yes | Whether the node is a leaf |
| `LeafEntry.reason` | `str` | yes | `unreachable` / `service_alive` / `terminal_type` / etc. |

## Handoff Schema (Phase 3)

### `find-complete-v1` — coordinator → hack-deep
Sent via `sessions_spawn(agent_id="hack-deep", ...)` with the AssetTree JSON
path embedded in `artifacts=...`.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"find-complete-v1"` | yes | Schema discriminator |
| `tree_id` | `str` | yes | The AssetTree id |
| `root_domain` | `str` | yes | Root domain discovered |
| `tree_path` | `str` | yes | Absolute path to persisted AssetTree JSON |
| `tree_stats` | `dict` | yes | Snapshot of `tree.stats()` |
| `frontier_summary` | `list[str]` | yes | One-line per UNSEEN leaf (for the LLM brief) |
| `duration_s` | `int` | yes | Total find-run duration in seconds |

## Provenance

- **Created**: 2026-06-14 (hack-deep-find v2 redesign, Phase 3 complete)
- **Based on**: hack-deep v3.2 Typed Task Envelope
- **Architecture**: Pure LLM orchestrator + 6 specialist subagents + handoff to hack-deep
- **Persistence**: AssetTree at `~/.opensquilla/state/asset_trees/<tree_id>.json`
- **Handoff evidence schema**: `find-complete-v1` registered in `attack_dispatch.evidence.EVIDENCE_SCHEMAS`

## Specialist Registry

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `subdomain-discoverer` | 子域名枚举专家 | ROOT_DOMAIN | SUB_DOMAIN | `recon_dns_resolve`, `recon_dns_over_https` |
| `ip-resolver` | DNS 解析专家 | SUB_DOMAIN | IP | `recon_dns_resolve`, `recon_dns_over_https` |
| `port-scanner` | 端口发现专家 | IP | PORT | `recon_port_scan_tcp`, `recon_port_scan_range`, `recon_grab_banner`, `masscan_scan`, `nmap_scan` |
| `service-fingerprint` | 服务指纹专家 | PORT | SERVICE | `recon_grab_banner`, `recon_http_probe`, `nmap_scan` |
| `endpoint-crawler` | 端点爬取专家 | SERVICE | ENDPOINT | `recon_directory_bruteforce`, `recon_extract_endpoints_from_js`, `recon_http_probe` |
| `leaf-verifier` | 叶子验证专家 | 任意 | (无子节点) | `recon_http_probe` |