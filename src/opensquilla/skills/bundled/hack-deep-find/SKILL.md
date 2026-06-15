---
name: hack-deep-find
description: "Recursive asset discovery from a root domain. Walks the chain ROOT_DOMAIN → SUB_DOMAIN → IP → PORT → SERVICE → ENDPOINT by reading its own SOUL.md and running the wave loop itself via sessions_spawn. Delegates all scanning to 6 specialist sub-agents (subdomain-discoverer, ip-resolver, port-scanner, service-fingerprint, endpoint-crawler, leaf-verifier) and maintains a persistent asset tree via the asset_tree_* builtin tool group. NOT for: single-domain DNS lookup (use dns tools directly), port scanning a known IP (use nmap directly), or generic recon without recursive depth."
homepage: ""
provenance:
  origin: opensquilla
  license: MIT
  upstream_url: ""
  maintained_by: OpenSquilla
metadata:
  {
    "platform":
      {
        "emoji": "🔍",
      },
  }
---

# hack-deep-find

Recursive wave-based asset discovery orchestrator. Given a root domain,
discovers the full attack surface by progressively enumerating each layer
of the asset hierarchy.

## When to use

| Need | Use |
|---|---|
| Full attack surface discovery for a domain | this skill |
| Single DNS lookup | DNS tools directly |
| Port scan a known IP | nmap directly |
| Quick subdomain check | dns tools directly |
| "Discover everything for X" | this skill |
| "Map attack surface of X" | this skill |

## How it works

This skill is a **pure LLM orchestrator**. The `hack-deep-find` agent
itself is a markdown persona (`SOUL_BODY.md`); the LLM reads the SOUL
and runs the recursive wave loop directly — there is **no Python driver**.
Per layer, the LLM:

1. Calls `asset_tree_find_unseen(tree_id, asset_type=<parent_type>)`
   to get the frontier nodes.
2. Per node, builds a `HANDOFF` envelope and calls
   `sessions_spawn(agent_id=<specialist>, task=<envelope>)`.
3. Calls `sessions_yield()` for the wave barrier.
4. Per specialist result, calls `asset_tree_add_nodes(...)` then
   `asset_tree_update_state(...)`.
5. Loops until `asset_tree_find_unseen` returns empty.

## 6 specialists (Phase 2)

| agent_id | input asset_type | output asset_type | tools |
|---|---|---|---|
| `subdomain-discoverer` | ROOT_DOMAIN | SUB_DOMAIN | `recon_dns_resolve`, `recon_dns_over_https` |
| `ip-resolver` | SUB_DOMAIN | IP | `recon_dns_resolve`, `recon_dns_over_https` |
| `port-scanner` | IP | PORT | `recon_port_scan_tcp`, `recon_port_scan_range`, `recon_grab_banner`, `masscan_scan`, `nmap_scan` |
| `service-fingerprint` | PORT | SERVICE | `recon_grab_banner`, `recon_http_probe`, `nmap_scan` |
| `endpoint-crawler` | SERVICE | ENDPOINT | `recon_directory_bruteforce`, `recon_extract_endpoints_from_js`, `recon_http_probe` |
| `leaf-verifier` | any | (no children) | `recon_http_probe` |

## Termination

`asset_tree_find_unseen` returns empty. The LLM-coordinator then:

1. Calls `asset_tree_stats(tree_id)` for the final report.
2. Calls `asset_tree_complete(tree_id)` to obtain the persisted path.
3. (Phase 3) Calls `sessions_spawn(agent_id="hack-deep", task=<find-complete envelope>)`
   to hand the tree off to hack-deep for exploitation.

## Constraints

- **Coordinator never scans directly** (enforced by `tools.allow`
  policy AND SOUL contract). All I/O goes through the 6 specialists.
- **Wave barrier**: one `sessions_yield()` per wave.
- **Tree persistence**: `asset_tree_*` tools write to
  `~/.opensquilla/state/asset_trees/<tree_id>.json` after every
  mutation; survive across LLM context evictions.
- **Specialist RESULT MARKER**: every specialist reply must end
  with a marker line (`schema: <x> | phase: ... | wave: ... | deps: ...`).
  The LLM-coordinator waits for the marker before proceeding to the
  next wave.

## Integration

This skill is backed by the `hack_deep_find` agent package:

- `coordinator` removed — pure LLM orchestrator (no Python driver)
- `specialists/<name>/SOUL_BODY.md` — per-specialist contract (6 subpackages)
- `ATTRIBUTION.md` — evidence schemas (6 specialist + 1 find-complete)
- `SOUL.md` — recursive wave loop instructions for the LLM

The coordinator is registered via `scripts/clone_hack_deep_find.py`;
the 6 specialists via `scripts/clone_hack_deep_find_specialists.py`.