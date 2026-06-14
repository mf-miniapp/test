# ATTRIBUTION.md — HACK-DEEP-FIND Envelope Schema

## Envelope Schema Table

| Schema Name | Fields | Description |
|---|---|---|
| `subdomain-v1` | root_domain, subdomains[{subdomain, source, confidence}] | 子域名枚举结果 |
| `ip-v1` | subdomains[{subdomain, ips[], cdn, ttl}] | DNS 解析结果 |
| `port-v1` | ips[{ip, ports[{port, protocol, state, banner}]}] | 端口扫描结果 |
| `service-v1` | ports[{ip, port, service, version, technology}] | 服务指纹结果 |
| `endpoint-v1` | services[{service, endpoints[{path, method, params, status}]}] | 端点发现结果 |
| `leaf-v1` | nodes[{node_id, is_leaf, reason}] | 叶子验证结果 |

## Provenance

- **Created**: 2026-06-14
- **Based on**: hack-deep v3.2 (cyberstrike-deep clone)
- **Purpose**: Asset discovery and tree construction
- **Architecture**: Recursive wave model (dynamic depth)
- **Specialists**: 6 recon-focused (vs 13 attack-focused in hack-deep)

## Specialist Registry

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `subdomain-discoverer` | 子域名枚举专家 | ROOT_DOMAIN | SUB_DOMAIN | DNS bruteforce, crt.sh, cert transparency, passive DNS |
| `ip-resolver` | 域名解析专家 | SUB_DOMAIN | IP | dig, DNS over HTTPS, CDN fingerprint |
| `port-scanner` | 端口扫描专家 | IP | PORT | nmap SYN scan, masscan, banner grab |
| `service-fingerprint` | 服务指纹专家 | PORT | SERVICE | nmap -sV, httpx, nuclei tech detect |
| `endpoint-crawler` | 端点爬取专家 | SERVICE | ENDPOINT | crawlee, waybackurls, gau, arjun param discovery |
| `leaf-verifier` | 叶子验证专家 | 任意 | (无子节点) | 验证已发现节点是否还有未发现子节点 |

## Integration Points

- **AssetTree**: Core data structure for storing discovered assets
- **Web UI**: POST /asset-tree/{id}/scan triggers deep-find
- **hack-deep**: Receives AssetTree for subsequent attack phases
- **WebSocket**: Real-time tree growth updates during exploration
