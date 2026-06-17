"""CDN / WAF detection — cdncheck binary (preferred) / stdlib (fallback).

Group: ``group:recon:cdn``.

v4.4 (2026-06-18) NEW tool. Solves the "phantom asset" problem
on 2026-06-17 51ifind.com run: the LLM was marking every IP:port
combination as a real asset based on a 200 OK from a reverse
proxy. A response of 200 + "Service Unavailable" body is NOT a
real asset — it's a CDN/WAF fronting nothing (or a back-end in
failover). Likewise "200 + <title>Default Web Page</title>" is
a placeholder.

cdncheck (https://github.com/projectdiscovery/cdncheck) inspects
the IP/hostname and returns the CDN provider, WAF, or cloud
provider. Use this BEFORE ingesting an IP:port as a real asset
in the F-final verification step. If the IP is a CDN IP (not
the origin), the orchestrator should mark the asset as
``cd_fronted: true`` and only ingest it as a CDN POP, not as
the customer's actual infrastructure.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from typing import Any

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


# ── helpers ──────────────────────────────────────────


def _parse_cdncheck_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse cdncheck -json output. One record per (ip, port) probed.

    cdncheck -json emits:
      {"ip":"1.2.3.4","port":80,"cdn":true,"cdn_name":"Cloudflare",
       " waf":true,"waf_name":"Cloudflare","cloud_provider":"..."}
    """
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append({
            "ip": rec.get("ip"),
            "port": rec.get("port"),
            "cdn": rec.get("cdn", False),
            "cdn_name": rec.get("cdn_name") or rec.get("cdn_provider"),
            "waf": rec.get("waf", False),
            "waf_name": rec.get("waf_name"),
            "cloud_provider": rec.get("cloud_provider"),
        })
    return out


# Known CDN IP ranges (fallback heuristic — partial list, used when
# cdncheck is not on PATH). Covers the most common providers.
_KNOWN_CDN_RANGES: tuple[tuple[str, str, ipaddress._BaseNetwork], ...] = (
    ("Cloudflare", "1.1.1.0/24", ipaddress.ip_network("1.1.1.0/24")),
    ("Cloudflare", "1.0.0.0/24", ipaddress.ip_network("1.0.0.0/24")),
    ("Cloudflare", "104.16.0.0/12", ipaddress.ip_network("104.16.0.0/12")),
    ("Cloudflare", "172.64.0.0/13", ipaddress.ip_network("172.64.0.0/13")),
    ("Cloudflare", "173.245.48.0/20", ipaddress.ip_network("173.245.48.0/20")),
    ("Cloudflare", "188.114.96.0/20", ipaddress.ip_network("188.114.96.0/20")),
    ("Cloudflare", "190.93.240.0/20", ipaddress.ip_network("190.93.240.0/20")),
    ("Cloudflare", "197.234.240.0/22", ipaddress.ip_network("197.234.240.0/22")),
    ("Cloudflare", "198.41.128.0/17", ipaddress.ip_network("198.41.128.0/17")),
    ("Cloudflare", "162.158.0.0/15", ipaddress.ip_network("162.158.0.0/15")),
    ("Cloudflare", "141.101.64.0/18", ipaddress.ip_network("141.101.64.0/18")),
    ("Akamai", "23.0.0.0/12", ipaddress.ip_network("23.0.0.0/12")),
    ("Akamai", "104.64.0.0/10", ipaddress.ip_network("104.64.0.0/10")),
    ("Akamai", "184.24.0.0/13", ipaddress.ip_network("184.24.0.0/13")),
    ("Akamai", "2.16.0.0/13", ipaddress.ip_network("2.16.0.0/13")),
    ("Fastly", "151.101.0.0/16", ipaddress.ip_network("151.101.0.0/16")),
    ("Fastly", "199.232.0.0/16", ipaddress.ip_network("199.232.0.0/16")),
    ("AWS CloudFront", "13.32.0.0/15", ipaddress.ip_network("13.32.0.0/15")),
    ("AWS CloudFront", "13.224.0.0/14", ipaddress.ip_network("13.224.0.0/14")),
    ("AWS CloudFront", "52.84.0.0/15", ipaddress.ip_network("52.84.0.0/15")),
    ("AWS CloudFront", "54.230.0.0/16", ipaddress.ip_network("54.230.0.0/16")),
    ("Azure CDN", "13.107.0.0/16", ipaddress.ip_network("13.107.0.0/16")),
    ("Azure CDN", "152.195.0.0/16", ipaddress.ip_network("152.195.0.0/16")),
    ("Alibaba Aliyun", "47.74.0.0/16", ipaddress.ip_network("47.74.0.0/16")),
    ("Alibaba Aliyun", "47.75.0.0/16", ipaddress.ip_network("47.75.0.0/16")),
    ("Alibaba Aliyun", "47.76.0.0/16", ipaddress.ip_network("47.76.0.0/16")),
    ("Tencent Cloud", "81.71.0.0/16", ipaddress.ip_network("81.71.0.0/16")),
    ("Tencent Cloud", "129.204.0.0/16", ipaddress.ip_network("129.204.0.0/16")),
    ("Tencent Cloud", "175.27.0.0/16", ipaddress.ip_network("175.27.0.0/16")),
    ("Tencent Cloud", "119.29.0.0/16", ipaddress.ip_network("119.29.0.0/16")),
    ("Cloudflare CN", "162.159.208.0/21", ipaddress.ip_network("162.159.208.0/21")),
    ("Wangsu (ChinaCache)", "58.215.0.0/16", ipaddress.ip_network("58.215.0.0/16")),
    ("ChinaCache", "61.135.0.0/16", ipaddress.ip_network("61.135.0.0/16")),
)


def _stdlib_cdn_lookup(ip: str) -> dict[str, Any]:
    """Heuristic CDN detection by IP range matching. Fallback only."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "cdn": False, "cdn_name": None,
                "waf": False, "waf_name": None,
                "cloud_provider": None, "source": "stdlib"}
    for name, _range_str, network in _KNOWN_CDN_RANGES:
        if ip_obj in network:
            return {"ip": ip, "cdn": True, "cdn_name": name,
                    "waf": False, "waf_name": None,
                    "cloud_provider": None, "source": "stdlib"}
    return {"ip": ip, "cdn": False, "cdn_name": None,
            "waf": False, "waf_name": None,
            "cloud_provider": None, "source": "stdlib"}


# ── tools ───────────────────────────────────────────


@tool(
    name="recon_cdn_check",
    description=(
        "Check if an IP is a CDN / WAF / cloud provider POP. v4.4-NEW: "
        "uses cdncheck binary (https://github.com/projectdiscovery/"
        "cdncheck) for accurate provider detection. Falls back to a "
        "hardcoded IP-range table (Cloudflare / Akamai / Fastly / AWS "
        "CloudFront / Azure CDN / Aliyun / Tencent Cloud / Wangsu) when "
        "cdncheck is not on PATH. Use this BEFORE ingesting an IP as a "
        "real customer asset in the F-final verification step. If "
        "cdn=true, mark the asset as `cd_fronted: true` and treat it as a "
        "CDN POP, not the customer's actual infrastructure."
    ),
    params={
        "ip": {
            "type": "string",
            "description": "IPv4 or IPv6 address to check.",
        },
        "port": {
            "type": "integer",
            "description": "Optional port (cdncheck uses port to disambiguate some providers). Default: 80.",
            "default": 80,
        },
    },
    required=["ip"],
    execution_timeout_seconds=20.0,
)
async def recon_cdn_check(ip: str, port: int = 80) -> str:
    """Check if an IP is a CDN / WAF / cloud provider via cdncheck (preferred) or stdlib (fallback)."""
    bp = _binaries.detect("cdncheck")
    if bp.available:
        try:
            rc, stdout, stderr = await _binaries._run_binary(
                ["cdncheck", "-json", "-i", ip, "-p", str(port), "-resp"],
                timeout_s=15,
            )
            records = _parse_cdncheck_jsonl(stdout)
            if records:
                rec = records[0]
                rec["source"] = "cdncheck"
                rec["binary_version"] = bp.version
                return json.dumps(rec, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            pass  # fall through to stdlib
    return json.dumps(_stdlib_cdn_lookup(ip), ensure_ascii=False)


@tool(
    name="recon_cdn_check_batch",
    description=(
        "Batched CDN / WAF / cloud provider check for a list of IPs. "
        "v4.4-NEW: uses cdncheck binary for parallel detection. Falls "
        "back to per-IP IP-range matching. Returns a JSON object with "
        "`results` (list of {ip, cdn, cdn_name, waf, waf_name, "
        "cloud_provider, source}) and the aggregate source. Use this in "
        "the F-final step to mark 50+ ingested IPs as CDN-fronted or "
        "real customer assets in one call."
    ),
    params={
        "ips": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of IPv4 / IPv6 addresses to check.",
        },
    },
    required=["ips"],
    execution_timeout_seconds=120.0,
)
async def recon_cdn_check_batch(ips: list[str]) -> str:
    """Batched CDN / WAF / cloud provider check via cdncheck (preferred) or stdlib (fallback)."""
    if not ips:
        return json.dumps({"results": [], "source": "noop"}, ensure_ascii=False)

    bp = _binaries.detect("cdncheck")
    if bp.available:
        try:
            rc, stdout, stderr = await _binaries._run_binary(
                ["cdncheck", "-json", "-l", "-", "-resp"],
                timeout_s=60,
            )
            records = _parse_cdncheck_jsonl(stdout)
            # Map records back to input list.
            by_ip: dict[str, dict[str, Any]] = {}
            for r in records:
                if r.get("ip"):
                    by_ip[r["ip"]] = r
                    by_ip[r["ip"]]["source"] = "cdncheck"
                    by_ip[r["ip"]]["binary_version"] = bp.version
            results: list[dict] = []
            for ip in ips:
                rec = by_ip.get(ip) or _stdlib_cdn_lookup(ip)
                results.append(rec)
            return json.dumps({
                "results": results, "source": "cdncheck",
                "binary_version": bp.version,
            }, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            pass

    # Stdlib fallback: parallel IP-range match.
    results = [_stdlib_cdn_lookup(ip) for ip in ips]
    return json.dumps({"results": results, "source": "stdlib"}, ensure_ascii=False)
