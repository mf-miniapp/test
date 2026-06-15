"""DNS recon tools — pure stdlib (`asyncio.getaddrinfo`).

Group: ``group:recon:dns``.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

from opensquilla.tools.registry import tool


def _normalize_addrinfo(family: int, sockaddr: tuple) -> str:
    return sockaddr[0]


@tool(
    name="recon_dns_resolve",
    description=(
        "Resolve a hostname to its A / AAAA records using the system resolver "
        "(asyncio.getaddrinfo). Returns a JSON object with `hostname` and "
        "`ips` (list of unique IPs, A + AAAA interleaved). Empty `ips` list "
        "means resolution failed (NXDOMAIN, timeout, no records). Does NOT "
        "perform WHOIS, certificate transparency lookup, or any other "
        "out-of-band source — for those, see `subdomain-discoverer`'s SOUL."
    ),
    params={
        "hostname": {
            "type": "string",
            "description": "Hostname to resolve (e.g. 'api.example.com').",
        },
        "timeout_s": {
            "type": "number",
            "description": "Resolution timeout in seconds. Default: 5.0.",
            "default": 5.0,
        },
    },
    required=["hostname"],
    execution_timeout_seconds=15.0,
)
async def recon_dns_resolve(hostname: str, timeout_s: float = 5.0) -> str:
    """Resolve hostname via stdlib asyncio.getaddrinfo."""
    result: dict[str, Any] = {"hostname": hostname, "ips": [], "error": None}
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        result["error"] = f"timeout after {timeout_s}s"
        return json.dumps(result, ensure_ascii=False)
    except socket.gaierror as exc:
        result["error"] = f"gaierror: {exc}"
        return json.dumps(result, ensure_ascii=False)
    except Exception as exc:  # defensive: surface unexpected resolver failures
        result["error"] = f"{type(exc).__name__}: {exc}"
        return json.dumps(result, ensure_ascii=False)

    seen: set[str] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = _normalize_addrinfo(family, sockaddr)
        if ip not in seen:
            seen.add(ip)
            result["ips"].append(ip)

    return json.dumps(result, ensure_ascii=False)


@tool(
    name="recon_dns_over_https",
    description=(
        "Resolve a hostname via DNS-over-HTTPS (Cloudflare or Google). Use this "
        "when the local resolver is suspected poisoned or when you need a "
        "second-source check on an IP. Returns the same JSON shape as "
        "`recon_dns_resolve` plus a `ttl` field when the provider exposes it. "
        "Falls back to `recon_dns_resolve` on transport failure."
    ),
    params={
        "hostname": {
            "type": "string",
            "description": "Hostname to resolve.",
        },
        "provider": {
            "type": "string",
            "enum": ["cloudflare", "google"],
            "description": "DoH provider. Default: cloudflare.",
            "default": "cloudflare",
        },
        "timeout_s": {
            "type": "number",
            "description": "HTTP timeout in seconds. Default: 5.0.",
            "default": 5.0,
        },
    },
    required=["hostname"],
    execution_timeout_seconds=20.0,
)
async def recon_dns_over_https(
    hostname: str,
    provider: str = "cloudflare",
    timeout_s: float = 5.0,
) -> str:
    """Resolve via DNS-over-HTTPS (stdlib HTTP, no curl)."""
    import urllib.error
    import urllib.request

    result: dict[str, Any] = {
        "hostname": hostname,
        "ips": [],
        "ttl": None,
        "provider": provider,
        "error": None,
    }

    providers = {
        "cloudflare": (
            "https://cloudflare-dns.com/dns-query",
            {"accept": "application/dns-json"},
        ),
        "google": (
            "https://dns.google/resolve",
            {"accept": "application/dns-json"},
        ),
    }

    base_url, headers = providers.get(provider, providers["cloudflare"])
    url = f"{base_url}?name={hostname}&type=A"

    req = urllib.request.Request(url, headers=headers)
    try:
        # Run blocking URL open in a thread to keep the event loop responsive
        loop = asyncio.get_running_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=timeout_s),
            ),
            timeout=timeout_s + 1,
        )
        payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    except (asyncio.TimeoutError, urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        # Fall back to system resolver
        fallback = await recon_dns_resolve(hostname, timeout_s=timeout_s)
        try:
            fb = json.loads(fallback)
            result["ips"] = fb.get("ips", [])
            result["error"] = f"doh_failed_fallback_used: {result['error']}"
        except json.JSONDecodeError:
            pass
        return json.dumps(result, ensure_ascii=False)

    seen: set[str] = set()
    for answer in payload.get("Answer", []):
        if answer.get("type") in (1, 28):  # A or AAAA
            ip = answer.get("data")
            if ip and ip not in seen:
                seen.add(ip)
                result["ips"].append(ip)

    if payload.get("Answer"):
        result["ttl"] = payload["Answer"][0].get("TTL")

    return json.dumps(result, ensure_ascii=False)