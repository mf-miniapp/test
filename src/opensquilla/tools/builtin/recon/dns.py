"""DNS recon tools — dnsx (preferred) / stdlib (fallback).

Group: ``group:recon:dns``.

v4.4 (2026-06-18) hardening: dnsx binary
(https://github.com/projectdiscovery/dnsx) does batched A/AAAA
+ CNAME + NS + MX resolution with retryable DNS, 5-10x faster
than per-host getaddrinfo. Stdlib is the fallback.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import tempfile
from pathlib import Path
from typing import Any

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


# ── helpers ──────────────────────────────────────────


def _normalize_addrinfo(family: int, sockaddr: tuple) -> str:
    return sockaddr[0]


async def _stdlib_resolve_one(hostname: str, timeout_s: float) -> tuple[list[str], str | None]:
    """Stdlib fallback: asyncio.getaddrinfo. Returns (ips, error_message).

    Always returns a tuple; never raises. error_message is non-None iff
    the resolution failed (timeout, gaierror, or other exception).
    """
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        return [], f"timeout after {timeout_s}s"
    except socket.gaierror as exc:
        return [], f"gaierror: {exc}"
    except Exception as exc:  # noqa: BLE001
        return [], f"{type(exc).__name__}: {exc}"
    seen: set[str] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = _normalize_addrinfo(family, sockaddr)
        if ip not in seen:
            seen.add(ip)
    return sorted(seen), None


def _parse_dnsx_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse dnsx -json JSONL output to flat records.

    dnsx -json emits one line per (host, record-type) pair, e.g.
      {"host":"api.example.com","resolver":["1.1.1.1"],"a":["1.2.3.4"],"aaaa":[],"status_code":"NOERROR"}
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
        host = rec.get("host", "")
        a = rec.get("a", []) or []
        aaaa = rec.get("aaaa", []) or []
        cname = rec.get("cname", []) or []
        out.append({
            "host": host,
            "a": a,
            "aaaa": aaaa,
            "cname": cname,
            "status_code": rec.get("status_code", ""),
        })
    return out


# ── tools ───────────────────────────────────────────


@tool(
    name="recon_dns_resolve",
    description=(
        "Resolve a hostname to its A / AAAA records. v4.4-preferred: "
        "uses dnsx binary (https://github.com/projectdiscovery/dnsx) "
        "for retryable, multi-resolver lookups. Falls back to stdlib "
        "asyncio.getaddrinfo when dnsx is not on PATH. Returns a JSON "
        "object with `hostname` and `ips` (list of unique IPs, A + AAAA "
        "interleaved). Empty `ips` list means resolution failed (NXDOMAIN, "
        "timeout, no records)."
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
    """Resolve hostname via dnsx (preferred) or stdlib (fallback)."""
    bp = _binaries.detect("dnsx")
    if bp.available:
        try:
            # dnsx -l takes a FILE of hostnames (one per line), not a single
            # hostname. For a single hostname, write to a tmpfile.
            import tempfile as _tf
            with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as _f:
                _f.write(hostname + "\n")
                _tmp = _f.name
            try:
                rc, stdout, stderr = await _binaries._run_binary(
                    ["dnsx", "-a", "-aaaa", "-resp", "-json", "-retry", "2",
                     "-l", _tmp, "-t", str(int(timeout_s))],
                    timeout_s=timeout_s + 5,
                )
            finally:
                try:
                    import os as _os
                    _os.unlink(_tmp)
                except OSError:
                    pass
            records = _parse_dnsx_jsonl(stdout)
            # dnsx -l takes a file or single host; for single host it
            # returns one record. If it didn't return a record for our
            # host (e.g. empty input handling), synthesize.
            ips: list[str] = []
            for r in records:
                if r["host"].rstrip(".") == hostname.rstrip("."):
                    ips = list(r["a"]) + list(r["aaaa"])
                    break
            if not ips and records:
                # take first record's a+aaaa
                ips = list(records[0]["a"]) + list(records[0]["aaaa"])
            return json.dumps({
                "hostname": hostname, "ips": ips, "error": None,
                "source": "dnsx", "binary_version": bp.version,
            }, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            # fall through to stdlib
            ips = await _stdlib_resolve_one(hostname, timeout_s)
            return json.dumps({
                "hostname": hostname, "ips": ips, "error": None,
                "source": "stdlib", "binary_error": f"{type(exc).__name__}: {exc}",
            }, ensure_ascii=False)

    # Stdlib fallback.
    ips, err = await _stdlib_resolve_one(hostname, timeout_s)
    return json.dumps({
        "hostname": hostname, "ips": ips, "error": err,
        "source": "stdlib",
    }, ensure_ascii=False)


@tool(
    name="recon_dns_resolve_batch",
    description=(
        "Batched DNS resolution for a list of hostnames. v4.4-preferred: "
        "uses dnsx binary for parallel resolution across multiple resolvers. "
        "Falls back to per-host stdlib getaddrinfo when dnsx is not on PATH. "
        "Returns a JSON object with `results` (list of {hostname, ips, error}) "
        "and the source. Use this in F0 / F1 to resolve 50+ subdomains at once "
        "rather than calling recon_dns_resolve per host."
    ),
    params={
        "hostnames": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of hostnames to resolve (e.g. ['api.example.com', 'cdn.example.com']).",
        },
        "timeout_s": {
            "type": "integer",
            "description": "Total batch timeout. Default: 30.",
            "default": 30,
        },
    },
    required=["hostnames"],
    execution_timeout_seconds=120.0,
)
async def recon_dns_resolve_batch(hostnames: list[str], timeout_s: int = 30) -> str:
    """Batched DNS resolution via dnsx (preferred) or stdlib (fallback)."""
    if not hostnames:
        return json.dumps({"results": [], "source": "noop"}, ensure_ascii=False)

    bp = _binaries.detect("dnsx")
    if bp.available:
        # dnsx -l takes a file of hostnames
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            for h in hostnames:
                f.write(h.strip() + "\n")
            tmp_path = f.name
        try:
            rc, stdout, stderr = await _binaries._run_binary(
                ["dnsx", "-a", "-aaaa", "-resp", "-json", "-retry", "2",
                 "-l", tmp_path, "-t", "10"],
                timeout_s=timeout_s,
            )
            records = _parse_dnsx_jsonl(stdout)
            # Build per-host result map.
            by_host: dict[str, dict[str, list[str]]] = {}
            for r in records:
                host = r["host"].rstrip(".")
                by_host[host] = {
                    "a": r["a"], "aaaa": r["aaaa"],
                }
            results: list[dict] = []
            for h in hostnames:
                hh = h.strip().rstrip(".")
                r = by_host.get(hh, {"a": [], "aaaa": []})
                results.append({
                    "hostname": h, "ips": r["a"] + r["aaaa"], "error": None,
                })
            return json.dumps({
                "results": results, "source": "dnsx",
                "binary_version": bp.version,
            }, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            # fall through
            pass
        finally:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass

    # Stdlib fallback: parallel asyncio.getaddrinfo.
    async def _one(h: str) -> dict[str, Any]:
        ips, err = await _stdlib_resolve_one(h, timeout_s=5.0)
        return {"hostname": h, "ips": ips, "error": err}

    results = await asyncio.gather(*[_one(h) for h in hostnames])
    return json.dumps({
        "results": results, "source": "stdlib",
    }, ensure_ascii=False)


@tool(
    name="recon_dns_over_https",
    description=(
        "Resolve a hostname via DNS-over-HTTPS (Cloudflare or Google). Use "
        "this when the local resolver is suspected poisoned or when you "
        "need a second-source check on an IP. Returns the same JSON shape "
        "as `recon_dns_resolve` plus a `ttl` field when the provider "
        "exposes it. Falls back to `recon_dns_resolve` on transport failure."
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
        "hostname": hostname, "ips": [], "ttl": None,
        "provider": provider, "error": None,
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
        loop = asyncio.get_running_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=timeout_s),
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
        if answer.get("type") in (1, 28):
            ip = answer.get("data")
            if ip and ip not in seen:
                seen.add(ip)
                result["ips"].append(ip)
    if payload.get("Answer"):
        result["ttl"] = payload["Answer"][0].get("TTL")
    return json.dumps(result, ensure_ascii=False)
