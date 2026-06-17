"""Subdomain enumeration — subfinder (preferred) / DNS brute (fallback).

v4 (2026-06-17) hardening: 51ifind.com run ingested only 13 subdomains
because domain-expander (legacy recon) was using just crt.sh + a tiny
brute list. subfinder binary (https://github.com/projectdiscovery/
subfinder) integrates 30+ sources (crt.sh, chaos, shodan, censys,
wayback, dnsdumpster, hackertarget, ...). We prefer the binary; the
stdlib path falls back to a small list of public DNS resolvers
querying crt.sh + a tiny wordlist.
"""
from __future__ import annotations

import asyncio
import json
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


# Tiny DNS brute list for stdlib fallback. The point is "we tried";
# subfinder is the real engine.
_BRUTE_WORDS: tuple[str, ...] = (
    "www", "mail", "smtp", "imap", "webmail",
    "api", "admin", "portal", "dashboard", "dev", "staging",
    "test", "beta", "internal", "intranet", "vpn", "remote",
    "ftp", "sftp", "ssh", "telnet",
    "shop", "store", "blog", "news", "docs", "wiki", "help",
    "cdn", "static", "assets", "media", "img", "images",
    "auth", "login", "sso", "oauth", "saml",
    "git", "gitlab", "github", "bitbucket", "svn",
    "monitor", "grafana", "prometheus", "kibana", "elastic",
    "jenkins", "jira", "confluence",
    "db", "mysql", "postgres", "redis", "mongo", "elastic",
    "k8s", "kube", "kubernetes", "rancher", "helm",
    "minio", "s3", "bucket", "storage", "blob",
    "lb", "haproxy", "nginx", "kong", "traefik",
    "m", "mobile", "app", "ios", "android",
)


async def _stdlib_subdomains(domain: str) -> list[str]:
    """Stdlib fallback: crt.sh + tiny brute list."""
    import urllib.request
    out: set[str] = set()
    # crt.sh
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "hack-deep-find/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read(2 * 1024 * 1024))
            for row in data:
                name = row.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith("." + domain) and "*" not in n:
                        out.add(n)
    except Exception:  # noqa: BLE001
        pass
    # tiny brute (resolve via getaddrinfo)
    for w in _BRUTE_WORDS:
        sub = f"{w}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(sub, None)
            out.add(sub)
        except (socket.gaierror, Exception):  # noqa: BLE001
            pass
    return sorted(out)


@tool(
    name="recon_subdomain_enum",
    description=(
        "Enumerate subdomains for a root domain. v4-preferred over "
        "domain-expander's stdlib DNS brute. Internally uses the "
        "``subfinder`` binary (https://github.com/projectdiscovery/"
        "subfinder) which integrates 30+ sources (crt.sh, chaos, shodan, "
        "censys, wayback, dnsdumpster, hackertarget, ...). Falls back "
        "to crt.sh + a tiny brute list when subfinder is not on PATH. "
        "Returns a JSON object with the source, a list of subdomains, "
        "and metadata. Use this in the F0 step of the find orchestrator."
    ),
    params={
        "domain": {
            "type": "string",
            "description": "Root domain (e.g. '51ifind.com').",
        },
        "timeout_s": {
            "type": "integer",
            "description": "Total timeout. Default: 180.",
            "default": 180,
        },
    },
    required=["domain"],
    execution_timeout_seconds=300.0,
)
async def recon_subdomain_enum(domain: str, timeout_s: int = 180) -> str:
    """Enumerate subdomains for a root domain."""
    bp = _binaries.detect("subfinder")
    if not bp.available:
        subs = await _stdlib_subdomains(domain)
        return json.dumps({
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "binary_error": "subfinder not on PATH",
            "domain": domain,
            "subdomain_count": len(subs),
            "subdomains": subs,
        }, ensure_ascii=False)

    out_path = f"/tmp/subfinder-{domain}.json"
    argv = [
        bp.path,
        "-d", domain,
        "-all",  # use all sources
        "-silent",
        "-json",
        "-o", out_path,
    ]
    try:
        rc, stdout, stderr = await _binaries._run_binary(argv, timeout_s=float(timeout_s))
    except (asyncio.TimeoutError, OSError) as exc:
        subs = await _stdlib_subdomains(domain)
        return json.dumps({
            "source": "stdlib",
            "binary_path": bp.path,
            "binary_version": bp.version,
            "binary_error": f"{type(exc).__name__}: {exc}",
            "domain": domain,
            "subdomain_count": len(subs),
            "subdomains": subs,
        }, ensure_ascii=False)

    # Parse subfinder JSONL output.
    subs: set[str] = set()
    try:
        out_file = Path(out_path)
        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    host = obj.get("host") or obj.get("subdomain") or obj.get("input")
                    if host and isinstance(host, str):
                        subs.add(host.strip().lower())
                except json.JSONDecodeError:
                    subs.add(line.strip().lower())
            try:
                out_file.unlink()
            except OSError:
                pass
    except OSError:
        pass

    return json.dumps({
        "source": "binary",
        "binary_path": bp.path,
        "binary_version": bp.version,
        "domain": domain,
        "subdomain_count": len(subs),
        "subdomains": sorted(subs),
    }, ensure_ascii=False)
