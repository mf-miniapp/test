"""Seed expansion / horizontal asset discovery tools (Batch 4, group:recon:seed).

Tools:
  - recon_whois_lookup          WHOIS query (registrant / nameservers / emails)
  - recon_asn_lookup            IP/domain → ASN + BGP prefix
  - recon_ct_subdomain_enum     crt.sh certificate transparency subdomain enum
  - recon_passive_dns           SecurityTrails/VirusTotal-style passive DNS
  - recon_related_domain_mining Same registrant / email / ns → related domains

Pure-stdlib; uses RDAP/WHOIS/HTTP. External services (crt.sh) are
read-only public endpoints.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


# ── helpers ──────────────────────────────────────────


def _http_get(url: str, timeout: float = 8.0) -> dict[str, Any]:
    import ssl

    result: dict[str, Any] = {"url": url, "status_code": None, "body": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (seed)")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            result["body"] = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        try:
            result["body"] = e.read().decode("utf-8", errors="replace")[:8192]
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ── 1. recon_whois_lookup ────────────────────────────


@tool(
    name="recon_whois_lookup",
    description=(
        "WHOIS lookup via the IANA RDAP bootstrap. Returns registrar, "
        "registrant name, registrant email, nameservers, creation/expiry "
        "dates, status codes. No RDAP API key required (public bootstrap)."
    ),
    params={
        "domain": {"type": "string"},
        "timeout_s": {"type": "number", "default": 8.0},
    },
    required=["domain"],
    execution_timeout_seconds=15.0,
)
async def recon_whois_lookup(domain: str, timeout_s: float = 8.0) -> str:
    loop = asyncio.get_running_loop()
    # Use RDAP bootstrap to find the registrar's RDAP endpoint
    bootstrap_url = f"https://rdap.org/domain/{domain}"
    res = await loop.run_in_executor(None, _http_get, bootstrap_url, timeout_s)
    if res["status_code"] != 200 or not res["body"]:
        return json.dumps(
            {"domain": domain, "ok": False, "error": res.get("error") or f"status_{res['status_code']}"},
            ensure_ascii=False,
        )
    try:
        doc = json.loads(res["body"])
    except json.JSONDecodeError:
        return json.dumps({"domain": domain, "ok": False, "error": "json_decode"}, ensure_ascii=False)

    # Extract common RDAP fields
    out: dict[str, Any] = {
        "domain": domain,
        "ok": True,
        "registrar": None,
        "registrant_name": None,
        "registrant_email": None,
        "admin_email": None,
        "nameservers": [],
        "created": None,
        "expires": None,
        "status": [],
    }
    for ent in doc.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray")
        name = None
        email = None
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if field and field[0] == "fn":
                    name = field[3]
                if field and field[0] == "email":
                    email = field[3]
        if "registrar" in roles:
            out["registrar"] = name
        if "registrant" in roles:
            out["registrant_name"] = name
            out["registrant_email"] = email
        if "administrative" in roles:
            out["admin_email"] = email
    for ns in doc.get("nameservers", []) or []:
        ldap_name = ns.get("ldhName")
        if ldap_name:
            out["nameservers"].append(ldap_name.lower())
    for ev in doc.get("events", []) or []:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action == "registration":
            out["created"] = date
        elif action == "expiration":
            out["expires"] = date
    out["status"] = doc.get("status", []) or []
    return json.dumps(out, ensure_ascii=False)


# ── 2. recon_asn_lookup ──────────────────────────────


def _parse_asnmap_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse asnmap -json output. One record per IP found in the ASN/org.

    asnmap -json emits records like:
      {"timestamp":"...","input":"google","as_number":"AS15169",
       "as_name":"GOOGLE","as_country":"US","as_range":["8.8.8.0/24",...],
       "ip_count":256}
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
            "asn": rec.get("as_number"),
            "as_name": rec.get("as_name"),
            "as_country": rec.get("as_country"),
            "ip_ranges": rec.get("as_range", []) or [],
            "ip_count": rec.get("ip_count"),
        })
    return out


@tool(
    name="recon_asn_lookup",
    description=(
        "Resolve a domain to its IP, then look up the IP's ASN. v4.4-preferred: "
        "uses asnmap binary (https://github.com/projectdiscovery/asnmap) "
        "for IP -> ASN + IP range. Falls back to ip-api.com HTTP API when "
        "asnmap is not on PATH. Returns ASN, AS name, country, IP range."
    ),
    params={
        "ip_or_domain": {"type": "string"},
        "timeout_s": {"type": "number", "default": 8.0},
    },
    required=["ip_or_domain"],
    execution_timeout_seconds=20.0,
)
async def recon_asn_lookup(ip_or_domain: str, timeout_s: float = 8.0) -> str:
    """ASN lookup via asnmap (preferred) or ip-api.com (fallback)."""
    bp = _binaries.detect("asnmap")
    if bp.available:
        try:
            # asnmap flag naming: -i for IP, -d for domain, -org for org
            is_ip = bool(re.match(r"^[\d.:a-fA-F]+$", ip_or_domain))
            if is_ip:
                argv = ["asnmap", "-json", "-i", ip_or_domain, "-silent"]
            else:
                argv = ["asnmap", "-json", "-d", ip_or_domain, "-silent"]
            rc, stdout, stderr = await _binaries._run_binary(
                argv, timeout_s=timeout_s + 5,
            )
            records = _parse_asnmap_jsonl(stdout)
            if records:
                r0 = records[0]
                return json.dumps({
                    "input": ip_or_domain,
                    "ok": True,
                    "asn": r0.get("asn"),
                    "as_name": r0.get("as_name"),
                    "as_country": r0.get("as_country"),
                    "ip_ranges": r0.get("ip_ranges", []),
                    "ip_count": r0.get("ip_count"),
                    "source": "asnmap", "binary_version": bp.version,
                }, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            pass  # fall through to ip-api

    import socket

    target_ip = ip_or_domain
    if not re.match(r"^[\d.:a-fA-F]+$", ip_or_domain):
        try:
            infos = socket.getaddrinfo(ip_or_domain, None, type=socket.SOCK_STREAM)
            target_ip = infos[0][4][0] if infos else ip_or_domain
        except Exception as e:  # noqa: BLE001
            return json.dumps({"input": ip_or_domain, "ok": False, "error": f"resolve: {e}"}, ensure_ascii=False)

    loop = asyncio.get_running_loop()
    api_url = f"http://ip-api.com/json/{target_ip}?fields=status,country,org,as,hosting,query"
    res = await loop.run_in_executor(None, _http_get, api_url, timeout_s)
    if res["status_code"] != 200 or not res["body"]:
        return json.dumps({"input": ip_or_domain, "resolved_ip": target_ip, "ok": False, "error": res.get("error")}, ensure_ascii=False)
    try:
        data = json.loads(res["body"])
    except json.JSONDecodeError:
        return json.dumps({"input": ip_or_domain, "ok": False, "error": "json_decode"}, ensure_ascii=False)
    as_field = data.get("as", "")  # e.g. "AS13335 Cloudflare, Inc."
    asn = None
    as_name = None
    m = re.match(r"^(AS\d+)\s+(.*)$", as_field)
    if m:
        asn = m.group(1)
        as_name = m.group(2)
    return json.dumps(
        {
            "input": ip_or_domain,
            "resolved_ip": target_ip,
            "ok": data.get("status") == "success",
            "asn": asn,
            "as_name": as_name,
            "country": data.get("country"),
            "org": data.get("org"),
            "hosting": data.get("hosting"),
            "bgp_prefix": None,  # ip-api.com doesn't return prefix
        },
        ensure_ascii=False,
    )


# ── 3. recon_ct_subdomain_enum ───────────────────────


@tool(
    name="recon_ct_subdomain_enum",
    description=(
        "Enumerate subdomains via crt.sh certificate transparency logs. "
        "Returns the list of subdomains found in publicly logged certs. "
        "Read-only, no key required."
    ),
    params={
        "domain": {"type": "string"},
        "limit": {"type": "integer", "default": 200},
        "timeout_s": {"type": "number", "default": 15.0},
    },
    required=["domain"],
    execution_timeout_seconds=60.0,
)
async def recon_ct_subdomain_enum(domain: str, limit: int = 200, timeout_s: float = 15.0) -> str:
    loop = asyncio.get_running_loop()
    url = f"https://crt.sh/?q={urllib_parse_quote(f'%.{domain}')}&output=json"
    res = await loop.run_in_executor(None, _http_get, url, timeout_s)
    if res["status_code"] != 200 or not res["body"]:
        return json.dumps(
            {"domain": domain, "ok": False, "error": res.get("error") or f"status_{res['status_code']}"},
            ensure_ascii=False,
        )
    try:
        entries = json.loads(res["body"])
    except json.JSONDecodeError:
        return json.dumps({"domain": domain, "ok": False, "error": "json_decode"}, ensure_ascii=False)
    if not isinstance(entries, list):
        return json.dumps({"domain": domain, "ok": False, "error": "unexpected_format"}, ensure_ascii=False)
    seen: set[str] = set()
    for e in entries[:limit]:
        name = (e.get("name_value") or "").strip()
        if name and name not in seen:
            seen.add(name)
    return json.dumps(
        {
            "domain": domain,
            "ok": True,
            "count": len(seen),
            "subdomains": sorted(seen)[:limit],
        },
        ensure_ascii=False,
    )


def urllib_parse_quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


# ── 4. recon_passive_dns ─────────────────────────────


@tool(
    name="recon_passive_dns",
    description=(
        "Best-effort passive DNS: queries a public HackerTarget API for "
        "historical A records. Returns a list of IPs that the domain "
        "historically resolved to. No key required."
    ),
    params={
        "domain": {"type": "string"},
        "limit": {"type": "integer", "default": 50},
        "timeout_s": {"type": "number", "default": 10.0},
    },
    required=["domain"],
    execution_timeout_seconds=30.0,
)
async def recon_passive_dns(domain: str, limit: int = 50, timeout_s: float = 10.0) -> str:
    loop = asyncio.get_running_loop()
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib_parse_quote(domain)}"
    res = await loop.run_in_executor(None, _http_get, url, timeout_s)
    if res["status_code"] != 200 or not res["body"]:
        return json.dumps(
            {"domain": domain, "ok": False, "error": res.get("error") or f"status_{res['status_code']}"},
            ensure_ascii=False,
        )
    # Parse "domain,ip\n" CSV
    pairs: list[dict[str, str]] = []
    for line in res["body"].splitlines():
        parts = line.split(",")
        if len(parts) == 2:
            pairs.append({"domain": parts[0].strip(), "ip": parts[1].strip()})
    return json.dumps(
        {
            "domain": domain,
            "ok": True,
            "count": len(pairs),
            "records": pairs[:limit],
        },
        ensure_ascii=False,
    )


# ── 5. recon_related_domain_mining ───────────────────


@tool(
    name="recon_related_domain_mining",
    description=(
        "Find domains related to `domain` by querying crt.sh for the same "
        "registrant organization / email. Returns a list of candidate "
        "related FQDNs. Heuristic — not authoritative."
    ),
    params={
        "domain": {"type": "string"},
        "limit": {"type": "integer", "default": 50},
        "timeout_s": {"type": "number", "default": 15.0},
    },
    required=["domain"],
    execution_timeout_seconds=60.0,
)
async def recon_related_domain_mining(
    domain: str,
    limit: int = 50,
    timeout_s: float = 15.0,
) -> str:
    """Heuristic: mine crt.sh for sibling domains by similar organization / email.

    Note: this is an approximation. A truly authoritative approach needs a
    paid passive-DNS / WHOIS-history API (SecurityTrails, Whoxy). The
    current implementation uses the same crt.sh endpoint but matches
    on the registrable domain's parent eTLD+1.
    """
    # First, derive the registrable root (eTLD+1)
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return json.dumps({"domain": domain, "ok": False, "error": "invalid_domain"}, ensure_ascii=False)
    root = ".".join(parts[-2:])

    loop = asyncio.get_running_loop()
    # crt.sh query: "%keyword" returns certs where CN contains the keyword
    url = f"https://crt.sh/?q={urllib_parse_quote(root)}&output=json"
    res = await loop.run_in_executor(None, _http_get, url, timeout_s)
    if res["status_code"] != 200 or not res["body"]:
        return json.dumps(
            {"domain": domain, "root": root, "ok": False, "error": res.get("error") or f"status_{res['status_code']}"},
            ensure_ascii=False,
        )
    try:
        entries = json.loads(res["body"])
    except json.JSONDecodeError:
        return json.dumps({"domain": domain, "ok": False, "error": "json_decode"}, ensure_ascii=False)

    # Heuristic: collect all unique eTLD+1 values from cert names, then
    # exclude the input root and any subdomain of it
    seen_root: set[str] = set()
    for e in entries[:limit * 4]:
        name = (e.get("name_value") or "").strip()
        if not name:
            continue
        # split on whitespace / comma (crt.sh returns multiple names separated by \n)
        for n in re.split(r"[\s,]+", name):
            n = n.lower().strip().lstrip("*.")
            if not n or "." not in n:
                continue
            np = n.split(".")
            if len(np) < 2:
                continue
            etld1 = ".".join(np[-2:])
            if etld1 == root:
                continue
            if n.endswith("." + root):
                continue
            seen_root.add(etld1)
        if len(seen_root) >= limit:
            break
    return json.dumps(
        {
            "domain": domain,
            "root": root,
            "ok": True,
            "count": len(seen_root),
            "related_domains": sorted(seen_root)[:limit],
        },
        ensure_ascii=False,
    )
