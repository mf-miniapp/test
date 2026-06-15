"""Cookie and HTTP header security tools (Batch 2, group:recon:header).

Tools:
  - recon_cookie_security_parse   Parse Set-Cookie, check security flags
  - recon_security_header_audit   Audit security headers (CSP, HSTS, etc.)
  - recon_info_disclosure_header_scan  Detect info-leaking headers
  - recon_cookie_jar_collect      Follow redirects, collect all Set-Cookies

Pure-stdlib implementation.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


# ── helpers ──────────────────────────────────────────


def _http_get(url: str, timeout: float = 5.0) -> dict[str, Any]:
    import ssl

    result: dict[str, Any] = {
        "url": url,
        "status_code": None,
        "headers": {},
        "set_cookies": [],
        "body": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (header)")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            for k, v in resp.headers.items():
                result["headers"].setdefault(k.lower(), v)
            for hk, hv in resp.headers.items():
                if hk.lower() == "set-cookie":
                    result["set_cookies"].append(hv)
            result["body"] = resp.read(256 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        try:
            for hk, hv in e.headers.items():
                if hk.lower() == "set-cookie":
                    result["set_cookies"].append(hv)
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ── 1. recon_cookie_security_parse ───────────────────


@tool(
    name="recon_cookie_security_parse",
    description=(
        "Parse a single Set-Cookie header. Returns name, value preview, "
        "HttpOnly, Secure, SameSite, Expires, Max-Age, Domain, Path, plus "
        "a risk score and reasons."
    ),
    params={
        "set_cookie_header": {"type": "string", "description": "Raw Set-Cookie value."},
    },
    required=["set_cookie_header"],
)
async def recon_cookie_security_parse(set_cookie_header: str) -> str:
    if not set_cookie_header:
        return json.dumps({"valid": False, "error": "empty"}, ensure_ascii=False)
    # Strip leading Set-Cookie: if present
    s = set_cookie_header.strip()
    if s.lower().startswith("set-cookie:"):
        s = s.split(":", 1)[1].strip()
    # Split name=value from attrs
    parts = [p.strip() for p in s.split(";")]
    nv = parts[0]
    if "=" not in nv:
        return json.dumps({"valid": False, "error": "no_name_value"}, ensure_ascii=False)
    name, value = nv.split("=", 1)
    name = name.strip()
    value = value.strip()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = "true"

    http_only = "httponly" in attrs
    secure = "secure" in attrs
    same_site = attrs.get("samesite", "None").capitalize() if "samesite" in attrs else "None"
    expires = attrs.get("expires")
    max_age_raw = attrs.get("max-age")
    max_age: int | None
    try:
        max_age = int(max_age_raw) if max_age_raw else None
    except ValueError:
        max_age = None
    domain = attrs.get("domain")
    path = attrs.get("path", "/")

    # Risk scoring
    risk_reasons: list[str] = []
    auth_keywords = ("session", "auth", "token", "jwt", "sid", "csrf", "phpsessid", "jsessionid", "asp.net_sessionid")
    if any(k in name.lower() for k in auth_keywords) and not http_only:
        risk_reasons.append("missing_httponly_on_auth_cookie")
    if not secure:
        risk_reasons.append("missing_secure_flag")
    if same_site == "None":
        risk_reasons.append("missing_samesite")
    if not expires and (max_age is None or max_age > 31536000 * 5):
        risk_reasons.append("persistent_without_expiry")
    if any(k in name.lower() for k in auth_keywords) and not http_only:
        risk = "high"
    elif "missing_secure_flag" in risk_reasons or "missing_samesite" in risk_reasons:
        risk = "medium"
    else:
        risk = "low"

    # Value preview: first 20 chars + "..." + total length
    v_preview = value[:20] + ("..." if len(value) > 20 else "")

    return json.dumps(
        {
            "valid": True,
            "name": name,
            "value_preview": v_preview,
            "value_length": len(value),
            "http_only": http_only,
            "secure": secure,
            "same_site": same_site,
            "expires": expires,
            "max_age": max_age,
            "domain": domain,
            "path": path,
            "risk": risk,
            "risk_reasons": risk_reasons,
        },
        ensure_ascii=False,
    )


# ── 2. recon_security_header_audit ───────────────────


_SECURITY_HEADERS_EXPECTED: tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",  # legacy but still expected
)


@tool(
    name="recon_security_header_audit",
    description=(
        "Audit a URL's response for the presence of expected security headers. "
        "Returns one entry per header (present or missing) with value + verdict."
    ),
    params={
        "url": {"type": "string"},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["url"],
    execution_timeout_seconds=15.0,
)
async def recon_security_header_audit(url: str, timeout_s: float = 5.0) -> str:
    res = _http_get(url, timeout=timeout_s)
    if res.get("error") and not res.get("headers"):
        return json.dumps({"error": res["error"], "headers": []}, ensure_ascii=False)
    headers = res.get("headers", {})
    audit: list[dict[str, Any]] = []
    for h in _SECURITY_HEADERS_EXPECTED:
        present = h in headers
        value = headers.get(h) if present else None
        audit.append(
            {
                "name": h,
                "present": present,
                "value": value,
                "security_relevant": True,
                "missing": not present,
            }
        )
    return json.dumps(
        {"url": url, "status_code": res.get("status_code"), "headers": audit, "missing_count": sum(1 for a in audit if a["missing"])},
        ensure_ascii=False,
    )


# ── 3. recon_info_disclosure_header_scan ─────────────


_INFO_DISCLOSURE_HEADERS: tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-aspnetmono-version",
    "x-runtime",
    "x-generator",
    "x-varnish",
    "via",
)


@tool(
    name="recon_info_disclosure_header_scan",
    description=(
        "Scan a URL's response for headers that leak stack / version info. "
        "Returns hits with value and disclosure kind."
    ),
    params={
        "url": {"type": "string"},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["url"],
    execution_timeout_seconds=15.0,
)
async def recon_info_disclosure_header_scan(url: str, timeout_s: float = 5.0) -> str:
    res = _http_get(url, timeout=timeout_s)
    headers = res.get("headers", {})
    findings: list[dict[str, Any]] = []
    for h in _INFO_DISCLOSURE_HEADERS:
        if h in headers:
            value = headers[h]
            # Disclosure kind classification
            kind = "version_revealed"
            if h == "x-powered-by":
                kind = "stack_revealed"
            elif h == "x-runtime":
                kind = "framework_version_revealed"
            elif h in ("x-aspnet-version", "x-aspnetmvc-version", "x-aspnetmono-version"):
                kind = "framework_version_revealed"
            elif h == "via":
                kind = "proxy_chain_revealed"
            elif h == "x-generator":
                kind = "generator_revealed"
            findings.append(
                {
                    "name": h,
                    "present": True,
                    "value": value,
                    "security_relevant": True,
                    "missing": False,
                    "disclosure": True,
                    "disclosure_kind": kind,
                }
            )
    return json.dumps(
        {"url": url, "headers": findings, "disclosure_count": len(findings)},
        ensure_ascii=False,
    )


# ── 4. recon_cookie_jar_collect ──────────────────────


@tool(
    name="recon_cookie_jar_collect",
    description=(
        "Fetch a URL (optionally following up to `max_redirects` hops) and "
        "collect all Set-Cookie headers + all response headers. Returns a "
        "list of cookies (raw strings) and a header map."
    ),
    params={
        "url": {"type": "string"},
        "max_redirects": {"type": "integer", "default": 3},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["url"],
    execution_timeout_seconds=30.0,
)
async def recon_cookie_jar_collect(
    url: str,
    max_redirects: int = 3,
    timeout_s: float = 5.0,
) -> str:
    """Walk redirects (manually, to capture all Set-Cookie headers)."""
    cookies: list[str] = []
    headers_seen: dict[str, str] = {}
    final_url = url
    final_status: int | None = None
    last_body = None
    for _ in range(max_redirects + 1):
        res = _http_get(final_url, timeout=timeout_s)
        if res.get("error"):
            return json.dumps(
                {"final_url": final_url, "error": res["error"], "cookies": cookies, "headers": headers_seen},
                ensure_ascii=False,
            )
        for c in res.get("set_cookies", []):
            if c not in cookies:
                cookies.append(c)
        for k, v in res.get("headers", {}).items():
            headers_seen.setdefault(k, v)
        last_body = res.get("body")
        final_status = res.get("status_code")
        if final_status in (301, 302, 303, 307, 308):
            loc = res.get("headers", {}).get("location")
            if loc:
                if loc.startswith("/"):
                    from urllib.parse import urlparse, urljoin

                    final_url = urljoin(final_url, loc)
                else:
                    final_url = loc
                continue
        break
    return json.dumps(
        {
            "final_url": final_url,
            "status_code": final_status,
            "cookie_count": len(cookies),
            "cookies": cookies,
            "headers": headers_seen,
            "body_preview": (last_body or "")[:256] if last_body else None,
        },
        ensure_ascii=False,
    )
