"""Authentication surface tools (Batch 2, group:recon:auth).

Tools:
  - recon_auth_endpoint_discover   Probe candidate auth endpoints
  - recon_oauth_flow_probe          OAuth/OIDC/SAML flow discovery
  - recon_jwt_analyze               Parse JWT header/payload
  - recon_default_creds_probe       Common default credential testing
  - recon_auth_form_parse           Parse login HTML form

Pure-stdlib implementation; no external auth framework.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


# ── helpers ──────────────────────────────────────────


def _http_request(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
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
        req = urllib.request.Request(url, method=method, data=body)
        req.add_header("User-Agent", "hack-deep-find/2.0 (auth)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            for k, v in resp.headers.items():
                result["headers"].setdefault(k.lower(), v)
            # urllib lowercases all header keys
            for hk, hv in resp.headers.items():
                if hk.lower() == "set-cookie":
                    result["set_cookies"].append(hv)
            result["body"] = resp.read(256 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        for hk, hv in e.headers.items():
            if hk.lower() == "set-cookie":
                result["set_cookies"].append(hv)
        try:
            result["body"] = e.read().decode("utf-8", errors="replace")[:8192]
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ── 1. recon_auth_endpoint_discover ──────────────────


_DEFAULT_AUTH_CANDIDATES: tuple[str, ...] = (
    "/login", "/signin", "/auth", "/auth/login", "/api/auth/login",
    "/api/v1/auth/login", "/user/login", "/account/login", "/admin/login",
    "/sso", "/saml/sso", "/auth/sso", "/oauth/authorize",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/register", "/signup", "/api/auth/register",
    "/forgot-password", "/reset-password", "/account/forgot",
    "/mfa", "/2fa", "/verify", "/api/auth/mfa",
    "/api-keys", "/tokens", "/api/v1/tokens",
    "/api/auth", "/auth/oauth", "/sso/login",
)


@tool(
    name="recon_auth_endpoint_discover",
    description=(
        "Probe a list of candidate auth paths against base_url and classify "
        "each by kind (login/register/sso/oauth/apikey/reset/mfa). Returns "
        "the hits with status + content_type + a hint for the form action."
    ),
    params={
        "base_url": {"type": "string"},
        "candidates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Paths to try. Default: ~30 common auth paths.",
        },
        "concurrency": {"type": "integer", "default": 10},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=60.0,
)
async def recon_auth_endpoint_discover(
    base_url: str,
    candidates: list[str] | None = None,
    concurrency: int = 10,
    timeout_s: float = 5.0,
) -> str:
    cands = tuple(candidates) if candidates else _DEFAULT_AUTH_CANDIDATES
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()
    found: list[dict[str, Any]] = []

    async def _probe(path: str) -> None:
        url = f"{origin}{path}"
        async with sem:
            res = await loop.run_in_executor(None, _http_request, url, "GET", None, None, timeout_s)
            if res["status_code"] in (200, 301, 302):
                kind = _classify_auth_kind(path)
                entry = {
                    "path": path,
                    "kind": kind,
                    "method": "GET",
                    "status": res["status_code"],
                    "content_type": res["headers"].get("content-type"),
                }
                # form action hint
                body = res.get("body") or ""
                m = re.search(r"<form[^>]+action=['\"]([^'\"]*)", body, re.IGNORECASE)
                if m:
                    entry["form_action"] = m.group(1)
                found.append(entry)

    await asyncio.gather(*[_probe(p) for p in cands])
    found.sort(key=lambda e: e["path"])
    return json.dumps(
        {"base_url": base_url, "tried": len(cands), "found": found},
        ensure_ascii=False,
    )


def _classify_auth_kind(path: str) -> str:
    p = path.lower()
    if any(k in p for k in ("/forgot", "/reset")):
        return "reset"
    if "/register" in p or "/signup" in p:
        return "register"
    if "/sso" in p or "/saml" in p:
        return "sso"
    if "/oauth" in p or "openid-configuration" in p or "oauth-authorization" in p:
        return "oauth"
    if "/api-key" in p or "/tokens" in p:
        return "apikey"
    if "/mfa" in p or "/2fa" in p or "/verify" in p:
        return "mfa"
    return "login"


# ── 2. recon_oauth_flow_probe ────────────────────────


_OAUTH_CANDIDATES: tuple[str, ...] = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/oauth/authorize",
    "/saml/sso",
    "/saml2/sso",
)


@tool(
    name="recon_oauth_flow_probe",
    description=(
        "Probe OIDC/OAuth2/SAML discovery endpoints and parse the metadata "
        "document when found. Returns authorization_endpoint, token_endpoint, "
        "scopes, response_types, and the discovered grant types."
    ),
    params={
        "base_url": {"type": "string"},
        "candidates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "OAuth/SAML discovery paths. Default: 7 common.",
        },
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=30.0,
)
async def recon_oauth_flow_probe(
    base_url: str,
    candidates: list[str] | None = None,
    timeout_s: float = 5.0,
) -> str:
    cands = tuple(candidates) if candidates else _OAUTH_CANDIDATES
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    loop = asyncio.get_running_loop()
    for path in cands:
        url = f"{origin}{path}"
        res = await loop.run_in_executor(None, _http_request, url, "GET", None, None, timeout_s)
        if res["status_code"] != 200 or not res["body"]:
            continue
        # OIDC / OAuth2 metadata is JSON
        if path.endswith("openid-configuration") or path.endswith("oauth-authorization-server"):
            try:
                meta = json.loads(res["body"])
            except json.JSONDecodeError:
                continue
            return json.dumps(
                {
                    "discovery_url": url,
                    "scheme": "oidc" if "openid-configuration" in path else "oauth2",
                    "authorization_endpoint": meta.get("authorization_endpoint"),
                    "token_endpoint": meta.get("token_endpoint"),
                    "userinfo_endpoint": meta.get("userinfo_endpoint"),
                    "scopes_supported": meta.get("scopes_supported", []),
                    "response_types_supported": meta.get("response_types_supported", []),
                    "grant_types_supported": meta.get("grant_types_supported", []),
                    "code_challenge_methods_supported": meta.get("code_challenge_methods_supported", []),
                },
                ensure_ascii=False,
            )
        # SAML: HTML form with SAMLRequest
        if "/saml" in path and "SAMLRequest" in res["body"]:
            m = re.search(r'action="([^"]+)"', res["body"])
            return json.dumps(
                {"discovery_url": url, "scheme": "saml", "sso_url": m.group(1) if m else url},
                ensure_ascii=False,
            )
    return json.dumps({"discovery_url": None, "scheme": None}, ensure_ascii=False)


# ── 3. recon_jwt_analyze ─────────────────────────────


@tool(
    name="recon_jwt_analyze",
    description=(
        "Parse a JWT (header.payload.signature), decode header and payload "
        "(without verification), report alg, exp, iat, iss, aud, sub, and "
        "remaining validity in seconds."
    ),
    params={
        "token": {"type": "string", "description": "JWT (Bearer xxx format supported)."},
    },
    required=["token"],
)
async def recon_jwt_analyze(token: str) -> str:
    # Strip "Bearer " prefix if present
    t = (token or "").strip()
    if t.lower().startswith("bearer "):
        t = t[7:].strip()
    parts = t.split(".")
    if len(parts) != 3:
        return json.dumps({"valid": False, "error": "not_jwt_format"}, ensure_ascii=False)

    def _decode(seg: str) -> dict[str, Any] | None:
        try:
            padded = seg + "=" * (-len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return None

    header = _decode(parts[0]) or {}
    payload = _decode(parts[1]) or {}

    # exp / iat are seconds since epoch
    import time

    now = int(time.time())
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    return json.dumps(
        {
            "valid": True,
            "alg": header.get("alg"),
            "typ": header.get("typ"),
            "kid": header.get("kid"),
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "sub": payload.get("sub"),
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "jti": payload.get("jti"),
            "scope": payload.get("scope"),
            "scopes": payload.get("scopes"),
            "remaining_seconds": (exp - now) if isinstance(exp, (int, float)) else None,
            "issued_seconds_ago": (now - iat) if isinstance(iat, (int, float)) else None,
        },
        ensure_ascii=False,
    )


# ── 4. recon_default_creds_probe ─────────────────────


_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("demo", "demo"),
)


@tool(
    name="recon_default_creds_probe",
    description=(
        "Try a small set of well-known default credentials against an auth "
        "URL (form POST or basic auth). Returns hits where the response "
        "indicates success (302/200 with body length > baseline). Stops "
        "after the first hit per URL."
    ),
    params={
        "auth_url": {"type": "string", "description": "The login endpoint URL."},
        "username_field": {"type": "string", "default": "username"},
        "password_field": {"type": "string", "default": "password"},
        "max_attempts": {"type": "integer", "default": 5, "description": "Cap default-cred attempts."},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["auth_url"],
    execution_timeout_seconds=60.0,
)
async def recon_default_creds_probe(
    auth_url: str,
    username_field: str = "username",
    password_field: str = "password",
    max_attempts: int = 5,
    timeout_s: float = 5.0,
) -> str:
    """Try common default creds. Returns the first hit (if any)."""
    loop = asyncio.get_running_loop()
    creds = _DEFAULT_CREDS[: max_attempts]
    # Baseline probe
    baseline = await loop.run_in_executor(None, _http_request, auth_url, "GET", None, None, timeout_s)
    baseline_len = len((baseline.get("body") or ""))
    baseline_status = baseline.get("status_code")

    hits: list[dict[str, Any]] = []
    for u, p in creds:
        body = f"{username_field}={urllib.parse.quote(u)}&{password_field}={urllib.parse.quote(p)}".encode("utf-8")
        res = await loop.run_in_executor(
            None, _http_request, auth_url, "POST", body,
            {"Content-Type": "application/x-www-form-urlencoded"}, timeout_s
        )
        status = res.get("status_code")
        body_len = len((res.get("body") or ""))
        # Heuristic: 302 redirect OR 200 with body length noticeably different from baseline
        if status in (301, 302) or (status == 200 and abs(body_len - baseline_len) > 100):
            hits.append({"username": u, "password": p, "status": status, "body_len": body_len})
            break
    return json.dumps(
        {
            "auth_url": auth_url,
            "baseline_status": baseline_status,
            "baseline_body_len": baseline_len,
            "attempts": len(creds),
            "hits": hits,
        },
        ensure_ascii=False,
    )


# ── 5. recon_auth_form_parse ─────────────────────────


_FORM_RE = re.compile(
    r"<form(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL
)
_INPUT_RE = re.compile(
    r"<input\b(?P<attrs>[^>]*)>", re.IGNORECASE
)
_ATTR_RE = re.compile(r"""(?P<name>\w+)\s*=\s*['"](?P<value>[^'"]*)['"]""", re.IGNORECASE)


@tool(
    name="recon_auth_form_parse",
    description=(
        "Parse an HTML login form: extract action, method, and all input "
        "fields (name + type). Returns structured form metadata."
    ),
    params={
        "html": {"type": "string", "description": "HTML body to parse."},
    },
    required=["html"],
)
async def recon_auth_form_parse(html: str) -> str:
    if not html:
        return json.dumps({"forms": [], "parse_status": "empty"}, ensure_ascii=False)
    forms: list[dict[str, Any]] = []
    for m in _FORM_RE.finditer(html):
        attrs = dict(_ATTR_RE.findall(m.group("attrs")))
        body = m.group("body")
        fields: list[dict[str, str]] = []
        for inp in _INPUT_RE.finditer(body):
            iattrs = dict(_ATTR_RE.findall(inp.group("attrs")))
            fields.append(
                {
                    "name": iattrs.get("name", ""),
                    "type": iattrs.get("type", "text"),
                    "value": iattrs.get("value", ""),
                }
            )
        forms.append(
            {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method") or "GET").upper(),
                "fields": fields,
                "field_names": [f["name"] for f in fields if f["name"]],
                "has_csrf": any("csrf" in f["name"].lower() or "_token" in f["name"].lower() for f in fields),
                "has_password": any(f["type"] == "password" for f in fields),
            }
        )
    return json.dumps(
        {"forms": forms, "form_count": len(forms), "parse_status": "ok"},
        ensure_ascii=False,
    )
