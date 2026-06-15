"""HTTP recon tools — stdlib only, no curl.

Group: ``group:recon:http``.

Why stdlib HTTP rather than curl: the existing ``scanner_tools.py`` used
``asyncio.create_subprocess_exec("curl", ...)`` which conflicts with the
sandbox approval pipeline. Stdlib ``urllib`` runs inline and stays inside
the pure-data-plane contract.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


@tool(
    name="recon_http_probe",
    description=(
        "Issue an HTTP HEAD/GET to `url` and return the status code, "
        "final URL (after redirects), and Server header. SSL verification "
        "is OFF by default so self-signed certs don't fail the probe — "
        "this is reconnaissance, not auth. Use this to verify a service is "
        "reachable before adding ENDPOINT children to the AssetTree."
    ),
    params={
        "url": {"type": "string", "description": "Full URL (e.g. 'http://1.2.3.4:8080/')."},
        "method": {
            "type": "string",
            "enum": ["HEAD", "GET"],
            "description": "HTTP method. Default: HEAD (lighter).",
            "default": "HEAD",
        },
        "timeout_s": {
            "type": "number",
            "description": "Total request timeout. Default: 5.0.",
            "default": 5.0,
        },
        "verify_ssl": {
            "type": "boolean",
            "description": "Verify TLS cert. Default: false (recon mode).",
            "default": False,
        },
    },
    required=["url"],
    execution_timeout_seconds=15.0,
)
async def recon_http_probe(
    url: str,
    method: str = "HEAD",
    timeout_s: float = 5.0,
    verify_ssl: bool = False,
) -> str:
    """Probe an HTTP endpoint."""
    import ssl

    result: dict[str, Any] = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "server": None,
        "title": None,
        "content_type": None,
        "error": None,
    }

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # type: ignore[override]
            return None

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ctx),
    )

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "hack-deep-find/2.0 (recon)")

    try:
        loop = asyncio.get_running_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: opener.open(req, timeout=timeout_s),
            ),
            timeout=timeout_s + 1,
        )
        result["status_code"] = response.status
        result["final_url"] = response.geturl()
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        # Try to extract <title> from a small GET if this was a HEAD
        if method == "HEAD" or not result["server"]:
            try:
                get_req = urllib.request.Request(url, method="GET")
                get_req.add_header("User-Agent", "hack-deep-find/2.0 (recon)")
                body_resp = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: opener.open(get_req, timeout=timeout_s),
                    ),
                    timeout=timeout_s + 1,
                )
                body = body_resp.read(64 * 1024).decode("utf-8", errors="ignore")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:256]
            except Exception:
                pass
    except urllib.error.HTTPError as exc:
        result["status_code"] = exc.code
        result["server"] = exc.headers.get("Server") if exc.headers else None
        result["error"] = f"HTTPError: {exc.code} {exc.reason}"
    except (urllib.error.URLError, asyncio.TimeoutError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return json.dumps(result, ensure_ascii=False)


# ── Internal helpers (NOT exposed as tools) ─────────────────────────────


def detect_cdn(cname: str | None) -> str | None:
    """Map a CNAME to its CDN provider (Cloudflare / Akamai / etc.)."""
    if not cname:
        return None

    cdn_patterns = {
        "cloudflare": ["cloudflare.com", "cloudflare.net"],
        "akamai": ["akamai.net", "akamaiedge.net", "akamaihd.net"],
        "fastly": ["fastly.net", "fastlylb.net"],
        "cloudfront": ["cloudfront.net", "amazonaws.com"],
    }

    cname_lower = cname.lower()
    for provider, patterns in cdn_patterns.items():
        for pattern in patterns:
            if pattern in cname_lower:
                return provider
    return None