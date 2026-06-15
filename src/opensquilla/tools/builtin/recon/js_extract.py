"""JS endpoint extractor — pulls likely API paths from a JS bundle.

Group: ``group:recon:http``.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""["'](/(?:api|v[0-9]+)/[a-zA-Z0-9/_-]+)['"]"""),
    re.compile(r"""["'](/[a-zA-Z0-9/_-]+\.(?:json|xml))['"]"""),
    re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
    re.compile(r"""\.get\(\s*["']([^"']+)["']"""),
    re.compile(r"""\.post\(\s*["']([^"']+)["']"""),
    re.compile(r"""url\s*:\s*["']([^"']+)["']"""),
)


@tool(
    name="recon_extract_endpoints_from_js",
    description=(
        "Download a JavaScript bundle from `js_url` and extract likely "
        "API endpoint paths via regex (fetch/axios/url literals, "
        "API/versioned paths, .json/.xml filenames). Returns the unique "
        "extracted paths sorted by frequency."
    ),
    params={
        "js_url": {
            "type": "string",
            "description": "URL of the JavaScript file to analyze.",
        },
        "timeout_s": {
            "type": "number",
            "description": "Download timeout. Default: 10.0.",
            "default": 10.0,
        },
        "max_body_mb": {
            "type": "number",
            "description": "Maximum JS body size to download (MB). Default: 5.",
            "default": 5,
        },
    },
    required=["js_url"],
    execution_timeout_seconds=20.0,
)
async def recon_extract_endpoints_from_js(
    js_url: str,
    timeout_s: float = 10.0,
    max_body_mb: float = 5.0,
) -> str:
    """Extract API endpoints from a JavaScript file."""
    result: dict[str, Any] = {
        "js_url": js_url,
        "endpoints": [],
        "endpoint_count": 0,
        "error": None,
    }
    max_bytes = int(max_body_mb * 1024 * 1024)

    try:
        req = urllib.request.Request(js_url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (recon)")
        loop = asyncio.get_running_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=timeout_s),
            ),
            timeout=timeout_s + 1,
        )
        body = response.read(max_bytes).decode("utf-8", errors="ignore")
    except (urllib.error.URLError, asyncio.TimeoutError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return json.dumps(result, ensure_ascii=False)

    seen: set[str] = set()
    endpoints: list[str] = []
    for pattern in _PATTERNS:
        for match in pattern.finditer(body):
            candidate = match.group(1).strip().strip("\"'")
            if candidate and len(candidate) > 2 and candidate not in seen:
                seen.add(candidate)
                endpoints.append(candidate)

    result["endpoints"] = endpoints
    result["endpoint_count"] = len(endpoints)
    return json.dumps(result, ensure_ascii=False)