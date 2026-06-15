"""Directory bruteforce — bounded fan-out, stdlib urllib only.

Group: ``group:recon:http``.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


_DEFAULT_WORDLIST: tuple[str, ...] = (
    "/admin", "/login", "/api", "/swagger", "/docs",
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
    "/backup", "/config", "/debug", "/health", "/status",
    "/version", "/metrics", "/actuator", "/graphql",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
)


@tool(
    name="recon_directory_bruteforce",
    description=(
        "Probe a list of paths under `base_url` and return the ones that "
        "respond with non-404 status. Concurrency is bounded so this is "
        "safe against an arbitrary-size wordlist. Default wordlist targets "
        "common admin / debug / API discovery paths; supply your own for "
        "deeper coverage."
    ),
    params={
        "base_url": {
            "type": "string",
            "description": "Base URL (e.g. 'https://example.com'). No trailing slash.",
        },
        "wordlist": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Paths to probe (each prefixed to base_url). "
                "Default: 21-path common-discovery wordlist."
            ),
        },
        "concurrency": {
            "type": "integer",
            "description": "Max concurrent requests. Default: 10.",
            "default": 10,
        },
        "timeout_s": {
            "type": "number",
            "description": "Per-request timeout. Default: 5.0.",
            "default": 5.0,
        },
    },
    required=["base_url"],
    execution_timeout_seconds=120.0,
)
async def recon_directory_bruteforce(
    base_url: str,
    wordlist: list[str] | None = None,
    concurrency: int = 10,
    timeout_s: float = 5.0,
) -> str:
    """Bruteforce a path list against base_url."""
    paths = tuple(wordlist) if wordlist else _DEFAULT_WORDLIST
    base = base_url.rstrip("/")
    semaphore = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()

    async def _probe(path: str) -> dict[str, Any] | None:
        async with semaphore:
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "hack-deep-find/2.0 (recon)")
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: urllib.request.urlopen(req, timeout=timeout_s),
                    ),
                    timeout=timeout_s + 1,
                )
                code = response.status
            except urllib.error.HTTPError as exc:
                code = exc.code
            except (urllib.error.URLError, asyncio.TimeoutError, OSError):
                return None

            if code in (404, 0):
                return None
            return {"path": path, "url": url, "status_code": code}

    results = await asyncio.gather(*[_probe(p) for p in paths])
    hits = [r for r in results if r is not None]
    return json.dumps(
        {
            "base_url": base,
            "scanned": len(paths),
            "hits": hits,
            "hit_count": len(hits),
        },
        ensure_ascii=False,
    )