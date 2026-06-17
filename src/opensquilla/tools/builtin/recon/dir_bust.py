"""Directory bruteforce — ffuf (preferred) / stdlib (fallback).

Group: ``group:recon:http``.

v4.4 (2026-06-18) hardening: ffuf binary
(https://github.com/ffuf/ffuf) is a purpose-built web fuzzer
that handles 1000+ wordlist entries in seconds. Stdlib
asyncio.gather+urllib is the FALLBACK for hosts without ffuf.

ffuf emits JSON to stdout with one record per match. We parse
the JSON for {url, status, length, words, lines} and return
the same shape as the stdlib path.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


_DEFAULT_WORDLIST: tuple[str, ...] = (
    "/admin", "/login", "/api", "/swagger", "/docs",
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
    "/backup", "/config", "/debug", "/health", "/status",
    "/version", "/metrics", "/actuator", "/graphql",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
)


def _parse_ffuf_json(text: str) -> list[dict[str, Any]]:
    """Parse ffuf -json output.

    ffuf -json emits a single JSON object with `results` array
    (one entry per match) and `config` block.
    """
    out: list[dict] = []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return out
    for r in payload.get("results", []) or []:
        url = r.get("url", "")
        # Strip the fuzz position to recover the matched path.
        input_field = r.get("input", {}) or {}
        # ffuf FUZZ keyword default; we use it as path.
        path = input_field.get("FUZZ", "")
        if not path and url:
            # fall back: derive from url vs base
            path = url
        out.append({
            "path": path,
            "url": url,
            "status_code": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
        })
    return out


@tool(
    name="recon_directory_bruteforce",
    description=(
        "Probe a list of paths under `base_url` and return the ones that "
        "respond with non-404 status. v4.4-preferred: uses ffuf binary "
        "(https://github.com/ffuf/ffuf) for fast parallel fuzzing. Falls "
        "back to stdlib asyncio.gather+urllib when ffuf is not on PATH. "
        "Default wordlist targets common admin / debug / API discovery "
        "paths; supply your own for deeper coverage."
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
            "description": "ffuf -t flag: concurrent threads. Default: 40.",
            "default": 40,
        },
        "timeout_s": {
            "type": "integer",
            "description": "Per-request timeout. Default: 5.",
            "default": 5,
        },
        "match_status": {
            "type": "string",
            "description": "ffuf -mc flag: matching status codes. Default: '200,201,202,204,301,302,307,401,403'.",
            "default": "200,201,202,204,301,302,307,401,403",
        },
    },
    required=["base_url"],
    execution_timeout_seconds=300.0,
)
async def recon_directory_bruteforce(
    base_url: str,
    wordlist: list[str] | None = None,
    concurrency: int = 40,
    timeout_s: int = 5,
    match_status: str = "200,201,202,204,301,302,307,401,403",
) -> str:
    """Bruteforce a path list against base_url. ffuf (preferred) / stdlib (fallback)."""
    paths = tuple(wordlist) if wordlist else _DEFAULT_WORDLIST
    base = base_url.rstrip("/")

    bp = _binaries.detect("ffuf")
    if bp.available:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            # ffuf wordlist: each line is the FUZZ placeholder content.
            for p in paths:
                # Strip leading slash — ffuf FUZZ will be appended to base.
                p_norm = p if p.startswith("/") else "/" + p
                f.write(p_norm + "\n")
            tmp_wl = f.name
        try:
            rc, stdout, stderr = await _binaries._run_binary(
                ["ffuf", "-u", f"{base}/FUZZ", "-w", tmp_wl,
                 "-mc", match_status, "-t", str(concurrency),
                 "-timeout", str(timeout_s),
                 "-json", "-noninteractive", "-s"],
                timeout_s=max(60, len(paths) * 2),
            )
            hits = _parse_ffuf_json(stdout)
            return json.dumps({
                "base_url": base, "scanned": len(paths),
                "hits": hits, "hit_count": len(hits),
                "source": "ffuf", "binary_version": bp.version,
            }, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            pass  # fall through to stdlib
        finally:
            try:
                Path(tmp_wl).unlink()
            except OSError:
                pass

    # Stdlib fallback.
    semaphore = asyncio.Semaphore(min(concurrency, 40))
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
    return json.dumps({
        "base_url": base, "scanned": len(paths),
        "hits": hits, "hit_count": len(hits), "source": "stdlib",
    }, ensure_ascii=False)
