"""URL deep crawl — katana (preferred) / stdlib (fallback).

v4 (2026-06-17): F3.5 web crawl. katana is a Go-based crawler with
headless browser support, JS extraction, form filling, and depth
control. Stdlib fallback is a simple BFS with HEAD/GET probes.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


_LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\'#]+)["\']', re.IGNORECASE)


async def _stdlib_crawl(start_url: str, max_depth: int, max_urls: int, timeout_s: float) -> dict:
    """BFS crawler. Honors same-origin only. Light weight."""
    parsed = urllib.parse.urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    endpoints: list[dict] = []
    js_files: list[str] = []
    while queue and len(visited) < max_urls:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hack-deep-find/2.0"})
            with urllib.request.urlopen(req, timeout=timeout_s) as r:
                ct = r.headers.get("Content-Type", "")
                body = r.read(256 * 1024)
                if "html" not in ct.lower():
                    continue
                body_str = body.decode("utf-8", errors="ignore")
                endpoints.append({
                    "url": url,
                    "method": "GET",
                    "status": r.status,
                    "content_type": ct,
                    "depth": depth,
                })
                for m in _LINK_RE.finditer(body_str):
                    href = m.group(1).strip()
                    if not href or href.startswith("javascript:"):
                        continue
                    absolute = urllib.parse.urljoin(url, href)
                    if absolute.startswith(origin) and absolute not in visited:
                        queue.append((absolute, depth + 1))
                for m in _SRC_RE.finditer(body_str):
                    src = m.group(1).strip()
                    if src.endswith(".js"):
                        js_files.append(urllib.parse.urljoin(url, src))
        except Exception:  # noqa: BLE001
            pass
    return {
        "start_url": start_url,
        "endpoints": endpoints,
        "js_files": list(set(js_files)),
        "crawled_count": len(visited),
    }


@tool(
    name="recon_katana_crawl",
    description=(
        "Deep-crawl a starting URL, discovering linked endpoints and JS "
        "files. v4-preferred over a stdlib BFS. Internally uses the "
        "``katana`` binary (https://github.com/projectdiscovery/katana) "
        "which is a Go-based crawler with headless-browser support, JS "
        "extraction, form filling, and depth control. Falls back to a "
        "simple BFS with HEAD/GET probes when katana is not on PATH. "
        "Use this in F3.5 to expand URL surface and find hidden paths."
    ),
    params={
        "url": {
            "type": "string",
            "description": "Starting URL (e.g. 'https://www.51ifind.com/').",
        },
        "max_depth": {
            "type": "integer",
            "description": "Crawl depth. Default: 3.",
            "default": 3,
        },
        "max_urls": {
            "type": "integer",
            "description": "Hard cap on URLs crawled. Default: 200.",
            "default": 200,
        },
        "timeout_s": {
            "type": "integer",
            "description": "Per-URL timeout. Default: 8.",
            "default": 8,
        },
    },
    required=["url"],
    execution_timeout_seconds=600.0,
)
async def recon_katana_crawl(
    url: str,
    max_depth: int = 3,
    max_urls: int = 200,
    timeout_s: int = 8,
) -> str:
    """Deep-crawl a URL via katana or stdlib BFS."""
    bp = _binaries.detect("katana")
    if not bp.available:
        data = await _stdlib_crawl(url, max_depth, max_urls, float(timeout_s))
        return json.dumps({
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "binary_error": "katana not on PATH",
            **data,
        }, ensure_ascii=False)

    out_path = f"/tmp/katana-{abs(hash(url))}.json"
    argv = [
        bp.path,
        "-u", url,
        "-d", str(max_depth),
        "-jc",  # JS extraction
        "-kf",  # known files (robots/sitemap)
        "-timeout", str(timeout_s),
        "-silent",
        "-jsonl",
        "-o", out_path,
    ]
    try:
        rc, stdout, stderr = await _binaries._run_binary(argv, timeout_s=600.0)
    except (asyncio.TimeoutError, OSError) as exc:
        data = await _stdlib_crawl(url, max_depth, max_urls, float(timeout_s))
        return json.dumps({
            "source": "stdlib",
            "binary_path": bp.path,
            "binary_version": bp.version,
            "binary_error": f"{type(exc).__name__}: {exc}",
            **data,
        }, ensure_ascii=False)

    endpoints: list[dict] = []
    js_files: list[str] = []
    try:
        out_file = Path(out_path)
        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    endpoint = obj.get("endpoint") or obj.get("url")
                    if endpoint:
                        endpoints.append({
                            "url": endpoint,
                            "method": obj.get("method", "GET"),
                            "source": obj.get("source", "katana"),
                            "depth": obj.get("depth", 0),
                        })
                    for js in obj.get("js_files", []) or []:
                        js_files.append(js)
                except json.JSONDecodeError:
                    if line.startswith("http"):
                        endpoints.append({"url": line.strip(), "method": "GET",
                                          "source": "katana", "depth": 0})
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
        "start_url": url,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "js_file_count": len(set(js_files)),
        "js_files": sorted(set(js_files)),
    }, ensure_ascii=False)
