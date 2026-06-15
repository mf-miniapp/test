"""Web application discovery tools (Batch 1, group:recon:webapp).

Tools:
  - recon_vhost_bruteforce  Host-header brute forcing against a base URL
  - recon_robots_sitemap    Parse robots.txt + sitemap.xml for extra URLs
  - recon_tech_detect       Identify server-side / client-side tech stack
  - recon_app_fingerprint   Map a base URL to an application type (CMS/framework)
  - recon_url_dedupe        Normalize + cluster a list of candidate URLs

Pure-stdlib implementation; no external HTTP client, no shell-out.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from html.parser import HTMLParser
from typing import Any
from xml.etree import ElementTree as ET

from opensquilla.tools.registry import tool


# ── helpers ──────────────────────────────────────────


def _http_get(url: str, host: str | None, timeout: float) -> dict[str, Any]:
    """Issue a GET/HEAD with optional Host header override. Pure stdlib."""
    import ssl

    result: dict[str, Any] = {
        "url": url,
        "host_header": host,
        "status_code": None,
        "server": None,
        "title": None,
        "content_type": None,
        "content_length": 0,
        "body_preview": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (webapp)")
        if host:
            req.add_header("Host", host)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            result["server"] = resp.headers.get("Server")
            result["content_type"] = resp.headers.get("Content-Type")
            body = resp.read(64 * 1024)
            result["content_length"] = len(body)
            if body and "text/html" in (result["content_type"] or ""):
                result["title"] = _extract_title(body)
            result["body_preview"] = body[:512].decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def _extract_title(body: bytes) -> str | None:
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return m.group(1).decode("utf-8", errors="replace").strip()[:200]


def _parse_robots(body: str) -> list[str]:
    """Extract Disallow / Allow / Sitemap paths/URLs from robots.txt."""
    paths: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("sitemap:"):
            paths.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith(("disallow:", "allow:")):
            rest = line.split(":", 1)[1].strip()
            if rest and rest != "/":
                paths.append(rest)
    return paths


def _parse_sitemap(body: str) -> list[str]:
    """Extract <loc> entries from a sitemap.xml body."""
    urls: list[str] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return urls
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    for loc in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
        if loc.text:
            urls.append(loc.text.strip())
    return urls


# ── 1. recon_vhost_bruteforce ────────────────────────


_DEFAULT_VHOST_WORDLIST: tuple[str, ...] = (
    "www", "api", "admin", "mail", "cdn", "static", "assets",
    "m", "mobile", "app", "auth", "sso", "login", "internal",
    "staging", "stage", "dev", "test", "qa", "beta", "demo",
    "blog", "shop", "store", "pay", "payment", "billing",
    "docs", "doc", "wiki", "help", "support",
    "vpn", "gateway", "proxy", "lb", "edge",
    "db", "mysql", "redis", "mongo", "es", "elastic",
    "kibana", "grafana", "prometheus", "jenkins", "ci", "cd",
    "git", "gitlab", "github", "bitbucket", "svn",
    "jira", "confluence", "slack",
    "minio", "s3", "oss", "storage", "files", "upload",
    "media", "img", "images", "video", "stream",
    "ws", "websocket", "socket", "realtime", "rt",
    "graphql", "grpc", "rpc",
)


@tool(
    name="recon_vhost_bruteforce",
    description=(
        "Brute-force a list of Host headers against base_url and return "
        "the ones whose response differs from the default (vhost discovery)."
    ),
    params={
        "base_url": {"type": "string", "description": "Base URL (e.g. 'https://1.2.3.4:443')."},
        "wordlist": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Host prefixes to try. Default: ~70 common vhosts.",
        },
        "concurrency": {"type": "integer", "default": 10},
        "timeout_s": {"type": "number", "default": 5.0},
        "diff_threshold": {
            "type": "integer",
            "default": 50,
            "description": "Min response size delta vs baseline to count as a distinct vhost.",
        },
    },
    required=["base_url"],
    execution_timeout_seconds=120.0,
)
async def recon_vhost_bruteforce(
    base_url: str,
    wordlist: list[str] | None = None,
    concurrency: int = 10,
    timeout_s: float = 5.0,
    diff_threshold: int = 50,
) -> str:
    """Identify distinct vhosts behind a single ip:port via Host header brute force."""
    words = tuple(wordlist) if wordlist else _DEFAULT_VHOST_WORDLIST
    parsed = urllib.parse.urlparse(base_url)
    host_base = parsed.netloc.split(":")[0]
    baseline = _http_get(base_url, host=host_base, timeout=timeout_s)
    baseline_len = baseline["content_length"]

    sem = asyncio.Semaphore(concurrency)
    found: list[dict[str, Any]] = []

    async def _probe(prefix: str) -> None:
        host = f"{prefix}.{host_base}"
        async with sem:
            res = await asyncio.get_running_loop().run_in_executor(
                None, _http_get, base_url, host, timeout_s
            )
            res["vhost"] = host
            res["diff_bytes"] = abs(res["content_length"] - baseline_len)
            found.append(res)

    await asyncio.gather(*[_probe(p) for p in words])
    distinct = [r for r in found if r["diff_bytes"] >= diff_threshold and r["status_code"]]
    return json.dumps(
        {
            "baseline": {
                "host": host_base,
                "status_code": baseline["status_code"],
                "content_length": baseline["content_length"],
            },
            "tried": len(words),
            "distinct_vhosts": sorted(distinct, key=lambda r: -r["diff_bytes"]),
        },
        ensure_ascii=False,
    )


# ── 2. recon_robots_sitemap ──────────────────────────


@tool(
    name="recon_robots_sitemap",
    description=(
        "Fetch robots.txt and sitemap.xml for a base URL; return extracted "
        "paths (Disallow/Allow) and URLs (Sitemap, <loc>)."
    ),
    params={
        "base_url": {"type": "string", "description": "Base URL (e.g. 'https://example.com')."},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=30.0,
)
async def recon_robots_sitemap(base_url: str, timeout_s: float = 5.0) -> str:
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    loop = asyncio.get_running_loop()

    def _fetch(url: str) -> str:
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "hack-deep-find/2.0 (webapp)")
            with urllib.request.urlopen(url=url, timeout=timeout_s) as resp:
                return resp.read(64 * 1024).decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            return ""

    robots_body = await loop.run_in_executor(None, _fetch, f"{origin}/robots.txt")
    sitemap_body = await loop.run_in_executor(None, _fetch, f"{origin}/sitemap.xml")

    robots_paths = _parse_robots(robots_body) if robots_body else []
    sitemap_urls = _parse_sitemap(sitemap_body) if sitemap_body else []
    # Also extract Sitemap: directives from robots.txt itself
    extra = _parse_robots(robots_body) if robots_body else []

    return json.dumps(
        {
            "base_url": base_url,
            "robots_present": bool(robots_body),
            "robots_paths": robots_paths,
            "sitemap_present": bool(sitemap_body),
            "sitemap_urls": sitemap_urls,
            "extra_sitemaps_from_robots": [u for u in extra if u.startswith(("http", "/"))],
        },
        ensure_ascii=False,
    )


# ── 3. recon_tech_detect ─────────────────────────────


_TECH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nginx", re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE)),
    ("apache", re.compile(r"apache(?:/([\d.]+))?", re.IGNORECASE)),
    ("iis", re.compile(r"microsoft-iis(?:/([\d.]+))?", re.IGNORECASE)),
    ("cloudflare", re.compile(r"cloudflare", re.IGNORECASE)),
    ("envoy", re.compile(r"envoy(?:/([\d.]+))?", re.IGNORECASE)),
    ("haproxy", re.compile(r"haproxy(?:/([\d.]+))?", re.IGNORECASE)),
    ("caddy", re.compile(r"caddy(?:/([\d.]+))?", re.IGNORECASE)),
    ("traefik", re.compile(r"traefik(?:/([\d.]+))?", re.IGNORECASE)),
    ("express", re.compile(r"x-powered-by:\s*express", re.IGNORECASE)),
    ("php", re.compile(r"x-powered-by:\s*php(?:/([\d.]+))?", re.IGNORECASE)),
    ("asp.net", re.compile(r"x-powered-by:\s*asp\.net", re.IGNORECASE)),
    ("java", re.compile(r"x-powered-by:\s*java(?:(?:/([\d.]+))|.*tomcat)?", re.IGNORECASE)),
    ("tomcat", re.compile(r"tomcat(?:/([\d.]+))?", re.IGNORECASE)),
    ("spring-boot", re.compile(r"spring-boot|spring_boot", re.IGNORECASE)),
    ("next.js", re.compile(r"x-nextjs|next\.js|_next/static", re.IGNORECASE)),
    ("nuxt", re.compile(r"_nuxt/|nuxt", re.IGNORECASE)),
    ("django", re.compile(r"csrfmiddlewaretoken|__django", re.IGNORECASE)),
    ("rails", re.compile(r"x-runtime|x-rails|rails", re.IGNORECASE)),
    ("laravel", re.compile(r"laravel|x-csrf-token", re.IGNORECASE)),
    ("react", re.compile(r"react|__NEXT_DATA__|reactdom", re.IGNORECASE)),
    ("vue", re.compile(r"vue\.(runtime\.)?esm-bundler|vuejs|__vue_app__", re.IGNORECASE)),
    ("jquery", re.compile(r"jquery(?:[/-]([\d.]+))?", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash(?:[/-]([\d.]+))?", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap(?:[/-]([\d.]+))?", re.IGNORECASE)),
    ("wordpress", re.compile(r"wp-content|wp-includes|/wp-json/", re.IGNORECASE)),
    ("drupal", re.compile(r"/sites/default/|drupal", re.IGNORECASE)),
    ("magento", re.compile(r"magento", re.IGNORECASE)),
    ("shopify", re.compile(r"shopify|cdn\.shopify\.com", re.IGNORECASE)),
    ("cloudflare-cdn", re.compile(r"cf-ray:|__cfduid", re.IGNORECASE)),
    ("fastly", re.compile(r"x-served-by:.*cache-ff|fastly", re.IGNORECASE)),
    ("akamai", re.compile(r"akamai|akamaihd", re.IGNORECASE)),
)


@tool(
    name="recon_tech_detect",
    description=(
        "Identify server-side (Server / X-Powered-By) and client-side "
        "(HTML meta / JS bundle) technology stack for a base URL. Returns "
        "a list of `name/version` strings."
    ),
    params={
        "base_url": {"type": "string"},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=15.0,
)
async def recon_tech_detect(base_url: str, timeout_s: float = 5.0) -> str:
    res = _http_get(base_url, host=None, timeout=timeout_s)
    haystack_parts: list[str] = []
    if res["server"]:
        haystack_parts.append(res["server"])
    if res["content_type"] and "text" in res["content_type"]:
        haystack_parts.append(res.get("body_preview") or "")
    haystack = "\n".join(haystack_parts)
    tech: list[str] = []
    seen: set[str] = set()
    for name, pat in _TECH_PATTERNS:
        m = pat.search(haystack)
        if m:
            version = m.group(1) if m.groups() else None
            entry = f"{name}/{version}" if version else name
            if entry not in seen:
                seen.add(entry)
                tech.append(entry)
    return json.dumps(
        {
            "base_url": base_url,
            "status_code": res["status_code"],
            "server_header": res["server"],
            "tech_stack": tech,
        },
        ensure_ascii=False,
    )


# ── 4. recon_app_fingerprint ─────────────────────────


_APP_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("wordpress", re.compile(r"/wp-content/|/wp-includes/|/wp-json/|wp-login\.php", re.IGNORECASE)),
    ("drupal", re.compile(r"/sites/default/|/core/misc/drupal\.js|drupal\.js", re.IGNORECASE)),
    ("joomla", re.compile(r"/media/jui/|com_content|option=com_", re.IGNORECASE)),
    ("magento", re.compile(r"/skin/frontend/|/mage/|magento", re.IGNORECASE)),
    ("shopify", re.compile(r"cdn\.shopify\.com|/cart\.json", re.IGNORECASE)),
    ("ghost", re.compile(r"ghost\.org|/ghost/api/|/ghost/", re.IGNORECASE)),
    ("hexo", re.compile(r"hexo-theme|hexo\.io", re.IGNORECASE)),
    ("hugo", re.compile(r"hugo|hugo-theme", re.IGNORECASE)),
    ("next.js", re.compile(r"__NEXT_DATA__|_next/static", re.IGNORECASE)),
    ("nuxt", re.compile(r"__NUXT__|_nuxt/", re.IGNORECASE)),
    ("gatsby", re.compile(r"gatsby|___gatsby", re.IGNORECASE)),
    ("django", re.compile(r"csrfmiddlewaretoken|__django|admin/jsi18n/", re.IGNORECASE)),
    ("flask", re.compile(r"werkzeug|flask", re.IGNORECASE)),
    ("express", re.compile(r"x-powered-by:.*express", re.IGNORECASE)),
    ("spring-boot", re.compile(r"actuator|spring.application|whitelabel.*error", re.IGNORECASE)),
    ("rails", re.compile(r"x-runtime|csrf-token.*authenticity_token", re.IGNORECASE)),
    ("laravel", re.compile(r"laravel_session|x-csrf-token", re.IGNORECASE)),
    ("tomcat", re.compile(r"tomcat|catalina|jsessionid", re.IGNORECASE)),
    ("nginx-proxy", re.compile(r"server:\s*nginx", re.IGNORECASE)),
    ("apache", re.compile(r"server:\s*apache", re.IGNORECASE)),
    ("iis", re.compile(r"server:\s*iis", re.IGNORECASE)),
    ("cloudfront", re.compile(r"x-amz-cf-id|cloudfront", re.IGNORECASE)),
    ("fastly", re.compile(r"x-served-by:.*cache-ff|fastly", re.IGNORECASE)),
)


@tool(
    name="recon_app_fingerprint",
    description=(
        "Map a base URL to a high-level application type by sniffing "
        "path/content/header signatures. Returns app_type from a fixed "
        "taxonomy: wordpress / drupal / joomla / magento / shopify / "
        "django / flask / express / spring-boot / rails / laravel / "
        "next.js / nuxt / gatsby / ghost / hexo / hugo / tomcat / "
        "nginx-proxy / apache / iis / cloudfront / fastly / unknown."
    ),
    params={"base_url": {"type": "string"}, "timeout_s": {"type": "number", "default": 5.0}},
    required=["base_url"],
    execution_timeout_seconds=15.0,
)
async def recon_app_fingerprint(base_url: str, timeout_s: float = 5.0) -> str:
    res = _http_get(base_url, host=None, timeout=timeout_s)
    headers_str = ""
    if res["server"]:
        headers_str += f"server: {res['server']}\n"
    body = res.get("body_preview") or ""
    haystack = headers_str + body
    for name, pat in _APP_SIGNATURES:
        if pat.search(haystack):
            return json.dumps(
                {
                    "base_url": base_url,
                    "app_type": name,
                    "confidence": "high" if res["status_code"] == 200 else "medium",
                },
                ensure_ascii=False,
            )
    return json.dumps(
        {"base_url": base_url, "app_type": "unknown", "confidence": "low"},
        ensure_ascii=False,
    )


# ── 5. recon_url_dedupe ──────────────────────────────


@tool(
    name="recon_url_dedupe",
    description=(
        "Normalize a list of candidate URLs and cluster by (scheme, host, port, "
        "base_path). Returns deduped list + a cluster summary."
    ),
    params={
        "urls": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Candidate URL strings to normalize + dedupe.",
        },
    },
    required=["urls"],
)
async def recon_url_dedupe(urls: list[str]) -> str:
    """Normalize URLs and cluster by (scheme, host, port, base_path)."""
    clusters: "OrderedDict[tuple[str, str, int, str], list[str]]" = OrderedDict()
    flat: list[dict[str, Any]] = []
    for u in urls:
        try:
            p = urllib.parse.urlparse(u)
        except Exception:
            continue
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower()
        port = p.port or (443 if scheme == "https" else 80)
        # base_path = first 1-2 path segments
        parts = [seg for seg in p.path.split("/") if seg][:2]
        base_path = "/" + "/".join(parts) if parts else ""
        key = (scheme, host, port, base_path)
        clusters.setdefault(key, []).append(u)
        flat.append({"url": u, "scheme": scheme, "host": host, "port": port, "base_path": base_path})

    deduped: list[dict[str, Any]] = []
    for (scheme, host, port, base_path), originals in clusters.items():
        canonical = f"{scheme}://{host}:{port}{base_path}" if (port not in (80, 443) or base_path) else f"{scheme}://{host}{base_path}"
        deduped.append(
            {
                "value": canonical,
                "scheme": scheme,
                "host": host,
                "port": port,
                "base_path": base_path,
                "originals": originals,
                "cluster_size": len(originals),
            }
        )
    return json.dumps(
        {"input_count": len(urls), "cluster_count": len(clusters), "urls": deduped},
        ensure_ascii=False,
    )
