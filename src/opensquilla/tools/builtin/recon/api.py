"""API surface discovery tools (Batch 1, group:recon:api).

Tools:
  - recon_openapi_parse        Fetch + parse OpenAPI/Swagger doc
  - recon_graphql_introspect   Issue GraphQL introspection query
  - recon_js_crawl_recursive   Recursively pull JS bundles, extract API paths
  - recon_api_path_normalize   Cluster + normalize endpoint paths
  - recon_auth_probe           Send probe and report auth gating (401/403)

Pure-stdlib implementation; no GraphQL client, no JS interpreter.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from typing import Any

from opensquilla.tools.registry import tool


# ── helpers ──────────────────────────────────────────


def _http_get(url: str, method: str = "GET", body: bytes | None = None,
              headers: dict[str, str] | None = None, timeout: float = 5.0) -> dict[str, Any]:
    import ssl

    result: dict[str, Any] = {
        "url": url,
        "status_code": None,
        "content_type": None,
        "body": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method=method, data=body)
        req.add_header("User-Agent", "hack-deep-find/2.0 (api)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            result["content_type"] = resp.headers.get("Content-Type")
            raw = resp.read(2 * 1024 * 1024)  # 2 MB cap
            result["body"] = raw.decode("utf-8", errors="replace")
            result["body_truncated"] = len(raw) >= 2 * 1024 * 1024
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        try:
            err_body = e.read()
            result["body"] = err_body.decode("utf-8", errors="replace")[:8192]
        except Exception:
            pass
        result["error"] = f"HTTPError: {e.code}"
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ── 1. recon_openapi_parse ───────────────────────────


_OPENAPI_CANDIDATES: tuple[str, ...] = (
    "/v3/api-docs",
    "/v3/api-docs.yaml",
    "/v2/api-docs",
    "/swagger.json",
    "/openapi.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/v3/api-docs",
)


@tool(
    name="recon_openapi_parse",
    description=(
        "Try a list of common OpenAPI/Swagger endpoints against base_url, parse "
        "the first hit into a normalized schema (info + paths + endpoint_count). "
        "Returns null schema on no hit."
    ),
    params={
        "base_url": {"type": "string"},
        "candidates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Paths to try (each prefixed to base_url). Default: 11 common.",
        },
        "timeout_s": {"type": "number", "default": 5.0},
        "max_size_kb": {
            "type": "integer",
            "default": 1024,
            "description": "Truncate schema larger than this (KB).",
        },
    },
    required=["base_url"],
    execution_timeout_seconds=60.0,
)
async def recon_openapi_parse(
    base_url: str,
    candidates: list[str] | None = None,
    timeout_s: float = 5.0,
    max_size_kb: int = 1024,
) -> str:
    cands = tuple(candidates) if candidates else _OPENAPI_CANDIDATES
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    loop = asyncio.get_running_loop()

    for path in cands:
        url = f"{origin}{path}"
        res = await loop.run_in_executor(None, _http_get, url, "GET", None, None, timeout_s)
        if not res["body"] or res["status_code"] != 200:
            continue
        if "json" not in (res["content_type"] or "").lower() and not res["body"].lstrip().startswith("{"):
            continue
        try:
            doc = json.loads(res["body"])
        except json.JSONDecodeError:
            continue
        # Normalize: OpenAPI 3 / Swagger 2 share a similar structure
        info = doc.get("info", {}) or {}
        paths = doc.get("paths", {}) or {}
        servers = doc.get("servers", []) or []
        components_security = (doc.get("components", {}) or {}).get("securitySchemes", {}) or {}
        security_defs = doc.get("securityDefinitions", {}) or {}
        auth_schemes = sorted(set(list(components_security.keys()) + list(security_defs.keys())))
        endpoints: list[dict[str, Any]] = []
        for p, methods in paths.items():
            for m, _op in (methods or {}).items():
                if m.lower() in {"get", "post", "put", "delete", "patch", "head", "options"}:
                    endpoints.append({"method": m.upper(), "path": p})
        return json.dumps(
            {
                "hit": True,
                "schema_url": url,
                "schema_type": "openapi",
                "schema_version": doc.get("openapi") or doc.get("swagger") or None,
                "title": info.get("title"),
                "version": info.get("version"),
                "auth_schemes": auth_schemes,
                "server_urls": [s.get("url", "") for s in servers if isinstance(s, dict)] or [origin],
                "endpoint_count": len(endpoints),
                "endpoints": endpoints,
                "raw_size": len(res["body"].encode("utf-8")),
                "parse_status": "ok" if len(res["body"].encode("utf-8")) <= max_size_kb * 1024 else "truncated",
            },
            ensure_ascii=False,
        )

    return json.dumps(
        {"hit": False, "schema_url": None, "endpoints": [], "parse_status": "no_hit"},
        ensure_ascii=False,
    )


# ── 2. recon_graphql_introspect ──────────────────────


_GRAPHQL_CANDIDATES: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/gql",
    "/api/gql",
    "/graphql/v1",
    "/v1/graphql",
)


_INTROSPECTION_QUERY = json.dumps(
    {
        "query": (
            "query IntrospectionQuery {"
            "  __schema {"
            "    queryType { name }"
            "    mutationType { name }"
            "    subscriptionType { name }"
            "    types { name kind }"
            "  }"
            "}"
        )
    }
)


@tool(
    name="recon_graphql_introspect",
    description=(
        "Try a list of common GraphQL endpoints and run an introspection "
        "query. Returns SDL/field summary if successful."
    ),
    params={
        "base_url": {"type": "string"},
        "candidates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "GraphQL paths to try. Default: 6 common.",
        },
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=60.0,
)
async def recon_graphql_introspect(
    base_url: str,
    candidates: list[str] | None = None,
    timeout_s: float = 5.0,
) -> str:
    cands = tuple(candidates) if candidates else _GRAPHQL_CANDIDATES
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    loop = asyncio.get_running_loop()
    for path in cands:
        url = f"{origin}{path}"
        body = _INTROSPECTION_QUERY.encode("utf-8")
        res = await loop.run_in_executor(
            None,
            _http_get,
            url,
            "POST",
            body,
            {"Content-Type": "application/json"},
            timeout_s,
        )
        if res["status_code"] != 200 or not res["body"]:
            continue
        try:
            data = json.loads(res["body"])
        except json.JSONDecodeError:
            continue
        if "data" not in data or "__schema" not in (data.get("data") or {}):
            continue
        schema = data["data"]["__schema"]
        query_type = (schema.get("queryType") or {}).get("name", "Query")
        mutation_type = (schema.get("mutationType") or {}).get("name", "Mutation")
        fields: list[dict[str, Any]] = []
        for t in schema.get("types", []) or []:
            if t.get("name") in (query_type, mutation_type):
                fields.append({"type": t.get("name"), "fields": t.get("fields") or []})
        return json.dumps(
            {
                "hit": True,
                "graphql_endpoint": url,
                "query_type": query_type,
                "mutation_type": mutation_type,
                "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
                "field_count": sum(len((f.get("fields") or [])) for f in fields),
                "fields": fields[:10],  # preview first 10 root fields
                "raw_size": len(res["body"].encode("utf-8")),
                "parse_status": "ok",
            },
            ensure_ascii=False,
        )
    return json.dumps(
        {"hit": False, "graphql_endpoint": None, "parse_status": "no_hit"},
        ensure_ascii=False,
    )


# ── 3. recon_js_crawl_recursive ──────────────────────


_JS_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""['"`]([/][\w/.\-{}]*?(?:api|graphql|rest|service|endpoint)[\w/.\-{}]*?)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`]([/][a-z0-9_.\-]{1,80})['"`]\s*[,)]""", re.IGNORECASE),
    re.compile(r"""(https?://[a-z0-9.\-]+(?::\d+)?/api/[a-z0-9_.\-/{}]+)""", re.IGNORECASE),
    re.compile(r"""\bbaseURL\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    re.compile(r"""\bAPI_URL\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
)


@tool(
    name="recon_js_crawl_recursive",
    description=(
        "Fetch entry_js_url, extract all chunk URLs referenced in it (depth up "
        "to `depth`), fetch each, and aggregate regex-extracted API paths. "
        "Returns deduped path list."
    ),
    params={
        "entry_js_url": {"type": "string", "description": "Full URL of the entry JS bundle."},
        "depth": {"type": "integer", "default": 3},
        "timeout_s": {"type": "number", "default": 8.0},
    },
    required=["entry_js_url"],
    execution_timeout_seconds=120.0,
)
async def recon_js_crawl_recursive(
    entry_js_url: str,
    depth: int = 3,
    timeout_s: float = 8.0,
) -> str:
    parsed = urllib.parse.urlparse(entry_js_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    loop = asyncio.get_running_loop()

    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(entry_js_url, 0)]
    paths: set[str] = set()
    chunk_ref_re = re.compile(r"""(?:src|href)\s*=\s*['"`]([^'"`]*?\.js)['"`]""", re.IGNORECASE)
    visited_count = 0

    while queue and visited_count < 64:  # hard cap
        url, lvl = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        visited_count += 1
        res = await loop.run_in_executor(None, _http_get, url, "GET", None, None, timeout_s)
        body = res.get("body") or ""
        for pat in _JS_PATH_PATTERNS:
            for m in pat.findall(body):
                if isinstance(m, tuple):
                    m = m[0]
                if m.startswith("/"):
                    paths.add(m)
        if lvl < depth:
            for ref in chunk_ref_re.findall(body):
                chunk_url = urllib.parse.urljoin(url, ref)
                if chunk_url not in seen and chunk_url.startswith(origin):
                    queue.append((chunk_url, lvl + 1))

    return json.dumps(
        {
            "entry": entry_js_url,
            "chunks_fetched": visited_count,
            "chunks_skipped_dedup": len(seen) - visited_count,
            "max_depth_reached": min(depth, max((lvl for _, lvl in seen and [(0,0)] or []), default=0)),
            "api_paths": sorted(paths)[:256],
            "path_count": len(paths),
        },
        ensure_ascii=False,
    )


# ── 4. recon_api_path_normalize ──────────────────────


@tool(
    name="recon_api_path_normalize",
    description=(
        "Cluster a list of API path strings into templates (e.g. "
        "`/users/123` + `/users/456` → `/users/{id}`). Heuristics: numeric "
        "segments, UUID segments, long hash segments become placeholders."
    ),
    params={
        "endpoints": {
            "type": "array",
            "items": {"type": "object"},
            "description": "List of {method, path} dicts.",
        },
    },
    required=["endpoints"],
)
async def recon_api_path_normalize(endpoints: list[dict[str, Any]]) -> str:
    """Normalize + cluster endpoints. Pure-Python heuristic."""
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
    hash_re = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)

    def _templatize(seg: str) -> str:
        if seg.isdigit():
            return "{id}"
        if uuid_re.match(seg):
            return "{uuid}"
        if hash_re.match(seg):
            return "{hash}"
        if seg in {"true", "false"}:
            return "{bool}"
        return seg

    clusters: "OrderedDict[tuple[str, str], list[dict[str, Any]]]" = OrderedDict()
    for ep in endpoints:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or ""
        parts = [_templatize(p) for p in path.split("/") if p]
        template = "/" + "/".join(parts) if parts else "/"
        key = (method, template)
        clusters.setdefault(key, []).append({**ep, "_template": template})

    normalized = [
        {
            "method": m,
            "path": t,
            "count": len(items),
            "examples": [i.get("path") for i in items[:3]],
        }
        for (m, t), items in clusters.items()
    ]
    return json.dumps(
        {
            "input_count": len(endpoints),
            "cluster_count": len(clusters),
            "endpoints": sorted(normalized, key=lambda r: (-r["count"], r["method"], r["path"])),
        },
        ensure_ascii=False,
    )


# ── 5. recon_auth_probe ──────────────────────────────


@tool(
    name="recon_auth_probe",
    description=(
        "Send an unauthenticated request to a URL and report whether the "
        "endpoint is auth-gated (401/403) vs publicly accessible (200/204)."
    ),
    params={
        "url": {"type": "string"},
        "method": {"type": "string", "enum": ["GET", "POST", "HEAD", "OPTIONS"], "default": "GET"},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["url"],
    execution_timeout_seconds=15.0,
)
async def recon_auth_probe(url: str, method: str = "GET", timeout_s: float = 5.0) -> str:
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, _http_get, url, method, None, None, timeout_s)
    status = res.get("status_code")
    auth_required = status in (401, 403) if status else None
    return json.dumps(
        {
            "url": url,
            "method": method,
            "status_code": status,
            "auth_required": auth_required,
            "publicly_accessible": status in (200, 204, 301, 302, 304) if status else None,
            "error": res.get("error"),
        },
        ensure_ascii=False,
    )
