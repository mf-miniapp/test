"""Sensitive static-asset tools (Batch 1, group:recon:sensitive).

Tools:
  - recon_sensitive_fingerprint  Tag a (path, body) pair with sensitivity + signature
  - recon_sensitive_variants      Generate extension/variant paths for a 403/401 hit
  - recon_secret_extract          Regex-scan response body for secret patterns

Pure-stdlib; no external services.
"""

from __future__ import annotations

import json
import re
from typing import Any

from opensquilla.tools.registry import tool


# ── 1. recon_sensitive_fingerprint ───────────────────


_PATH_CATEGORY_MAP: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # (pattern, category, default_sensitivity)
    (re.compile(r"/\.env(\.|$)|\.dockerenv|/Procfile|/application\.(properties|yml|yaml)|/wp-config\.php\.bak|/\.aws/credentials|/secrets\.json|/config/database\.yml|/config/master\.key|/config\.ya?ml|/config\.json", re.IGNORECASE), "config", "critical"),
    (re.compile(r"/backup|\.zip$|\.tar\.gz$|\.sql$|\.bak$|\.old$|\.swp$|~|/index\.html\.bak|/www\.zip|/site\.zip|/dump\.sql", re.IGNORECASE), "backup", "critical"),
    (re.compile(r"/\.git/|/\.svn/|/\.hg/|/\.bzr/|/\.DS_Store|/\.htaccess", re.IGNORECASE), "vcs", "critical"),
    (re.compile(r"/actuator|/debug|/trace|/metrics|/health|/status|/info|/server-info|/heapdump", re.IGNORECASE), "debug", "high"),
    (re.compile(r"/swagger|/api-docs|/openapi\.json|/redoc|/docs|/graphql", re.IGNORECASE), "docs", "medium"),
    (re.compile(r"/admin|/administrator|/manager/html|/phpmyadmin|/jenkins|/grafana|/kibana|/console|/wp-admin|/wp-login|/login|/signin|/auth", re.IGNORECASE), "admin", "high"),
    (re.compile(r"/robots\.txt|/sitemap\.xml|/humans\.txt|/security\.txt|/crossdomain\.xml", re.IGNORECASE), "metadata", "medium"),
)


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("slack_token", re.compile(r"xox[abprs]-[0-9a-zA-Z-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("stripe_live_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("password_kv", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"<>\n]{6,})")),
    ("db_connection_string", re.compile(r"(?i)(?:jdbc|mysql|postgresql|mongodb)://[^\s'\"<>]{6,}")),
)


@tool(
    name="recon_sensitive_fingerprint",
    description=(
        "Classify a (path, response_body) pair: returns category + sensitivity "
        "based on path pattern, plus signature if a secret pattern matches in body."
    ),
    params={
        "path": {"type": "string", "description": "URL path (e.g. '/.env')."},
        "response_body": {"type": "string", "description": "Response body text (or empty for HEAD-only probes)."},
        "content_type": {"type": "string", "description": "Response Content-Type header."},
        "status": {"type": "integer", "description": "HTTP status code observed."},
    },
    required=["path"],
)
async def recon_sensitive_fingerprint(
    path: str,
    response_body: str = "",
    content_type: str = "",
    status: int = 200,
) -> str:
    category = "unknown"
    sensitivity = "info"
    for pat, cat, sens in _PATH_CATEGORY_MAP:
        if pat.search(path):
            category = cat
            # 200 keeps default; 403 still critical for vcs/config/backup; 404 -> ignore
            if status == 404:
                sensitivity = "info"
            else:
                sensitivity = sens
            break

    signature: str | None = None
    if response_body and status == 200:
        for name, pat in _SECRET_PATTERNS:
            if pat.search(response_body):
                signature = name
                if category in {"config", "backup", "vcs"}:
                    sensitivity = "critical"
                break

    return json.dumps(
        {
            "path": path,
            "category": category,
            "sensitivity": sensitivity,
            "signature": signature,
            "status": status,
            "content_type": content_type,
        },
        ensure_ascii=False,
    )


# ── 2. recon_sensitive_variants ──────────────────────


_VARIANT_SUFFIXES: tuple[str, ...] = (
    ".bak", ".old", ".swp", "~", ".orig", ".save", ".dist", ".sample", ".inc", ".txt",
)


@tool(
    name="recon_sensitive_variants",
    description=(
        "Generate up to N variant paths for a 403/401 hit. Variants: suffix, "
        "prefix, and in-place back-up markers."
    ),
    params={
        "path": {"type": "string", "description": "The 403/401 path (e.g. '/.git/HEAD')."},
        "max_variants": {"type": "integer", "default": 5, "description": "Cap variants."},
    },
    required=["path"],
)
async def recon_sensitive_variants(path: str, max_variants: int = 5) -> str:
    variants: list[dict[str, str]] = []
    # 1. Suffix variants
    for s in _VARIANT_SUFFIXES:
        variants.append({"path": f"{path}{s}", "kind": "suffix", "marker": s})
    # 2. In-place back-up
    if "/" in path:
        head, tail = path.rsplit("/", 1)
        for s in (".bak", "~", ".swp"):
            variants.append({"path": f"{head}/{tail}{s}", "kind": "inplace", "marker": s})
    # 3. Path-level prefix variant
    variants.append({"path": f"~{path}", "kind": "prefix", "marker": "~"})

    # Dedup preserving order, then cap
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for v in variants:
        if v["path"] in seen:
            continue
        seen.add(v["path"])
        deduped.append(v)
        if len(deduped) >= max_variants:
            break

    return json.dumps(
        {"path": path, "variant_count": len(deduped), "variants": deduped},
        ensure_ascii=False,
    )


# ── 3. recon_secret_extract ──────────────────────────


@tool(
    name="recon_secret_extract",
    description=(
        "Regex-scan a response body for ~10 common secret patterns "
        "(AWS keys, private keys, JWT, GitHub PATs, Slack tokens, Google API "
        "keys, Stripe live keys, password K/V, DB connection strings). "
        "Returns hits with surrounding context (50 chars)."
    ),
    params={
        "response_body": {"type": "string"},
        "content_type": {"type": "string"},
        "max_hits_per_pattern": {"type": "integer", "default": 3},
    },
    required=["response_body"],
)
async def recon_secret_extract(
    response_body: str,
    content_type: str = "",
    max_hits_per_pattern: int = 3,
) -> str:
    if not response_body:
        return json.dumps(
            {"hits": [], "total": 0, "parse_status": "empty_body"},
            ensure_ascii=False,
        )
    hits: list[dict[str, Any]] = []
    for name, pat in _SECRET_PATTERNS:
        for i, m in enumerate(pat.finditer(response_body)):
            if i >= max_hits_per_pattern:
                break
            start = max(0, m.start() - 50)
            end = min(len(response_body), m.end() + 50)
            ctx = response_body[start:end].replace("\n", " ").replace("\r", " ")
            hits.append(
                {
                    "pattern": name,
                    "match": m.group(0)[:80] + ("..." if len(m.group(0)) > 80 else ""),
                    "context": ctx,
                }
            )
    return json.dumps(
        {"hits": hits, "total": len(hits), "parse_status": "ok"},
        ensure_ascii=False,
    )
