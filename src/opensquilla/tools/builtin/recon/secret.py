"""Secret / credential scanning tools (Batch 3, group:recon:secret).

Tools:
  - recon_secret_scan_text       Regex + entropy-based generic scan
  - recon_secret_scan_js_bundle  Fetch + scan a JS bundle URL
  - recon_secret_scan_git_history  Best-effort git history scan (local clone)
  - recon_secret_scan_env_dump   Parse .env / config file format
  - recon_secret_classify        Classify a candidate secret by kind only (v4.5: blast_radius removed — attack-side view belongs to hack-deep W2)
  - recon_secret_validate_aws_key  Probe AWS STS GetCallerIdentity (read-only)

Pure-stdlib; no external scanners.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import re
import subprocess
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


# ── secret patterns (extended set for cross-source scan) ─────


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("slack_token", re.compile(r"xox[abprs]-[0-9a-zA-Z-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("stripe_live_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("password_kv", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"<>\n]{6,})")),
    ("db_connection_string", re.compile(r"(?i)(?:jdbc|mysql|postgresql|mongodb|redis)://[^\s'\"<>]{6,}")),
    ("internal_host", re.compile(r"(?i)(?:https?://)?([a-z0-9][a-z0-9.\-]*(?:\.local|\.internal|\.corp|\.lan|\.intranet)(?::\d+)?(?:/[^\s'\"<>]*)?)")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)


# ── helpers ──────────────────────────────────────────


def _http_get(url: str, timeout: float = 8.0) -> dict[str, Any]:
    import ssl

    result: dict[str, Any] = {"url": url, "status_code": None, "body": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (secret)")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            result["body"] = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        try:
            result["body"] = e.read().decode("utf-8", errors="replace")[:8192]
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ── 1. recon_secret_scan_text ────────────────────────


@tool(
    name="recon_secret_scan_text",
    description=(
        "Generic regex + entropy-based scan over arbitrary text. Returns "
        "all matches with kind, value (truncated to 80 chars), 50-char "
        "context, and shannon entropy."
    ),
    params={
        "text": {"type": "string"},
        "source_hint": {"type": "string", "description": "Where this text came from (js/env/config/git/document)."},
    },
    required=["text"],
)
async def recon_secret_scan_text(text: str, source_hint: str = "document") -> str:
    if not text:
        return json.dumps({"hits": [], "total": 0, "parse_status": "empty"}, ensure_ascii=False)
    hits: list[dict[str, Any]] = []
    for kind, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0) if kind != "password_kv" else m.group(1)
            start = max(0, m.start() - 50)
            end = min(len(text), m.end() + 50)
            ctx = text[start:end].replace("\n", " ").replace("\r", " ")
            ent = _shannon_entropy(value) if len(value) > 8 else 0.0
            hits.append(
                {
                    "kind": kind,
                    "evidence": value[:80] + ("..." if len(value) > 80 else ""),
                    "context": ctx,
                    "source": source_hint,
                    "entropy": round(ent, 2),
                }
            )
    return json.dumps({"hits": hits, "total": len(hits), "parse_status": "ok"}, ensure_ascii=False)


# ── 2. recon_secret_scan_js_bundle ───────────────────


@tool(
    name="recon_secret_scan_js_bundle",
    description=(
        "Fetch a JS bundle URL and run recon_secret_scan_text on the body. "
        "Convenience wrapper for the common 'JS bundle leaks creds' case."
    ),
    params={
        "js_url": {"type": "string"},
        "timeout_s": {"type": "number", "default": 8.0},
    },
    required=["js_url"],
    execution_timeout_seconds=30.0,
)
async def recon_secret_scan_js_bundle(js_url: str, timeout_s: float = 8.0) -> str:
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, _http_get, js_url, timeout_s)
    if not res.get("body"):
        return json.dumps({"hits": [], "total": 0, "error": res.get("error")}, ensure_ascii=False)
    # Reuse scan_text via JSON
    nested = json.loads(
        await recon_secret_scan_text(res["body"], source_hint="js")
    )
    return json.dumps(
        {
            "js_url": js_url,
            "status_code": res.get("status_code"),
            "body_length": len(res["body"]),
            "hits": nested.get("hits", []),
            "total": nested.get("total", 0),
        },
        ensure_ascii=False,
    )


# ── 3. recon_secret_scan_git_history ─────────────────


@tool(
    name="recon_secret_scan_git_history",
    description=(
        "Best-effort git history scan: shallow-clone the repo to a temp dir, "
        "iterate commits, scan each commit's diff against HEAD for secrets. "
        "No network writes; only git clone (read-only)."
    ),
    params={
        "repo_url": {"type": "string"},
        "depth": {"type": "integer", "default": 10},
    },
    required=["repo_url"],
    execution_timeout_seconds=120.0,
)
async def recon_secret_scan_git_history(repo_url: str, depth: int = 10) -> str:
    loop = asyncio.get_running_loop()
    import tempfile

    with tempfile.TemporaryDirectory(prefix="recon-git-") as tmp:
        clone_dir = f"{tmp}/repo"
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["git", "clone", "--depth", str(depth), repo_url, clone_dir],
                    capture_output=True, text=True, timeout=60,
                ),
            )
            if proc.returncode != 0:
                return json.dumps(
                    {"repo_url": repo_url, "error": f"clone failed: {proc.stderr[:200]}"},
                    ensure_ascii=False,
                )
        except Exception as e:  # noqa: BLE001
            return json.dumps({"repo_url": repo_url, "error": f"clone exception: {e}"}, ensure_ascii=False)

        try:
            log_proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["git", "-C", clone_dir, "log", "-p", f"-{depth}", "--all"],
                    capture_output=True, text=True, timeout=30,
                ),
            )
        except Exception as e:  # noqa: BLE001
            return json.dumps({"repo_url": repo_url, "error": f"log failed: {e}"}, ensure_ascii=False)

        body = log_proc.stdout or ""
        nested = json.loads(
            await recon_secret_scan_text(body, source_hint="git")
        )
        return json.dumps(
            {
                "repo_url": repo_url,
                "depth": depth,
                "log_length": len(body),
                "hits": nested.get("hits", []),
                "total": nested.get("total", 0),
            },
            ensure_ascii=False,
        )


# ── 4. recon_secret_scan_env_dump ────────────────────


_ENV_KV_RE = re.compile(r"^\s*([A-Z_][A-Z0-9_]{2,})\s*[:=]\s*(.+?)\s*$", re.MULTILINE)


@tool(
    name="recon_secret_scan_env_dump",
    description=(
        "Parse a .env / application.properties / config.yml style file, "
        "extract all KEY=value pairs, and scan the values for secrets. "
        "Also runs the generic text scan over the whole content."
    ),
    params={
        "text": {"type": "string"},
        "source_hint": {"type": "string", "default": "env"},
    },
    required=["text"],
)
async def recon_secret_scan_env_dump(text: str, source_hint: str = "env") -> str:
    if not text:
        return json.dumps({"kv_pairs": [], "kv_count": 0, "hits": [], "total": 0}, ensure_ascii=False)
    pairs: list[dict[str, str]] = []
    for m in _ENV_KV_RE.finditer(text):
        k, v = m.group(1), m.group(2).strip()
        if len(v) > 4096:
            v = v[:4096] + "..."
        pairs.append({"key": k, "value_preview": v[:80] + ("..." if len(v) > 80 else "")})
    nested = json.loads(
        await recon_secret_scan_text(text, source_hint=source_hint)
    )
    return json.dumps(
        {
            "kv_pairs": pairs,
            "kv_count": len(pairs),
            "hits": nested.get("hits", []),
            "total": nested.get("total", 0),
        },
        ensure_ascii=False,
    )


# ── 5. recon_secret_classify ─────────────────────────
# v4.5 (2026-06-18): blast_radius field removed.
# Rationale: blast_radius is an attack-side metric ("how bad is it if
# exploited?"), and hack-deep-find's contract is "identify secrets, do
# not evaluate exploitability". v4.4/v4 used to emit this field; v4.5
# keeps only `kind` + structural metadata (`evidence_length`,
# `context_preview`). Action recommendations ("rotate_immediately",
# "investigate") also removed for the same reason. Downstream consumers
# (hack-deep W2) compute blast_radius from the kind + context if needed.


@tool(
    name="recon_secret_classify",
    description=(
        "v4.5: Classify a candidate secret by kind only. Returns `kind` "
        "(aws_access_key_id / private_key / jwt / ...) and structural "
        "metadata (evidence_length, context_preview). Does NOT return "
        "blast_radius — that is an attack-side metric and lives in "
        "hack-deep W2."
    ),
    params={
        "evidence": {"type": "string", "description": "The candidate secret value (or first 80 chars)."},
        "context": {"type": "string", "description": "Surrounding 50-char context (optional)."},
    },
    required=["evidence"],
)
async def recon_secret_classify(evidence: str, context: str = "") -> str:
    e = evidence.strip()
    kind = "generic"
    for name, pat in _SECRET_PATTERNS:
        if pat.search(e):
            kind = name
            break
    return json.dumps(
        {
            "kind": kind,
            "evidence_length": len(e),
            "context_preview": (context or "")[:80],
        },
        ensure_ascii=False,
    )


# ── 6. recon_secret_validate_aws_key ─────────────────


@tool(
    name="recon_secret_validate_aws_key",
    description=(
        "Read-only AWS key validation: attempt anonymous STS "
        "GetCallerIdentity. If the key is exposed AND the bucket hosts a "
        "public S3 error document, the response may leak the AWS account ID. "
        "Returns validated=true only when we get a real account/arn. NEVER "
        "uses the key for write operations."
    ),
    params={
        "access_key_id": {"type": "string"},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["access_key_id"],
    execution_timeout_seconds=10.0,
)
async def recon_secret_validate_aws_key(access_key_id: str, timeout_s: float = 5.0) -> str:
    # Pure-stdlib probe: query a public AWS endpoint that requires the key
    # (will return 400/403, NOT a successful auth). This is a NO-OP for
    # the actual key; we do not sign requests.
    url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
    res = _http_get(url, timeout=timeout_s)
    return json.dumps(
        {
            "access_key_id": access_key_id,
            "validated": False,
            "note": "Anonymous probe; we never sign requests. Use hack-deep's vuln-exploit phase to attempt actual auth.",
            "status_code": res.get("status_code"),
            "error": res.get("error"),
        },
        ensure_ascii=False,
    )
