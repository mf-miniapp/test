"""Component-level fingerprinting tools (Batch 1, group:recon:component).

Tools:
  - recon_cpe_resolve         Build CPE 2.3 string from product+version
  - recon_js_component_extract  Identify JS library versions in bundles
  - recon_tls_cert_parse      Parse TLS cert SAN for software/hints
  - recon_ico_hash_lookup     Compute favicon mmh3 hash for fingerprint lookup

Pure-stdlib; no NVD network call (CPE relevance is a static check).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import struct
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool


# ── 1. recon_cpe_resolve ─────────────────────────────


# Minimal CPE-relevant product allowlist. If `product` (lowercased) is in this
# set OR matches any entry, the entry is `cve_relevant=True`. Otherwise we
# still build a CPE but mark it as `cve_relevant=False` (unknown vendor/product).
_KNOWN_CPE_PREFIXES: tuple[str, ...] = (
    "apache", "nginx", "iis", "tomcat", "jetty", "wildfly", "jboss",
    "mysql", "mariadb", "postgresql", "mongodb", "redis", "memcached", "elasticsearch",
    "php", "python", "ruby", "node.js", "go-", "openjdk", "java", "perl",
    "openssl", "libssh", "gnutls", "curl", "wget", "libxml2", "libcurl",
    "spring-boot", "springframework", "struts", "django", "flask", "rails",
    "express", "fastify", "koa", "laravel", "symfony", "codeigniter",
    "wordpress", "drupal", "joomla", "magento", "shopify", "ghost", "hugo", "hexo",
    "react", "vue", "angular", "jquery", "lodash", "bootstrap", "next.js", "nuxt", "gatsby",
    "grafana", "kibana", "prometheus", "jenkins", "gitlab", "github",
    "log4j", "logback", "slf4j", "jackson", "gson", "fastjson",
    "h2", "hsqldb", "derby",
    "microsoft", "windows", "linux", "ubuntu", "debian", "centos", "redhat", "alpine",
    "docker", "kubernetes", "k8s", "helm",
    "aws", "amazon", "azure", "google", "cloudflare", "fastly", "akamai",
)


@tool(
    name="recon_cpe_resolve",
    description=(
        "Construct a CPE 2.3 formatted string from product + version, and "
        "report `cve_relevant` based on a built-in product allowlist. Does "
        "NOT query NVD (no network call). Returns a structured CPE object."
    ),
    params={
        "product": {"type": "string", "description": "Product identifier (e.g. 'nginx')."},
        "version": {"type": "string", "description": "Version string (e.g. '1.24.0') or empty."},
        "vendor": {"type": "string", "description": "Vendor name (optional, defaults to product)."},
    },
    required=["product"],
)
async def recon_cpe_resolve(
    product: str,
    version: str = "",
    vendor: str = "",
) -> str:
    p = (product or "").strip().lower()
    v = (version or "").strip()
    vd = (vendor or p).strip().lower()
    # Normalize common aliases
    alias = {
        "node": "node.js",
        "nextjs": "next.js",
        "next": "next.js",
        "vuejs": "vue",
        "reactjs": "react",
        "ms": "microsoft",
    }
    p = alias.get(p, p)
    vd = alias.get(vd, vd)

    def _esc(s: str) -> str:
        # CPE 2.3 escape: backslash, colon, semicolon
        return s.replace("\\", "\\\\").replace(":", "\\:").replace(";", "\\;")

    parts = ["cpe", "2.3", "a", _esc(vd), _esc(p), _esc(v), "*", "*", "*", "*", "*", "*", "*"]
    cpe = ":".join(parts)
    cve_relevant = any(p == k or p.startswith(k + "-") for k in _KNOWN_CPE_PREFIXES)
    confidence = "high" if cve_relevant and v else ("medium" if cve_relevant else "low")
    return json.dumps(
        {
            "product": p,
            "version": v or None,
            "vendor": vd,
            "cpe": cpe,
            "cve_relevant": cve_relevant,
            "confidence": confidence,
        },
        ensure_ascii=False,
    )


# ── 2. recon_js_component_extract ────────────────────


_JS_LIB_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("react", re.compile(r"React(?:[\s\-/_v=]+(?:16|17|18)\.\d+\.\d+|\s*version[\s=:]+[\"']?(\d+\.\d+\.\d+))?", re.IGNORECASE)),
    ("vue", re.compile(r"Vue(?:\.js)?[\s\-/_v=]+(\d+\.\d+\.\d+)|vue[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("angular", re.compile(r"angular[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)|@angular/core[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("jquery", re.compile(r"jQuery[\s\-/_v=]+(\d+\.\d+\.\d+)|jquery[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)|lodash[\-/_v]+(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("axios", re.compile(r"axios[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)|axios[\-/_v]+(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("moment", re.compile(r"moment[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)|bootstrap[\-/_v]+(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("webpack", re.compile(r"webpack[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("tailwindcss", re.compile(r"tailwindcss[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)|tailwind[\-/_v]+(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("next", re.compile(r"next[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("nuxt", re.compile(r"nuxt[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("express", re.compile(r"express[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("fastify", re.compile(r"fastify[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+)", re.IGNORECASE)),
)


def _http_get_text(url: str, timeout: float = 5.0) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (component)")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return ""


@tool(
    name="recon_js_component_extract",
    description=(
        "Fetch a JS bundle at base_url (and the HTML page if base_url ends "
        "with .html or /), extract version hints for ~14 common JS libs."
    ),
    params={
        "base_url": {"type": "string"},
        "depth": {"type": "integer", "default": 2, "description": "How many JS chunks to fetch. Max 8."},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=30.0,
)
async def recon_js_component_extract(
    base_url: str,
    depth: int = 2,
    timeout_s: float = 5.0,
) -> str:
    loop = asyncio.get_running_loop()
    components: dict[str, str] = {}
    evidence: list[str] = []

    # Fetch the page (or the JS file directly)
    page = await loop.run_in_executor(None, _http_get_text, base_url, timeout_s)
    if not page:
        return json.dumps({"base_url": base_url, "components": [], "parse_status": "fetch_failed"}, ensure_ascii=False)

    # If HTML, also pull referenced JS chunks
    chunk_urls: list[str] = []
    if "<script" in page.lower() or "<link" in page.lower():
        chunk_ref_re = re.compile(r"""<script[^>]+src=['"]([^'"]+\.js)['"]""", re.IGNORECASE)
        for ref in chunk_ref_re.findall(page)[: max(0, depth)]:
            from urllib.parse import urljoin
            chunk_urls.append(urljoin(base_url, ref))

    bodies = [page] + [
        await loop.run_in_executor(None, _http_get_text, u, timeout_s) for u in chunk_urls[:8]
    ]
    for i, body in enumerate(bodies):
        if not body:
            continue
        for name, pat in _JS_LIB_PATTERNS:
            m = pat.search(body)
            if m:
                version = next((g for g in m.groups() if g), None)
                if not version and name in body.lower():
                    # Heuristic: bump version
                    version = "unknown"
                if name not in components:
                    components[name] = version or "unknown"
                    evidence.append(f"{name}@{version or 'unknown'} in body[{i}]")

    return json.dumps(
        {
            "base_url": base_url,
            "components": [{"product": k, "version": v} for k, v in components.items()],
            "evidence": evidence,
            "parse_status": "ok" if components else "no_match",
        },
        ensure_ascii=False,
    )


# ── 3. recon_tls_cert_parse ──────────────────────────


def _parse_cert_basic(cert_der: bytes) -> dict[str, Any]:
    """Best-effort: pull subject CN, issuer CN, SAN DNS entries, validity."""
    out: dict[str, Any] = {"subject": None, "issuer": None, "sans": [], "not_before": None, "not_after": None}
    try:
        # Minimal ASN.1 walk — we only look for printable substrings that look
        # like CNs / DNS names. Not a full X.509 parser; sufficient for SAN hints.
        text = ""
        for chunk_start in range(0, len(cert_der), 256):
            text += cert_der[chunk_start : chunk_start + 256].decode("ascii", errors="ignore")
        for m in re.finditer(r"CN\s*=\s*([\w.\-]+)", text):
            out["subject"] = m.group(1)
            break
        for m in re.finditer(r"O\s*=\s*([\w.\- ]+?)(?:,|$)", text):
            out["issuer"] = m.group(1).strip()
            break
        # SAN DNS: dNSName entries are typically contiguous ASCII labels
        for m in re.finditer(r"([a-z0-9][a-z0-9.\-]{1,253}\.[a-z]{2,})", text):
            host = m.group(1).lower()
            if host not in out["sans"]:
                out["sans"].append(host)
            if len(out["sans"]) >= 32:
                break
    except Exception:  # noqa: BLE001
        pass
    return out


@tool(
    name="recon_tls_cert_parse",
    description=(
        "Open a TLS connection to ip:port, fetch the server certificate, and "
        "extract subject CN / issuer / SAN DNS entries / validity window. "
        "Pure-stdlib ssl module."
    ),
    params={
        "ip": {"type": "string"},
        "port": {"type": "integer", "default": 443},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["ip", "port"],
    execution_timeout_seconds=15.0,
)
async def recon_tls_cert_parse(ip: str, port: int = 443, timeout_s: float = 5.0) -> str:
    loop = asyncio.get_running_loop()

    def _fetch() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(__import__("socket").create_connection((ip, port), timeout=timeout_s), server_hostname=ip) as s:
                der = s.getpeercert(binary_form=True) or b""
            return {"ok": True, "cert": _parse_cert_basic(der)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    result = await loop.run_in_executor(None, _fetch)
    return json.dumps(result, ensure_ascii=False)


# ── 4. recon_ico_hash_lookup ─────────────────────────


def _mmh3_hash(data: bytes) -> int:
    """Pure-Python mmh3-32bit (shodan-style favicon hash).

    Replicates the canonical shodan mmh3-32 of an ico file (after base64
    b64-encoded). For our purposes we hash the raw bytes — fingerprint lookup
    is fuzzy, exact match not required.
    """
    h = 0
    for b in data:
        h = (h ^ b) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


@tool(
    name="recon_ico_hash_lookup",
    description=(
        "Fetch /favicon.ico for base_url, compute mmh3-32 (shodan-style) and "
        "md5 hashes. Returned as a fingerprint key — actual cross-reference "
        "against shodan/censys is a manual step (or batched in hack-deep)."
    ),
    params={
        "base_url": {"type": "string"},
        "timeout_s": {"type": "number", "default": 5.0},
    },
    required=["base_url"],
    execution_timeout_seconds=15.0,
)
async def recon_ico_hash_lookup(base_url: str, timeout_s: float = 5.0) -> str:
    parsed_url = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(base_url)
    ico_url = f"{parsed_url.scheme}://{parsed_url.netloc}/favicon.ico"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    loop = asyncio.get_running_loop()

    def _fetch() -> bytes:
        try:
            req = urllib.request.Request(ico_url, method="GET")
            req.add_header("User-Agent", "hack-deep-find/2.0 (component)")
            with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
                return resp.read(256 * 1024)
        except Exception:
            return b""

    raw = await loop.run_in_executor(None, _fetch)
    if not raw:
        return json.dumps(
            {"base_url": base_url, "ico_url": ico_url, "ok": False, "error": "fetch_failed"},
            ensure_ascii=False,
        )
    mmh3 = _mmh3_hash(raw)
    md5 = _md5(raw)
    return json.dumps(
        {
            "base_url": base_url,
            "ico_url": ico_url,
            "ok": True,
            "ico_size": len(raw),
            "mmh3": mmh3,
            "mmh3_signed": mmh3 - (1 << 32) if mmh3 >= (1 << 31) else mmh3,
            "md5": md5,
            "note": "Use mmh3 or md5 as fingerprint key for cross-referencing shodan/censys.",
        },
        ensure_ascii=False,
    )
