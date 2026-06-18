#!/usr/bin/env python3
"""Strong endpoint verification for asset enumeration.

Problem
-------
HTTP probes that only check status code produce false positives when the
origin is behind an ``openresty`` / ``nginx`` catch-all reverse proxy
that rewrites every upstream error to ``200 OK`` with a fixed
``application/json`` or ``text/javascript`` body (e.g. the stock
``{"status_code":-402,"status_msg":"\\u8bf7\\u6c42\\u9519\\u8bef"}`` envelope used by many
Chinese CDNs / API gateways).

Real example: ``https://openapi.10jqka.com.cn/phpmyadmin`` returns
``200`` ``text/javascript`` ``49 bytes`` for **every** path probed,
including random non-existent paths. The 49-byte JSON is the upstream
error fallback, not a phpMyAdmin login page.

Weak verification (status code only) would have reported this as a
"phpMyAdmin exposed" finding. Strong verification rejects it.

Verification dimensions
-----------------------
A target is considered **truly exposed** only when *at least two* of the
following four checks pass (configurable via ``--min-passes``):

1. ``body_fingerprint`` -- the response body contains component-specific
   string markers (e.g. ``phpMyAdmin``, ``Swagger UI``, ``"openapi"``,
   ``"info":``) AND the body size is in the expected order of magnitude
   (KB+ rather than the few-dozen bytes typical of error envelopes).
2. ``content_type`` -- ``Content-Type`` matches the component's expected
   type (``text/html`` for phpMyAdmin, ``application/json`` for
   OpenAPI specs, ``text/yaml`` for Swagger 3 in YAML, etc.).
3. ``static_resource`` -- a known static asset of the component
   (e.g. ``/phpmyadmin/themes/pmahomme/css/theme.css``,
   ``/swagger-ui-bundle.js``) is reachable and returns the expected
   ``Content-Type`` / non-trivial body.
4. ``negative_control`` -- a random non-existent path under the same
   host returns a **different** response (different status code,
   different body, or both) than the target. If the negative control
   matches the target byte-for-byte, the target is a generic
   catch-all, not a real endpoint.

Built-in fingerprints
---------------------
The module ships with a small library of high-value exposure surfaces
commonly seen during asset discovery:

- ``phpmyadmin`` (MySQL admin)
- ``swagger`` / ``openapi`` (API schema disclosure)
- ``actuator`` (Spring Boot env / heapdump / mappings)
- ``env`` / ``.env`` (dotenv leak)
- ``git`` (``.git/config`` / ``.git/HEAD``)
- ``backup`` (``.sql`` / ``.bak`` / ``.zip`` / ``.tar.gz``)
- ``adminer`` (alternative MySQL admin)
- ``wordpress`` (wp-login.php / wp-config.php)
- ``console`` (Hadoop / WebLogic / Jenkins)

New fingerprints can be added at runtime via ``FINGERPRINTS.register()``
or loaded from a JSON file with ``--fingerprints path.json``.

Usage
-----
    # Verify a single URL against a named fingerprint
    python3 scripts/strong_verify.py verify \\
        --url https://openapi.10jqka.com.cn/phpmyadmin/ \\
        --fingerprint phpmyadmin

    # Batch-verify a list of URLs, auto-detect fingerprint
    python3 scripts/strong_verify.py batch \\
        --input urls.txt --json report.json

    # Library usage
    from scripts.strong_verify import StrongVerifier
    v = StrongVerifier()
    result = v.verify("https://example.com/phpmyadmin/", "phpmyadmin")
    print(result.verdict, result.passes)
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import random
import re
import string
import sys
import urllib.error
import urllib.request
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Fingerprint:
    """Component-specific verification recipe."""

    name: str
    body_markers: tuple = ()
    body_markers_any: tuple = ()
    min_body_bytes: int = 512
    expected_content_types: tuple = ()
    static_paths: tuple = ()
    body_regex: tuple = ()

    def describe(self) -> str:
        return (
            f"Fingerprint(name={self.name!r}, "
            f"markers={len(self.body_markers) + len(self.body_markers_any)}, "
            f"static_paths={len(self.static_paths)})"
        )


@dataclasses.dataclass
class ProbeResult:
    """One HTTP probe outcome."""

    url: str
    status: object  # int | None
    content_type: str
    body: bytes
    body_sha256: str
    error: object = None  # str | None

    @property
    def size(self) -> int:
        return len(self.body)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "size": self.size,
            "body_sha256": self.body_sha256,
            "error": self.error,
        }


@dataclasses.dataclass
class VerifyResult:
    """Aggregated verdict for a single target."""

    url: str
    fingerprint: str
    verdict: str  # exposed | rejected | error
    passes: list
    fails: list
    checks: dict
    probes: list

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "fingerprint": self.fingerprint,
            "verdict": self.verdict,
            "passes": self.passes,
            "fails": self.fails,
            "checks": self.checks,
            "probes": [p.to_dict() for p in self.probes],
        }


# ---------------------------------------------------------------------------
# Fingerprint library
# ---------------------------------------------------------------------------


class FingerprintRegistry:
    """Holds the active set of :class:`Fingerprint` definitions."""

    def __init__(self) -> None:
        self._items: dict = {}
        for fp in _BUILTIN_FINGERPRINTS:
            self.register(fp)

    def register(self, fp: Fingerprint) -> None:
        if fp.name in self._items:
            raise ValueError(f"duplicate fingerprint: {fp.name!r}")
        self._items[fp.name] = fp

    def get(self, name: str) -> Fingerprint:
        if name not in self._items:
            raise KeyError(
                f"unknown fingerprint {name!r}; "
                f"available: {sorted(self._items)}"
            )
        return self._items[name]

    def match_any(self, probe) -> object:  # -> Fingerprint | None
        # Skip fingerprints without any marker configured (e.g. ``generic``)
        # -- they would match every page and provide no signal.
        for fp in self._items.values():
            if not (fp.body_markers or fp.body_markers_any or fp.body_regex):
                continue
            if _body_matches(fp, probe.body):
                return fp
        return None

    def all(self) -> list:
        return list(self._items.values())

    def load_json(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError("fingerprints JSON must be a list")
        loaded = 0
        for entry in data:
            fp = Fingerprint(
                name=entry["name"],
                body_markers=tuple(entry.get("body_markers", ())),
                body_markers_any=tuple(entry.get("body_markers_any", ())),
                min_body_bytes=int(entry.get("min_body_bytes", 512)),
                expected_content_types=tuple(
                    entry.get("expected_content_types", ())
                ),
                static_paths=tuple(entry.get("static_paths", ())),
                body_regex=tuple(entry.get("body_regex", ())),
            )
            self.register(fp)
            loaded += 1
        return loaded


_BUILTIN_FINGERPRINTS: list = [
    Fingerprint(
        name="phpmyadmin",
        body_markers=("phpmyadmin", "pma_username", "pmahomme"),
        min_body_bytes=1024,
        expected_content_types=("text/html",),
        static_paths=(
            "favicon.ico",
            "themes/pmahomme/css/theme.css",
            "js/vendor/jquery/jquery.min.js",
        ),
    ),
    Fingerprint(
        name="adminer",
        body_markers=("adminer", "username"),
        body_markers_any=("adminer", "adminer-"),
        min_body_bytes=1024,
        expected_content_types=("text/html",),
        static_paths=(
            "favicon.ico",
            "static/default.css",
        ),
    ),
    Fingerprint(
        name="swagger",
        body_markers=("swagger", "openapi"),
        body_markers_any=(
            "swagger-ui",
            '"openapi":',
            '"swagger":',
            "swagger: ",
        ),
        min_body_bytes=256,
        expected_content_types=(
            "text/html",
            "application/json",
            "text/javascript",
            "text/yaml",
        ),
        static_paths=(
            "swagger-ui.css",
            "swagger-ui-bundle.js",
            "swagger-ui-standalone-preset.js",
        ),
    ),
    Fingerprint(
        name="openapi",
        body_markers=("openapi",),
        body_markers_any=('"openapi":', '"info":', '"paths":'),
        min_body_bytes=128,
        expected_content_types=(
            "application/json",
            "text/javascript",
            "text/yaml",
            "application/yaml",
        ),
    ),
    Fingerprint(
        name="actuator",
        body_markers=("_links", "self", "health"),
        body_markers_any=(
            '"_links":',
            '"_links" :',
            '{"status":"UP"',
        ),
        min_body_bytes=64,
        expected_content_types=(
            "application/json",
            "application/vnd.spring-boot.actuator",
        ),
    ),
    Fingerprint(
        name="env",
        body_markers=(),
        body_markers_any=(
            "DB_PASSWORD",
            "AWS_SECRET",
            "MYSQL_ROOT_PASSWORD",
            "APP_KEY=",
        ),
        min_body_bytes=64,
        expected_content_types=("text/plain", "application/octet-stream"),
    ),
    Fingerprint(
        name="git",
        body_markers=(),
        body_markers_any=("ref: refs/heads/", "[core]"),
        min_body_bytes=8,
        expected_content_types=("text/plain", "application/octet-stream"),
        static_paths=(
            ".git/HEAD",
            ".git/config",
        ),
    ),
    Fingerprint(
        name="backup",
        body_markers=(),
        body_markers_any=("MYSQL", "CREATE TABLE", "BEGIN;"),
        min_body_bytes=256,
        expected_content_types=(
            "application/zip",
            "application/x-gzip",
            "application/x-tar",
            "application/octet-stream",
            "text/plain",
        ),
    ),
    Fingerprint(
        name="jenkins",
        body_markers=("jenkins", "hudson"),
        body_markers_any=("Jenkins", "JENKINS_HOME"),
        min_body_bytes=1024,
        expected_content_types=("text/html",),
        static_paths=("login", "scriptText"),
    ),
    Fingerprint(
        name="weblogic",
        body_markers=("weblogic",),
        body_markers_any=("WebLogic", "BEA WebLogic"),
        min_body_bytes=512,
        expected_content_types=("text/html", "application/json"),
    ),
    Fingerprint(
        name="hadoop",
        body_markers=("hadoop",),
        body_markers_any=("Hadoop", "NameNode", "DataNode"),
        min_body_bytes=512,
        expected_content_types=("text/html", "application/json"),
    ),
    Fingerprint(
        name="wordpress",
        body_markers=("wordpress", "wp-login"),
        body_markers_any=("wp-login.php", "wp-config.php"),
        min_body_bytes=512,
        expected_content_types=("text/html",),
        static_paths=("wp-login.php", "wp-config.php.bak"),
    ),
    Fingerprint(
        name="generic",
        body_markers=(),
        body_markers_any=(),
        min_body_bytes=64,
        expected_content_types=(),
    ),
]


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------


DEFAULT_UA = "strong_verify/1.0 (+https://opensquilla.local)"
DEFAULT_TIMEOUT = 15


def http_probe(
    url: str,
    *,
    method: str = "GET",
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_UA,
    max_body_bytes: int = 1 * 1024 * 1024,
):
    """Single HTTP probe. Returns a :class:`ProbeResult` even on error.

    Never raises; all exceptions are captured into ``error``.
    Body is truncated to ``max_body_bytes`` to keep memory bounded.
    """
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", user_agent)
        req.add_header("Accept", "*/*")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_body_bytes)
            return ProbeResult(
                url=url,
                status=resp.status,
                content_type=resp.headers.get("Content-Type", ""),
                body=raw,
                body_sha256=hashlib.sha256(raw).hexdigest(),
            )
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(max_body_bytes)
        except Exception:
            raw = b""
        return ProbeResult(
            url=url,
            status=e.code,
            content_type=(e.headers.get("Content-Type", "") if e.headers else ""),
            body=raw,
            body_sha256=hashlib.sha256(raw).hexdigest(),
            error=f"HTTPError: {e.code} {e.reason}",
        )
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return ProbeResult(
            url=url,
            status=None,
            content_type="",
            body=b"",
            body_sha256=hashlib.sha256(b"").hexdigest(),
            error=f"{type(e).__name__}: {e}",
        )


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def _body_matches(fp: Fingerprint, body: bytes) -> bool:
    """Match markers against raw bytes. Decodes once to a tolerant str.
    Returns True if all configured marker groups produce at least one hit.
    """
    body_str = body[: 64 * 1024].decode("utf-8", errors="replace")
    body_lower = body_str.lower()
    if fp.body_markers:
        if not any(m in body_lower for m in fp.body_markers):
            return False
    if fp.body_markers_any:
        if not any(m.lower() in body_lower for m in fp.body_markers_any):
            return False
    if fp.body_regex:
        if not any(re.search(p, body_str, re.IGNORECASE) for p in fp.body_regex):
            return False
    return True


def check_body_fingerprint(fp: Fingerprint, probe: ProbeResult):
    body_str = probe.body[: 64 * 1024].decode("utf-8", errors="replace")
    body_lower = body_str.lower()
    matched_marker = None
    for m in fp.body_markers:
        if m in body_lower:
            matched_marker = m
            break
    if matched_marker is None:
        for m in fp.body_markers_any:
            if m.lower() in body_lower:
                matched_marker = m
                break
    size_ok = probe.size >= fp.min_body_bytes
    passed = matched_marker is not None and size_ok
    return passed, {
        "matched_marker": matched_marker,
        "size": probe.size,
        "min_required": fp.min_body_bytes,
        "size_ok": size_ok,
        "marker_ok": matched_marker is not None,
    }


def check_content_type(fp: Fingerprint, probe: ProbeResult):
    if not fp.expected_content_types:
        return True, {"skipped": True, "reason": "no expected types configured"}
    ct = probe.content_type.lower()
    matched = next(
        (t for t in fp.expected_content_types if t.lower() in ct), None
    )
    return matched is not None, {
        "actual": ct,
        "expected_any_of": list(fp.expected_content_types),
        "matched": matched,
    }


# Static asset types we expect: ico/css/js/png/jpg/jpeg/gif/svg/woff/woff2/ttf
_STATIC_CT_PREFIXES = (
    "image/", "text/css", "application/javascript", "text/javascript",
    "application/x-javascript", "font/", "application/font", "application/octet-stream",
)


def _is_static_response(probe, suffix: str) -> tuple:
    """Strict static-asset check: status 2xx, non-trivial body, content-type
    matches what the suffix implies, and the body is not a tiny error envelope.

    Returns (ok, reason).
    """
    if probe.status is None:
        return False, "no_status"
    if not (200 <= probe.status < 400):
        return False, f"status={probe.status}"
    if probe.size < 256:
        # Real static assets (CSS/JS/ICO) are almost always > 256 bytes.
        return False, f"tiny_body={probe.size}"
    ct = probe.content_type.lower()
    # Reject generic catch-all error envelopes masquerading as 200.
    if ct.startswith("text/javascript") and probe.size < 4096:
        return False, "looks_like_error_envelope"
    # If we know what the file should be, check it.
    s = suffix.lower()
    if s.endswith(".css"):
        if "css" not in ct and "text/plain" not in ct:
            return False, f"ct_mismatch_for_css:{ct}"
    elif s.endswith(".js"):
        if "javascript" not in ct and "text/plain" not in ct and "ecmascript" not in ct:
            return False, f"ct_mismatch_for_js:{ct}"
    elif s.endswith(".ico") or s.endswith(".png") or s.endswith(".jpg") or s.endswith(".gif") or s.endswith(".svg"):
        if not (ct.startswith("image/") or "icon" in ct or "octet-stream" in ct):
            return False, f"ct_mismatch_for_image:{ct}"
    elif s.endswith(".woff") or s.endswith(".woff2") or s.endswith(".ttf"):
        if not (ct.startswith("font/") or "octet-stream" in ct):
            return False, f"ct_mismatch_for_font:{ct}"
    return True, "ok"


def check_static_resources(fp: Fingerprint, base: str, timeout: int):
    """Probe each known static asset. Pass only if at least one returns
    a *real* asset (status 2xx, non-trivial body, content-type that
    matches the file suffix).

    This rejects openresty-style catch-alls that return a fixed 49-byte
    error envelope for every path, including static asset paths.
    """
    if not fp.static_paths:
        return True, {"skipped": True, "reason": "no static_paths configured"}
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(base)
    path = parsed.path
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    findings = []
    for suffix in fp.static_paths:
        target = urlunparse(
            parsed._replace(path=path + suffix.lstrip("/"))
        )
        probe = http_probe(target, timeout=timeout)
        ok, reason = _is_static_response(probe, suffix)
        findings.append({
            "path": suffix, "url": target, **probe.to_dict(),
            "ok": ok, "reason": reason,
        })
    passed = any(f["ok"] for f in findings)
    return passed, {"resources": findings, "any_passed": passed}


def check_negative_control(base: str, target: ProbeResult, timeout: int):
    """Compare target against a random non-existent path under same host.
    If bytes match, target is a generic catch-all, not a real endpoint.
    """
    from urllib.parse import urlparse, urlunparse

    rand = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=16)
    )
    parsed = urlparse(base)
    # Place the control path under the SAME directory as the target.
    # urlparse preserves ``/phpmyadmin/`` so we slice the path to keep
    # the directory prefix, only replacing the last segment.
    target_path = parsed.path
    if not target_path.endswith("/"):
        target_path = target_path.rsplit("/", 1)[0] + "/"
    bogus = urlunparse(parsed._replace(path=f"{target_path}__noexist_{rand}/"))
    control = http_probe(bogus, timeout=timeout)
    same_status = target.status == control.status
    same_size = abs(target.size - control.size) <= 8
    same_hash = target.body_sha256 == control.body_sha256
    identical = same_status and same_size and same_hash
    return not identical, {
        "control_url": bogus,
        "control_status": control.status,
        "control_size": control.size,
        "control_sha256": control.body_sha256,
        "same_status": same_status,
        "same_size": same_size,
        "same_hash": same_hash,
        "identical_to_target": identical,
    }


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class StrongVerifier:
    """High-level entry point."""

    def __init__(
        self,
        registry: object = None,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        min_passes: int = 2,
        run_static_resources: bool = True,
        run_negative_control: bool = True,
    ) -> None:
        self.registry = registry or FingerprintRegistry()
        self.timeout = timeout
        self.min_passes = min_passes
        self.run_static_resources = run_static_resources
        self.run_negative_control = run_negative_control

    def verify(self, url: str, fingerprint_name: str) -> VerifyResult:
        fp = self.registry.get(fingerprint_name)
        target = http_probe(url, timeout=self.timeout)
        probes: list = [target]
        passes: list = []
        fails: list = []
        checks: dict = {}

        if target.error and target.status is None:
            return VerifyResult(
                url=url,
                fingerprint=fingerprint_name,
                verdict="error",
                passes=[],
                fails=["network"],
                checks={"network": {"error": target.error}},
                probes=probes,
            )

        ok, detail = check_body_fingerprint(fp, target)
        checks["body_fingerprint"] = detail
        (passes if ok else fails).append("body_fingerprint")

        ok, detail = check_content_type(fp, target)
        checks["content_type"] = detail
        (passes if ok else fails).append("content_type")

        if self.run_static_resources and fp.static_paths:
            ok, detail = check_static_resources(fp, url, self.timeout)
            checks["static_resource"] = detail
            (passes if ok else fails).append("static_resource")
            for r in detail.get("resources", []):
                probes.append(
                    ProbeResult(
                        url=r["url"],
                        status=r["status"],
                        content_type=r["content_type"],
                        body=b"",
                        body_sha256=r["body_sha256"],
                    )
                )

        if self.run_negative_control:
            ok, detail = check_negative_control(url, target, self.timeout)
            checks["negative_control"] = detail
            (passes if ok else fails).append("negative_control")

        verdict = "exposed" if len(passes) >= self.min_passes else "rejected"
        return VerifyResult(
            url=url,
            fingerprint=fingerprint_name,
            verdict=verdict,
            passes=passes,
            fails=fails,
            checks=checks,
            probes=probes,
        )

    def batch(
        self,
        urls: Iterable,
        *,
        auto_detect: bool = True,
        json_out: str = None,
    ) -> list:
        results: list = []
        for url in urls:
            url = url.strip() if isinstance(url, str) else url
            if not url or url.startswith("#"):
                continue
            probe = http_probe(url, timeout=self.timeout)
            if auto_detect:
                fp = self.registry.match_any(probe)
                if fp is None:
                    results.append(
                        VerifyResult(
                            url=url,
                            fingerprint="<auto:none>",
                            verdict="rejected",
                            passes=[],
                            fails=["no_fingerprint_matched"],
                            checks={
                                "body_fingerprint": {
                                    "size": probe.size,
                                    "marker_ok": False,
                                }
                            },
                            probes=[probe],
                        )
                    )
                    continue
                fingerprint_name = fp.name
            else:
                fingerprint_name = "generic"
            results.append(self.verify(url, fingerprint_name))
        if json_out:
            with open(json_out, "w", encoding="utf-8") as fh:
                json.dump(
                    [r.to_dict() for r in results],
                    fh,
                    ensure_ascii=False,
                    indent=2,
                )
        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_human_result(r: VerifyResult) -> None:
    status = "[OK]   " if r.verdict == "exposed" else "[REJ]  "
    if r.verdict == "error":
        status = "[ERR]  "
    print(f"{status}{r.fingerprint:<14} {r.url}")
    print(f"       passes: {r.passes}")
    print(f"       fails:  {r.fails}")
    nc = r.checks.get("negative_control") or {}
    if nc:
        print(
            f"       ctrl:   status={nc.get('control_status')} "
            f"size={nc.get('control_size')} identical={nc.get('identical_to_target')}"
        )
    bf = r.checks.get("body_fingerprint") or {}
    if bf:
        print(
            f"       body:   size={bf.get('size')} "
            f"marker={bf.get('matched_marker')!r} "
            f"min_required={bf.get('min_required')}"
        )
    ct = r.checks.get("content_type") or {}
    if ct:
        print(
            f"       ctype:  actual={ct.get('actual')!r} "
            f"matched={ct.get('matched')!r}"
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="strong_verify",
        description="Strong endpoint verification (4-dim) for asset enumeration.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_verify = sub.add_parser("verify", help="verify a single URL")
    p_verify.add_argument("--url", required=True)
    p_verify.add_argument("--fingerprint", required=True)
    p_verify.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p_verify.add_argument("--min-passes", type=int, default=2)
    p_verify.add_argument("--no-static", action="store_true")
    p_verify.add_argument("--no-negative", action="store_true")
    p_verify.add_argument("--json", help="write JSON report to this path")

    p_batch = sub.add_parser("batch", help="verify a list of URLs")
    p_batch.add_argument("--input", required=True)
    p_batch.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p_batch.add_argument("--min-passes", type=int, default=2)
    p_batch.add_argument("--json", help="write JSON report to this path")
    p_batch.add_argument(
        "--no-auto-detect", action="store_true"
    )
    p_batch.add_argument(
        "--fingerprints", help="path to JSON file with extra fingerprints"
    )

    p_list = sub.add_parser("list", help="list built-in fingerprints")

    args = parser.parse_args(argv)
    registry = FingerprintRegistry()
    if args.cmd == "list":
        for fp in registry.all():
            print(fp.describe())
        return 0
    if args.cmd == "batch" and getattr(args, "fingerprints", None):
        loaded = registry.load_json(args.fingerprints)
        print(f"# loaded {loaded} extra fingerprints", file=sys.stderr)
    if args.cmd == "verify":
        v = StrongVerifier(
            registry=registry,
            timeout=args.timeout,
            min_passes=args.min_passes,
            run_static_resources=not args.no_static,
            run_negative_control=not args.no_negative,
        )
        result = v.verify(args.url, args.fingerprint)
        _print_human_result(result)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
        return 0 if result.verdict == "exposed" else 1
    if args.cmd == "batch":
        with open(args.input, "r", encoding="utf-8") as fh:
            urls = fh.readlines()
        v = StrongVerifier(
            registry=registry,
            timeout=args.timeout,
            min_passes=args.min_passes,
        )
        results = v.batch(
            urls,
            auto_detect=not args.no_auto_detect,
            json_out=args.json,
        )
        for r in results:
            _print_human_result(r)
        return 0 if any(r.verdict == "exposed" for r in results) else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
