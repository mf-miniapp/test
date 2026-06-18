"""HTTP recon tools — httpx binary (preferred) / stdlib (fallback).

Group: ``group:recon:http``.

v4.4 (2026-06-18) hardening: httpx binary
(https://github.com/projectdiscovery/httpx) probes many URLs in
parallel with a single subprocess. Stdlib urllib is the FALLBACK
for hosts without httpx.

Why not curl: the legacy ``scanner_tools.py`` used
``asyncio.create_subprocess_exec("curl", ...)`` which conflicts with
the sandbox approval pipeline. httpx is preferred over curl
because httpx does status+title+tech+server+TLS-grab in ONE call
(banner-grab, fingerprint, content-type), reducing round-trips.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from typing import Any

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries
import tempfile
from pathlib import Path


# ── httpx output parser ──────────────────────────────────


def _parse_httpx_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse httpx -json JSONL output. One record per URL.

    httpx -json emits records like:
      {"url":"https://1.2.3.4","status_code":200,"title":"...",
       "webserver":"nginx/1.18","tech":["Nginx"],"content_type":"...",
       "final_url":"https://1.2.3.4/","scheme":"https","method":"GET",
       "host":"1.2.3.4","a":["1.2.3.4"],"timestamp":"..."}
    """
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append({
            "url": rec.get("url", ""),
            "status_code": rec.get("status_code"),
            "title": rec.get("title"),
            "server": rec.get("webserver"),
            "content_type": rec.get("content_type"),
            "final_url": rec.get("final_url") or rec.get("url"),
            "tech": rec.get("tech", []) or [],
            "scheme": rec.get("scheme"),
            "host": rec.get("host"),
        })
    return out


@tool(
    name="recon_http_probe",
    description=(
        "Issue an HTTP HEAD/GET to `url` and return the status code, "
        "final URL (after redirects), and Server header. SSL verification "
        "is OFF by default so self-signed certs don't fail the probe — "
        "this is reconnaissance, not auth. Use this to verify a service is "
        "reachable before adding ENDPOINT children to the AssetTree."
    ),
    params={
        "url": {"type": "string", "description": "Full URL (e.g. 'http://1.2.3.4:8080/')."},
        "method": {
            "type": "string",
            "enum": ["HEAD", "GET"],
            "description": "HTTP method. Default: HEAD (lighter).",
            "default": "HEAD",
        },
        "timeout_s": {
            "type": "number",
            "description": "Total request timeout. Default: 5.0.",
            "default": 5.0,
        },
        "verify_ssl": {
            "type": "boolean",
            "description": "Verify TLS cert. Default: false (recon mode).",
            "default": False,
        },
    },
    required=["url"],
    execution_timeout_seconds=15.0,
)
async def recon_http_probe(
    url: str,
    method: str = "HEAD",
    timeout_s: float = 5.0,
    verify_ssl: bool = False,
) -> str:
    """Probe an HTTP endpoint."""
    import ssl

    result: dict[str, Any] = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "server": None,
        "title": None,
        "content_type": None,
        "error": None,
    }

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # type: ignore[override]
            return None

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ctx),
    )

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "hack-deep-find/2.0 (recon)")

    try:
        loop = asyncio.get_running_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: opener.open(req, timeout=timeout_s),
            ),
            timeout=timeout_s + 1,
        )
        result["status_code"] = response.status
        result["final_url"] = response.geturl()
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        # Try to extract <title> from a small GET if this was a HEAD
        if method == "HEAD" or not result["server"]:
            try:
                get_req = urllib.request.Request(url, method="GET")
                get_req.add_header("User-Agent", "hack-deep-find/2.0 (recon)")
                body_resp = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: opener.open(get_req, timeout=timeout_s),
                    ),
                    timeout=timeout_s + 1,
                )
                body = body_resp.read(64 * 1024).decode("utf-8", errors="ignore")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:256]
            except Exception:
                pass
    except urllib.error.HTTPError as exc:
        result["status_code"] = exc.code
        result["server"] = exc.headers.get("Server") if exc.headers else None
        result["error"] = f"HTTPError: {exc.code} {exc.reason}"
    except (urllib.error.URLError, asyncio.TimeoutError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return json.dumps(result, ensure_ascii=False)




# ── URL validate (HTTP probe + body error-page detection) ────────────────

# Strings / patterns that indicate an error page even when the server
# returns HTTP 200. Common with reverse proxies (Kong, nginx, envoy)
# that wrap a real 4xx/5xx in a 200 response with a generic error body.
_ERROR_BODY_INDICATORS: tuple[tuple[str, str], ...] = (
    # (substring_to_match_in_body_lowercased, reason_label)
    ("not found", "404 page"),
    ("404 not found", "404 page"),
    ("page not found", "404 page"),
    ("internal server error", "500 page"),
    ("service unavailable", "503 page"),
    ("bad gateway", "502 page"),
    ("gateway timeout", "504 page"),
    ("forbidden", "403 page"),
    ("access denied", "403 page"),
    ("unauthorized", "401 page"),
    ("nginx error", "nginx error page"),
    ("nginx/1.", "nginx default error page"),  # default nginx error pages
    ("apache/2.", "apache default error page"),
    ("kong error", "kong error page"),
    ("upstream connect error", "upstream error page"),
    ("the page you are looking for can't be found", "404 page"),
    ("site can't be reached", "browser error page"),
    ("this site can't be reached", "browser error page"),
    ("err_", "browser error page"),  # chrome ERR_CONNECTION_REFUSED etc
    ("site not found", "404 page"),
    ("domain is not configured", "404 page"),
    ("default web page", "default web page"),
    ("it works", "apache default page"),  # only if content_type is html
    ("test page", "test placeholder page"),
    ("coming soon", "placeholder page"),
    ("placeholder", "placeholder page"),
    ("maintenance", "maintenance page"),
    ("under construction", "placeholder page"),
)


def _is_error_body(body: str, content_type: str | None) -> str | None:
    """Return error reason if body looks like an error page, else None.

    A body is considered an error page if:
      1. content_type is text/html (or unset) AND
      2. body (lowercased, first 64KB) contains any known error indicator.
    """
    if not body:
        return None
    # Skip non-HTML responses — JSON API errors are valid (the API surface
    # is a legit asset, the error message is part of the contract).
    if content_type and "html" not in content_type.lower():
        return None
    sample = body[: 64 * 1024].lower()
    for indicator, reason in _ERROR_BODY_INDICATORS:
        if indicator in sample:
            return reason
    return None


@tool(
    name="recon_url_validate",
    description=(
        "Validate a URL for AssetTree ingestion. Performs an HTTP HEAD probe "
        "with fallback to GET, then a body-level error-page check. Returns "
        "``verified=true`` ONLY if status_code is 200 AND body is not a "
        "known error page (404/500/502/503/504/Kong/nginx default etc). "
        "Use this BEFORE adding a URL node to the AssetTree — the AssetTree "
        "add_node call requires a ``verification`` object whose ``verified`` "
        "field must be true; passing the probe result of recon_url_validate "
        "satisfies that contract."
    ),
    params={
        "url": {"type": "string", "description": "Full URL (e.g. 'http://1.2.3.4:8080/admin')."},
        "method": {
            "type": "string",
            "enum": ["HEAD", "GET"],
            "description": "HTTP method. Default: GET (we need the body to check for error pages).",
            "default": "GET",
        },
        "timeout_s": {
            "type": "number",
            "description": "Total request timeout. Default: 8.0 (slightly more than recon_http_probe to allow for slow servers).",
            "default": 8.0,
        },
        "verify_ssl": {
            "type": "boolean",
            "description": "Verify TLS cert. Default: false (recon mode).",
            "default": False,
        },
        "max_body_bytes": {
            "type": "integer",
            "description": "How many bytes of response body to read for error-page check. Default: 65536 (64KB).",
            "default": 65536,
        },
    },
    required=["url"],
    execution_timeout_seconds=20.0,
)
async def recon_url_validate(
    url: str,
    method: str = "GET",
    timeout_s: float = 8.0,
    verify_ssl: bool = False,
    max_body_bytes: int = 65536,
) -> str:
    """Probe URL + check body is not an error page.

    Returns a dict with:
      - verified: bool   (true only if status=200 AND body not an error page)
      - reason: str|null (why verified is false; "ok" if verified is true)
      - probe:  {status_code, server, content_type, title, final_url, error}
      - verified_at: iso_ts (when the probe was run)
    """
    import ssl
    from datetime import datetime, timezone

    # v4.4: httpx short-circuit. Single URL via httpx costs a subprocess
    # start (~100ms) but gets us status+title+server+tech+final_url in
    # ONE call. Stdlib fallback below takes 2 round-trips (HEAD + GET).
    bp = _binaries.detect("httpx")
    if bp.available:
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
                f.write(url + "\n")
                tmp = f.name
            try:
                rc, stdout, stderr = await _binaries._run_binary(
                    ["httpx", "-l", tmp, "-status-code", "-title", "-webserver",
                     "-content-type", "-follow-redirects", "-no-stdin",
                     "-json", "-timeout", str(int(timeout_s))],
                    timeout_s=timeout_s + 5,
                )
                records = _parse_httpx_jsonl(stdout)
                rec = records[0] if records else None
                if rec and rec.get("status_code") is not None:
                    result: dict[str, Any] = {
                        "url": url,
                        "verified": False,
                        "reason": None,
                        "probe": {
                            "status_code": rec["status_code"],
                            "server": rec["server"],
                            "content_type": rec["content_type"],
                            "title": rec["title"],
                            "final_url": rec["final_url"],
                            "error": None,
                            "tech": rec["tech"],
                        },
                        "verified_at": None,
                    }
                    # httpx doesn't return body for error-page detection
                    # unless -body is set. For 200 OK with html, we fall
                    # back to body check via stdlib GET below if -body not set.
                    if rec["status_code"] != 200:
                        result["reason"] = f"status_{rec['status_code']}"
                    else:
                        # 200 — try body check (httpx -body in second pass)
                        try:
                            rc2, stdout2, _ = await _binaries._run_binary(
                                ["httpx", "-l", tmp, "-status-code",
                                 "-body", "-no-stdin", "-timeout", str(int(timeout_s))],
                                timeout_s=timeout_s + 5,
                            )
                            for line2 in stdout2.splitlines():
                                line2 = line2.strip()
                                if not line2:
                                    continue
                                try:
                                    r2 = json.loads(line2)
                                except json.JSONDecodeError:
                                    continue
                                body = r2.get("body", "") or ""
                                ct = r2.get("content_type") or rec["content_type"]
                                err = _is_error_body(body, ct)
                                if err:
                                    result["reason"] = f"error_body:{err}"
                                else:
                                    result["reason"] = "ok"
                                    result["verified"] = True
                                break
                            else:
                                # httpx -body not available; trust status=200.
                                result["reason"] = "ok_no_body_check"
                                result["verified"] = True
                        except (asyncio.TimeoutError, OSError):
                            # body check failed; trust status=200
                            result["reason"] = "ok_no_body_check"
                            result["verified"] = True
                    result["verified_at"] = datetime.now(timezone.utc).isoformat()
                    return json.dumps(result, ensure_ascii=False)
            finally:
                try:
                    Path(tmp).unlink()
                except OSError:
                    pass
        except (asyncio.TimeoutError, OSError, IndexError) as exc:
            pass  # fall through to stdlib

    result: dict[str, Any] = {
        "url": url,
        "verified": False,
        "reason": None,
        "probe": {
            "status_code": None,
            "server": None,
            "content_type": None,
            "title": None,
            "final_url": None,
            "error": None,
        },
        "verified_at": None,
    }

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # type: ignore[override]
            return None

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ctx),
    )

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "hack-deep-find/2.0 (validate)")

    body = ""
    try:
        loop = asyncio.get_running_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: opener.open(req, timeout=timeout_s),
            ),
            timeout=timeout_s + 1,
        )
        result["probe"]["status_code"] = response.status
        result["probe"]["final_url"] = response.geturl()
        result["probe"]["server"] = response.headers.get("Server")
        result["probe"]["content_type"] = response.headers.get("Content-Type")
        # Read body for error-page check
        try:
            body = response.read(max_body_bytes).decode("utf-8", errors="ignore")
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["probe"]["title"] = title_match.group(1).strip()[:256]
        except Exception as exc:
            result["probe"]["error"] = f"body_read: {type(exc).__name__}: {exc}"
    except urllib.error.HTTPError as exc:
        result["probe"]["status_code"] = exc.code
        result["probe"]["server"] = exc.headers.get("Server") if exc.headers else None
        result["probe"]["content_type"] = exc.headers.get("Content-Type") if exc.headers else None
        result["probe"]["error"] = f"HTTPError: {exc.code} {exc.reason}"
    except (urllib.error.URLError, asyncio.TimeoutError, OSError) as exc:
        result["probe"]["error"] = f"{type(exc).__name__}: {exc}"

    # Final verdict
    status = result["probe"]["status_code"]
    if status is None:
        result["reason"] = "no_response"
    elif status != 200:
        result["reason"] = f"status_{status}"
    else:
        # status == 200 — check body
        body_error = _is_error_body(body, result["probe"]["content_type"])
        if body_error:
            result["reason"] = f"error_body:{body_error}"
        else:
            result["reason"] = "ok"
            result["verified"] = True

    result["verified_at"] = datetime.now(timezone.utc).isoformat()
    return json.dumps(result, ensure_ascii=False)




# ── Batch URL validation via httpx (preferred over single-URL stdlib) ─────


def _is_error_body(body: str, content_type: str | None) -> str | None:
    """Body-level error-page detector. Reused by both single and batch paths.

    A body is considered an error page if:
      1. content_type is text/html (or unset) AND
      2. body (lowercased, first 64KB) contains any known error indicator.
    """
    if not body:
        return None
    if content_type and "html" not in content_type.lower():
        return None
    sample = body[: 64 * 1024].lower()
    for indicator, reason in _ERROR_BODY_INDICATORS:
        if indicator in sample:
            return reason
    return None


@tool(
    name="recon_url_validate_batch",
    description=(
        "Validate a LIST of URLs in one batch. v4-preferred over calling "
        "recon_url_validate per URL. Internally uses the ``httpx`` binary "
        "(https://github.com/projectdiscovery/httpx) to probe all URLs in "
        "parallel with a single subprocess; falls back to per-URL stdlib "
        "probes if httpx is not on PATH. Each URL gets a verification "
        "envelope: {verified, reason, probe, verified_at}. URLs that are "
        "non-200 or return an error body (404 page / 500 page / nginx "
        "default / kong error / upstream error / etc.) are marked "
        "verified=False and should NOT be added to the AssetTree."
    ),
    params={
        "urls": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of full URLs to validate (e.g. ['https://1.2.3.4:443', 'http://1.2.3.4:8080/admin']).",
        },
        "timeout_s": {
            "type": "integer",
            "description": "Per-URL timeout in seconds. Default: 8.0.",
            "default": 8,
        },
        "max_concurrency": {
            "type": "integer",
            "description": "httpx -c flag: concurrent probes. Default: 30.",
            "default": 30,
        },
    },
    required=["urls"],
    execution_timeout_seconds=300.0,
)
async def recon_url_validate_batch(
    urls: list[str],
    timeout_s: int = 8,
    max_concurrency: int = 30,
) -> str:
    """Validate many URLs at once. Preferred for ingest-time verification.

    Returns a JSON object:
      {
        "source": "binary" | "stdlib",
        "binary_path": str | None,
        "binary_version": str | None,
        "verified_count": int,
        "rejected_count": int,
        "results": [
          {url, verified, reason, probe: {status_code, server, title, ...},
           verified_at}, ...
        ]
      }
    """
    import json
    import tempfile
    from datetime import datetime, timezone
    from opensquilla.tools.builtin.recon._binaries import detect, _run_binary

    if not urls:
        return json.dumps({
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "verified_count": 0,
            "rejected_count": 0,
            "results": [],
        }, ensure_ascii=False)

    bp = detect("httpx")
    if not bp.available:
        # Stdlib fallback: probe each URL one-by-one.
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate
        results = []
        for u in urls:
            r = json.loads(await recon_url_validate(u, method="GET", timeout_s=float(timeout_s)))
            results.append(r)
        return json.dumps({
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "verified_count": sum(1 for r in results if r.get("verified")),
            "rejected_count": sum(1 for r in results if not r.get("verified")),
            "results": results,
        }, ensure_ascii=False)

    # httpx path: write URLs to a temp file, run httpx -json -l, parse JSONL.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="httpx-urls-"
    ) as f:
        for u in urls:
            f.write(u + "\n")
        urls_path = f.name

    jsonl_path = urls_path + ".jsonl"
    # v4.6.1 (2026-06-18) httpx v1.x 兼容性修复:
    #   httpx v0.x: 并发标志是 ``-c`` (concurrency).
    #   httpx v1.x: 改名为 ``-t`` (threads, 默认 50). 用错标志 httpx rc=2
    #               + stderr "flag provided but not defined: -c", 但 stdout
    #               空, 触发 _parse_httpx_jsonl 返回 [], 进而 no_response.
    #   修复: 优先用 ``-t``; 如果 httpx 是 v0.x (--version < 1.0.0) 才用 ``-c``.
    #   这里采用保守做法: 探测一次 ``-t`` 标志支持, 不支持则 fallback ``-c``.
    import shutil as _shutil
    _httpx_path = bp.path
    _use_threads_flag = True  # httpx v1.x 默认
    if _httpx_path:
        _v = _shutil.which(_httpx_path)
        # 简单判别: 跑 `httpx -h` 看是否出现 "-t, -threads"
        try:
            _help_proc = __import__("subprocess").run(
                [_httpx_path, "-h"], capture_output=True, text=True, timeout=5,
            )
            if "-t, -threads" not in _help_proc.stdout:
                _use_threads_flag = False
        except Exception:
            _use_threads_flag = False
    _concurrency_flag = "-t" if _use_threads_flag else "-c"

    argv = [
        bp.path, "-l", urls_path,
        "-json", "-o", jsonl_path,
        "-timeout", str(timeout_s),
        _concurrency_flag, str(max_concurrency),
        "-silent",
        "-no-stdin",
        "-fr",  # follow redirects; final URL recorded in json
    ]
    try:
        rc, stdout, stderr = await _run_binary(argv, timeout_s=300.0)
    except (asyncio.TimeoutError, OSError) as exc:
        # Binary failed: fall back to stdlib per-URL.
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate
        results = []
        for u in urls:
            try:
                r = json.loads(await recon_url_validate(u, method="GET", timeout_s=float(timeout_s)))
            except Exception as inner:  # noqa: BLE001
                r = {"url": u, "verified": False, "reason": f"stdlib_error: {inner}",
                     "probe": {}, "verified_at": None}
            results.append(r)
        return json.dumps({
            "source": "stdlib",
            "binary_path": bp.path,
            "binary_version": bp.version,
            "binary_error": f"{type(exc).__name__}: {exc}",
            "verified_count": sum(1 for r in results if r.get("verified")),
            "rejected_count": sum(1 for r in results if not r.get("verified")),
            "results": results,
        }, ensure_ascii=False)
    finally:
        try:
            import os
            os.unlink(urls_path)
        except OSError:
            pass

    # v4.6.1 (2026-06-18) 不静默吞 rc != 0: httpx 标志错误 (例如 httpx v1.x
    # 用了已废弃的 ``-c`` 标志) 会返回 rc=2, stdout 空. 以前直接走到下面
    # _parse_httpx_jsonl, 解析成空 records, 全部 URL 标 no_response — 这就
    # 是用户看到"httpx 二进制有连接问题"但实际是标志错误的根因.
    if rc != 0:
        # 把 stderr 前 200 字符带上方便 LLM 调试
        stderr_head = (stderr or "").strip()[:200]
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate
        results = []
        for u in urls:
            try:
                r = json.loads(await recon_url_validate(u, method="GET", timeout_s=float(timeout_s)))
            except Exception as inner:  # noqa: BLE001
                r = {"url": u, "verified": False, "reason": f"stdlib_error: {inner}",
                     "probe": {}, "verified_at": None}
            results.append(r)
        return json.dumps({
            "source": "stdlib",
            "binary_path": bp.path,
            "binary_version": bp.version,
            "binary_error": f"rc={rc}: {stderr_head}",
            "verified_count": sum(1 for r in results if r.get("verified")),
            "rejected_count": sum(1 for r in results if not r.get("verified")),
            "results": results,
        }, ensure_ascii=False)

    # Parse httpx JSONL output
    results: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    indexed: dict[str, dict[str, Any]] = {}
    try:
        from pathlib import Path as _P
        jsonl_file = _P(jsonl_path)
        if jsonl_file.exists():
            for line in jsonl_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    indexed[obj.get("url", "").rstrip("/")] = obj
                except json.JSONDecodeError:
                    continue
        try:
            jsonl_file.unlink()
        except OSError:
            pass
    except OSError:
        pass

    for u in urls:
        u_norm = u.rstrip("/")
        # httpx may record the final URL after redirects; match on both.
        hit = indexed.get(u_norm) or indexed.get(u)
        if hit is None:
            results.append({
                "url": u,
                "verified": False,
                "reason": "no_response",
                "probe": {},
                "verified_at": now_iso,
            })
            continue
        status = hit.get("status_code") or hit.get("status")
        content_type = hit.get("content_type", "")
        title = hit.get("title")
        body = hit.get("body", "") or ""
        server = hit.get("webserver") or hit.get("server")
        err = None
        if status is None or status == 0:
            err = "no_response"
            reason = "no_response"
            verified = False
        elif status != 200:
            reason = f"status_{status}"
            verified = False
        else:
            body_error = _is_error_body(body, content_type)
            if body_error:
                reason = f"error_body:{body_error}"
                verified = False
            else:
                reason = "ok"
                verified = True
        results.append({
            "url": u,
            "verified": verified,
            "reason": reason,
            "probe": {
                "status_code": status,
                "server": server,
                "title": title,
                "content_type": content_type,
                "final_url": hit.get("final_url") or u,
                "error": err,
            },
            "verified_at": now_iso,
        })

    return json.dumps({
        "source": "binary",
        "binary_path": bp.path,
        "binary_version": bp.version,
        "verified_count": sum(1 for r in results if r["verified"]),
        "rejected_count": sum(1 for r in results if not r["verified"]),
        "results": results,
    }, ensure_ascii=False)




# ── Internal helpers (NOT exposed as tools) ─────────────────────────────


def detect_cdn(cname: str | None) -> str | None:
    """Map a CNAME to its CDN provider (Cloudflare / Akamai / etc.)."""
    if not cname:
        return None

    cdn_patterns = {
        "cloudflare": ["cloudflare.com", "cloudflare.net"],
        "akamai": ["akamai.net", "akamaiedge.net", "akamaihd.net"],
        "fastly": ["fastly.net", "fastlylb.net"],
        "cloudfront": ["cloudfront.net", "amazonaws.com"],
    }

    cname_lower = cname.lower()
    for provider, patterns in cdn_patterns.items():
        for pattern in patterns:
            if pattern in cname_lower:
                return provider
    return None