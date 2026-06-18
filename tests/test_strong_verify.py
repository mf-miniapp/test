"""Unit tests for scripts/strong_verify.py.

These tests do not hit the network. They monkeypatch
``strong_verify.http_probe`` to return synthetic ``ProbeResult`` objects
that simulate:

1. A real phpMyAdmin (large HTML body, correct content-type, distinct
   from a random non-existent path).
2. An openresty catch-all (49-byte JSON, ``text/javascript``, identical
   to a random non-existent path).
3. A Spring Boot actuator (small JSON, ``application/json``).
4. A 404 page (status 404, large HTML).
5. A network error (status=None, error set).
"""

from __future__ import annotations

import dataclasses
import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SV_PATH = _REPO / "scripts" / "strong_verify.py"


def _load_module() -> Any:
    """Load scripts/strong_verify.py as a module.

    The file is intentionally a script (with ``if __name__ == "__main__"``),
    not a package. We load it by path so the test does not depend on a
    package install.
    """
    spec = importlib.util.spec_from_file_location("strong_verify", _SV_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["strong_verify"] = mod
    spec.loader.exec_module(mod)
    return mod


sv = _load_module()


def _probe(
    url: str,
    *,
    status: int | None = 200,
    content_type: str = "text/html; charset=utf-8",
    body: bytes = b"<html></html>",
    error: str | None = None,
) -> sv.ProbeResult:
    import hashlib

    return sv.ProbeResult(
        url=url,
        status=status,
        content_type=content_type,
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        error=error,
    )


@pytest.fixture
def monkey_http_probe(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[sv.ProbeResult]]:
    """Replace ``http_probe`` with a queue-driven mock.

    Each call to the mocked probe pops a ``ProbeResult`` off the queue.
    If the queue is empty, falls back to a generic 200 OK.
    """
    queue: list[sv.ProbeResult] = []

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        if queue:
            p = queue.pop(0)
            # Preserve the url the caller asked for, so the verifier can
            # log it. This mirrors what a real network would do.
            return dataclasses.replace(p, url=url)
        return _probe(url)

    monkeypatch.setattr(sv, "http_probe", fake)
    # StrongVerifier references the module-level http_probe at call time
    # via the module global, so the patch above is sufficient.
    return queue


# ---------------------------------------------------------------------------
# Fingerprint library sanity
# ---------------------------------------------------------------------------


def test_fingerprints_load() -> None:
    reg = sv.FingerprintRegistry()
    names = {fp.name for fp in reg.all()}
    for required in {
        "phpmyadmin",
        "swagger",
        "openapi",
        "actuator",
        "env",
        "git",
        "backup",
        "jenkins",
        "weblogic",
        "hadoop",
        "wordpress",
        "adminer",
    }:
        assert required in names, f"missing fingerprint: {required}"


def test_fingerprint_registry_rejects_duplicates() -> None:
    reg = sv.FingerprintRegistry()
    with pytest.raises(ValueError, match="duplicate fingerprint"):
        reg.register(sv.Fingerprint(name="phpmyadmin"))


def test_fingerprint_registry_rejects_unknown() -> None:
    reg = sv.FingerprintRegistry()
    with pytest.raises(KeyError, match="unknown fingerprint"):
        reg.get("nope")


# ---------------------------------------------------------------------------
# _body_matches and check_body_fingerprint
# ---------------------------------------------------------------------------


def test_body_matches_with_marker() -> None:
    fp = sv.Fingerprint(name="x", body_markers=("phpmyadmin",), min_body_bytes=100)
    body = b"<html>phpMyAdmin welcome</html>" + b"x" * 200
    assert sv._body_matches(fp, body) is True


def test_body_matches_no_marker() -> None:
    fp = sv.Fingerprint(name="x", body_markers=("phpmyadmin",), min_body_bytes=100)
    body = b"<html>hello world</html>" + b"x" * 200
    assert sv._body_matches(fp, body) is False


def test_body_matches_with_any_marker_case_insensitive() -> None:
    fp = sv.Fingerprint(
        name="x", body_markers_any=("PhPMyAdmin",), min_body_bytes=1
    )
    # body is decoded to lowercase before comparison
    assert sv._body_matches(fp, b"phpMyAdmin") is True


def test_check_body_fingerprint_rejects_tiny_error_envelope() -> None:
    fp = sv.Fingerprint(
        name="phpmyadmin",
        body_markers=("phpmyadmin",),
        min_body_bytes=1024,
    )
    # openresty-style tiny error envelope, contains no phpMyAdmin marker
    envelope = b'{"status_code":-402,"status_msg":"err"}'
    p = _probe("https://x/phpmyadmin/", body=envelope)
    ok, detail = sv.check_body_fingerprint(fp, p)
    assert ok is False
    assert detail["size"] == len(envelope)
    assert detail["matched_marker"] is None


def test_check_body_fingerprint_accepts_real_page() -> None:
    fp = sv.Fingerprint(
        name="phpmyadmin",
        body_markers=("phpmyadmin",),
        min_body_bytes=1024,
    )
    real = b"<html><body>Welcome to phpMyAdmin</body></html>" + b"x" * 2048
    p = _probe("https://x/phpmyadmin/", body=real)
    ok, detail = sv.check_body_fingerprint(fp, p)
    assert ok is True
    assert detail["matched_marker"] == "phpmyadmin"
    assert detail["size_ok"] is True


# ---------------------------------------------------------------------------
# check_content_type
# ---------------------------------------------------------------------------


def test_check_content_type_match() -> None:
    fp = sv.Fingerprint(
        name="x", expected_content_types=("text/html", "text/plain")
    )
    p = _probe("https://x/", content_type="text/html; charset=utf-8")
    ok, detail = sv.check_content_type(fp, p)
    assert ok is True
    assert detail["matched"] == "text/html"


def test_check_content_type_mismatch() -> None:
    fp = sv.Fingerprint(name="x", expected_content_types=("text/html",))
    p = _probe("https://x/", content_type="text/javascript;charset=utf-8")
    ok, detail = sv.check_content_type(fp, p)
    assert ok is False
    assert detail["matched"] is None


def test_check_content_type_skipped_when_unset() -> None:
    fp = sv.Fingerprint(name="x")  # no expected_content_types
    p = _probe("https://x/", content_type="anything/at-all")
    ok, detail = sv.check_content_type(fp, p)
    assert ok is True
    assert detail["skipped"] is True


# ---------------------------------------------------------------------------
# check_static_resources (strict version)
# ---------------------------------------------------------------------------


def test_check_static_resources_rejects_catchall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """openresty catch-all returns 49B JS for every static path."""
    fp = sv.Fingerprint(
        name="phpmyadmin",
        static_paths=("favicon.ico", "themes/pmahomme/css/theme.css"),
    )
    real_calls: list[str] = []

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        real_calls.append(url)
        return _probe(
            url,
            status=200,
            content_type="text/javascript;charset=utf-8",
            body=b'{"status_code":-402,"status_msg":"err"}',
        )

    monkeypatch.setattr(sv, "http_probe", fake)
    ok, detail = sv.check_static_resources(
        fp, "https://x/phpmyadmin/", timeout=5
    )
    assert ok is False
    assert detail["any_passed"] is False
    # All sub-resources should be flagged as "looks_like_error_envelope"
    for r in detail["resources"]:
        assert r["ok"] is False
        # Reason may be ``tiny_body=<N>`` (size < 256), ``looks_like_error_envelope``
        # (text/javascript with small body), or ``ct_mismatch_for_*`` (wrong content-type).
        assert r["reason"].startswith(
            ("tiny_body=", "looks_like_error_envelope", "ct_mismatch_for_")
        ), f"unexpected reason: {r['reason']}"


def test_check_static_resources_accepts_real_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fp = sv.Fingerprint(
        name="phpmyadmin",
        static_paths=("favicon.ico", "themes/pmahomme/css/theme.css"),
    )

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        if url.endswith(".ico"):
            return _probe(
                url,
                status=200,
                content_type="image/x-icon",
                body=b"\x00\x01\x02" * 1024,
            )
        if url.endswith(".css"):
            return _probe(
                url,
                status=200,
                content_type="text/css",
                body=b"body { color: red; }" + b" " * 2048,
            )
        return _probe(url, status=404)

    monkeypatch.setattr(sv, "http_probe", fake)
    ok, detail = sv.check_static_resources(
        fp, "https://x/phpmyadmin/", timeout=5
    )
    assert ok is True
    assert detail["any_passed"] is True


# ---------------------------------------------------------------------------
# check_negative_control
# ---------------------------------------------------------------------------


def test_negative_control_identifies_catchall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_body = b'{"status_code":-402,"status_msg":"err"}'
    target = _probe(
        "https://x/phpmyadmin/",
        body=target_body,
        content_type="text/javascript;charset=utf-8",
    )

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        # catch-all: every random path returns the same 49-byte envelope
        if "/phpmyadmin/__noexist_" in url:
            return _probe(
                url,
                status=200,
                content_type="text/javascript;charset=utf-8",
                body=target_body,
            )
        return target

    monkeypatch.setattr(sv, "http_probe", fake)
    ok, detail = sv.check_negative_control(
        "https://x/phpmyadmin/", target, timeout=5
    )
    assert ok is False  # the control matched -> rejected
    assert detail["identical_to_target"] is True


def test_negative_control_passes_for_real_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_body = b"<html>phpMyAdmin login</html>" + b"x" * 2048
    target = _probe(
        "https://x/phpmyadmin/", body=real_body, content_type="text/html"
    )

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        if "/phpmyadmin/__noexist_" in url:
            return _probe(
                url, status=404, content_type="text/html", body=b"Not Found"
            )
        return target

    monkeypatch.setattr(sv, "http_probe", fake)
    ok, detail = sv.check_negative_control(
        "https://x/phpmyadmin/", target, timeout=5
    )
    assert ok is True
    assert detail["identical_to_target"] is False


# ---------------------------------------------------------------------------
# StrongVerifier.verify — end-to-end
# ---------------------------------------------------------------------------


def test_verify_rejects_openresty_catchall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The original 10jqka false positive: must come out rejected."""
    catchall_body = b'{"status_code":-402,"status_msg":"err"}'

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        return _probe(
            url,
            status=200,
            content_type="text/javascript;charset=utf-8",
            body=catchall_body,
        )

    monkeypatch.setattr(sv, "http_probe", fake)
    v = sv.StrongVerifier()
    r = v.verify("https://openapi.10jqka.com.cn/phpmyadmin/", "phpmyadmin")
    assert r.verdict == "rejected"
    assert "body_fingerprint" in r.fails
    assert "content_type" in r.fails
    assert "negative_control" in r.fails


def test_verify_accepts_real_phpmyadmin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_body = (
        b"<html><head><title>phpMyAdmin</title></head>"
        b"<body><form><input name='pma_username'></form></body></html>"
        + b"x" * 3000
    )

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        if url.endswith("/favicon.ico"):
            return _probe(
                url,
                status=200,
                content_type="image/x-icon",
                body=b"\x00" * 4096,
            )
        if url.endswith("theme.css"):
            return _probe(
                url,
                status=200,
                content_type="text/css",
                body=b"body{color:red;}" + b" " * 4096,
            )
        if url.startswith("https://x/phpmyadmin/__noexist_"):
            return _probe(url, status=404, body=b"NF")
        return _probe(url, body=real_body, content_type="text/html; charset=utf-8")

    monkeypatch.setattr(sv, "http_probe", fake)
    v = sv.StrongVerifier()
    r = v.verify("https://x/phpmyadmin/", "phpmyadmin")
    assert r.verdict == "exposed", r.to_dict()
    assert set(r.passes) >= {"body_fingerprint", "content_type", "negative_control"}


def test_verify_reports_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        return _probe(url, status=None, error="URLError: timeout")

    monkeypatch.setattr(sv, "http_probe", fake)
    v = sv.StrongVerifier()
    r = v.verify("https://unreachable.invalid/phpmyadmin/", "phpmyadmin")
    assert r.verdict == "error"
    assert "network" in r.fails


# ---------------------------------------------------------------------------
# Fingerprint auto-detection
# ---------------------------------------------------------------------------


def test_auto_detect_phpmyadmin() -> None:
    body = b"<html>phpMyAdmin login form pma_username</html>" + b"x" * 2000
    p = _probe("https://x/phpmyadmin/", body=body)
    reg = sv.FingerprintRegistry()
    fp = reg.match_any(p)
    assert fp is not None
    assert fp.name == "phpmyadmin"


def test_auto_detect_swagger() -> None:
    body = b'{"openapi":"3.0.0","info":{"title":"X"},"paths":{}}'
    p = _probe("https://x/v3/api-docs", body=body)
    reg = sv.FingerprintRegistry()
    fp = reg.match_any(p)
    assert fp is not None
    # swagger and openapi both match; first one wins
    assert fp.name in {"openapi", "swagger"}


def test_auto_detect_none_for_unknown() -> None:
    # Use a body with no overlap with any built-in fingerprint.
    body = b"<html><body>just a plain hello world page</body></html>" + b" " * 2000
    p = _probe("https://x/", body=body)
    reg = sv.FingerprintRegistry()
    fp = reg.match_any(p)
    assert fp is None


# ---------------------------------------------------------------------------
# Custom fingerprint JSON loading
# ---------------------------------------------------------------------------


def test_load_custom_fingerprints(tmp_path: Path) -> None:
    custom = tmp_path / "fps.json"
    custom.write_text(
        json.dumps(
            [
                {
                    "name": "tomcat-manager",
                    "body_markers": ("tomcat", "manager"),
                    "min_body_bytes": 200,
                    "expected_content_types": ["text/html"],
                    "static_paths": ("html/manager-howto.html",),
                }
            ]
        ),
        encoding="utf-8",
    )
    reg = sv.FingerprintRegistry()
    loaded = reg.load_json(str(custom))
    assert loaded == 1
    fp = reg.get("tomcat-manager")
    assert fp.body_markers == ("tomcat", "manager")
    assert fp.static_paths == ("html/manager-howto.html",)


# ---------------------------------------------------------------------------
# CLI smoke (subprocess)
# ---------------------------------------------------------------------------


def test_cli_list_runs(capsys: pytest.CaptureFixture[str]) -> None:
    from scripts import strong_verify  # type: ignore  # noqa: F401
    # Re-invoke main(["list"]) in-process to keep the test self-contained.
    rc = sv.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "phpmyadmin" in out
    assert "swagger" in out


def test_cli_verify_rejects_catchall(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catchall_body = b'{"status_code":-402,"status_msg":"err"}'

    def fake(url: str, **_kwargs: Any) -> sv.ProbeResult:
        return _probe(
            url,
            status=200,
            content_type="text/javascript;charset=utf-8",
            body=catchall_body,
        )

    monkeypatch.setattr(sv, "http_probe", fake)
    rc = sv.main(
        [
            "verify",
            "--url",
            "https://x.example/phpmyadmin/",
            "--fingerprint",
            "phpmyadmin",
            "--no-static",
            "--no-negative",
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "[REJ]" in out
    assert "phpmyadmin" in out
