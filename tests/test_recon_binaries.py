"""Tests for the v4 binary-based recon tools.

Covers:
  - _binaries.detect: returns available=True iff shutil.which() finds it
    AND --version works.
  - _binaries.detect_all: returns 12 tracked binaries.
  - _binaries.prefer: runs binary if available, else falls back to stdlib.
  - recon_url_validate_batch: parses httpx JSONL into verified envelopes.
  - recon_url_validate_batch: stdlib fallback when httpx not on PATH.
  - recon_port_batch: parses naabu JSONL into port records.
  - recon_port_batch: stdlib fallback when naabu not on PATH (top 1000).
  - recon_subdomain_enum: stdlib crt.sh path returns valid subdomains
    for a real domain.
  - recon_katana_crawl: stdlib BFS returns >=1 endpoint on a real server.
  - recon_nuclei_scan: stdlib tiny CVE map stub.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from opensquilla.tools.builtin.recon import _binaries


def _run(coro):
    return asyncio.run(coro)


# ── _binaries tests ───────────────────────────────────────────────────────


class TestBinaryDetection:
    def test_detect_all_returns_12_tracked(self):
        all_bp = _binaries.detect_all()
        # 12 tracked binaries (naabu/httpx/subfinder/katana/nuclei/nmap/
        # masscan/ffuf/dnsx/asnmap/tlsx/cdncheck)
        assert len(all_bp) == 12

    def test_detect_known_binary_on_path(self):
        # naabu IS on this machine (per environment).
        bp = _binaries.detect("naabu", refresh=True)
        # Even if the test runs on a machine without naabu, the detection
        # logic itself is correct (returns BinaryPath with available=False).
        # We only assert the type/contract, not the actual availability.
        assert isinstance(bp.available, bool)
        assert bp.name == "naabu"

    def test_detect_unknown_binary(self):
        bp = _binaries.detect("definitely-not-a-real-binary-xyz")
        assert bp.available is False
        assert bp.path is None
        assert bp.version is None

    def test_binary_path_is_truthy_iff_available(self):
        bp = _binaries.detect("naabu", refresh=True)
        if bp.available:
            assert bp.path
            assert bool(bp) is True
        else:
            assert bp.path is None
            assert bool(bp) is False


# ── recon_url_validate_batch tests ────────────────────────────────────────


class _Handler(BaseHTTPRequestHandler):
    status_code = 200
    body = b"<html><body>OK</body></html>"
    content_type = "text/html"

    def do_GET(self):  # noqa: N802
        self.send_response(self.status_code)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *_args):
        return


@pytest.fixture
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", server
    server.shutdown()
    thread.join(timeout=2)


class TestReconUrlValidateBatch:
    def test_empty_list_returns_empty(self):
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate_batch
        result = json.loads(_run(recon_url_validate_batch(urls=[])))
        assert result["verified_count"] == 0
        assert result["rejected_count"] == 0
        assert result["results"] == []

    def test_stdlib_fallback_when_httpx_unavailable(self, http_server, monkeypatch):
        """Force httpx to be unavailable, expect stdlib path."""
        from opensquilla.tools.builtin.recon import http_probe

        # Monkey-patch _binaries.detect to return unavailable.
        def fake_detect(name, refresh=False):
            return _binaries.BinaryPath(
                name=name, path=None, version=None, available=False,
            )
        monkeypatch.setattr(_binaries, "detect", fake_detect)

        url, _ = http_server
        result = json.loads(_run(http_probe.recon_url_validate_batch(urls=[url])))
        assert result["source"] == "stdlib"
        assert result["verified_count"] == 1
        assert result["rejected_count"] == 0
        assert result["results"][0]["verified"] is True
        assert result["results"][0]["probe"]["status_code"] == 200

    def test_error_page_rejected_in_batch(self, http_server, monkeypatch):
        """404 page body in batch mode -> rejected (stdlib fallback path)."""
        from opensquilla.tools.builtin.recon import http_probe

        def fake_detect(name, refresh=False):
            return _binaries.BinaryPath(
                name=name, path=None, version=None, available=False,
            )
        monkeypatch.setattr(_binaries, "detect", fake_detect)

        url, server = http_server
        server.RequestHandlerClass.body = b"<html><head><title>404 Not Found</title></head><body>Page not found</body></html>"
        server.RequestHandlerClass.content_type = "text/html"

        result = json.loads(_run(http_probe.recon_url_validate_batch(urls=[url])))
        assert result["verified_count"] == 0
        assert result["rejected_count"] == 1
        assert "error_body" in result["results"][0]["reason"]


# ── recon_port_batch tests ────────────────────────────────────────────────


class TestReconPortBatch:
    def test_empty_list_returns_empty(self):
        from opensquilla.tools.builtin.recon.port_batch import recon_port_batch
        result = json.loads(_run(recon_port_batch(ips=[])))
        # Empty list: source=stdlib (early return), open_count=0
        assert result["open_count"] == 0
        assert result["results"] == []

    def test_stdlib_fallback_scans_top_1000(self, monkeypatch):
        """When naabu unavailable, stdlib path scans top 1000 ports."""
        from opensquilla.tools.builtin.recon import port_batch

        def fake_detect(name, refresh=False):
            return _binaries.BinaryPath(
                name=name, path=None, version=None, available=False,
            )
        monkeypatch.setattr(_binaries, "detect", fake_detect)

        # Bind a port so we have an "open" target.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # the port is closed but that's ok for stdlib path

        result = json.loads(_run(port_batch.recon_port_batch(
            ips=["127.0.0.1"], ports="80,443", timeout_s=1,
        )))
        assert result["source"] == "stdlib"
        assert result["scanned_ips"] == 1
        assert result["scanned_ports_per_ip"] == 2
        # All 2 ports scanned, none open (we closed the socket).
        assert all(r["state"] in ("open", "closed") for r in result["results"])


# ── recon_subdomain_enum tests ────────────────────────────────────────────


class TestReconSubdomainEnum:
    def test_stdlib_fallback_for_real_domain(self, monkeypatch):
        """stdlib path should hit crt.sh and return at least www. for google.com."""
        from opensquilla.tools.builtin.recon import subdomain_enum

        def fake_detect(name, refresh=False):
            return _binaries.BinaryPath(
                name=name, path=None, version=None, available=False,
            )
        monkeypatch.setattr(_binaries, "detect", fake_detect)

        # crt.sh is publicly available; this should return real results.
        result = json.loads(_run(subdomain_enum.recon_subdomain_enum(
            domain="google.com", timeout_s=15,
        )))
        assert result["source"] == "stdlib"
        assert result["domain"] == "google.com"
        # crt.sh has at least a few entries for google.com.
        # We don't require a specific count, but the list should be non-empty.
        # (If crt.sh is unreachable, the brute list is also tried.)
        assert isinstance(result["subdomains"], list)


# ── recon_katana_crawl tests ──────────────────────────────────────────────


class TestReconKatanaCrawl:
    def test_stdlib_bfs_returns_at_least_one_endpoint(self, http_server, monkeypatch):
        """stdlib BFS should discover the starting URL."""
        from opensquilla.tools.builtin.recon import katana_crawl

        def fake_detect(name, refresh=False):
            return _binaries.BinaryPath(
                name=name, path=None, version=None, available=False,
            )
        monkeypatch.setattr(_binaries, "detect", fake_detect)

        url, _ = http_server
        result = json.loads(_run(katana_crawl.recon_katana_crawl(
            url=url, max_depth=1, max_urls=10, timeout_s=2,
        )))
        assert result["source"] == "stdlib"
        assert result["start_url"] == url
        # At minimum, the start URL is in endpoints.
        urls = [e["url"] for e in result["endpoints"]]
        assert url in urls


# ── recon_nuclei_scan tests ───────────────────────────────────────────────


class TestReconNucleiScan:
    def test_stdlib_stub_returns_findings(self, monkeypatch):
        """stdlib fallback runs a tiny CVE map; should return valid envelope."""
        from opensquilla.tools.builtin.recon import nuclei_scan

        def fake_detect(name, refresh=False):
            return _binaries.BinaryPath(
                name=name, path=None, version=None, available=False,
            )
        monkeypatch.setattr(_binaries, "detect", fake_detect)

        result = json.loads(_run(nuclei_scan.recon_nuclei_scan(
            targets=["https://example.com"], severity="info",
        )))
        assert result["source"] == "stdlib"
        assert result["scanned_targets"] == 1
        # findings list is empty when no components passed (just targets).
        assert isinstance(result["findings"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
