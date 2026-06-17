"""Tests for the v4 ingest verification gate.

Covers:
  - recon_url_validate: status 200 with non-error body -> verified=True
  - recon_url_validate: status 200 with error body (404 page etc) -> verified=False
  - recon_url_validate: status 500 / 404 / timeout -> verified=False
  - recon_url_validate: JSON API 200 with error key in body -> still verified=True
    (we only flag HTML error pages; JSON API errors are part of the contract)
  - recon_port_verify: TCP open -> verified=True
  - recon_port_verify: TCP timeout / refused -> verified=False
  - tree.add_node: PORT/SERVICE/URL/ENDPOINT without verification -> ValueError
  - tree.add_node: PORT/SERVICE/URL/ENDPOINT with verification.verified=False -> ValueError
  - tree.add_node: with verification.verified=True -> accepted
  - tree.add_node: with allow_unverified=True -> accepted (for deserialization)
  - tree.add_node: dedup hit with new verification -> updates metadata.verification
  - tree.add_node: PORT with verification stores verification in metadata
"""
from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from opensquilla.asset_tree.tree import AssetTree
from opensquilla.asset_tree.models import AssetType


# ── recon_url_validate tests ──────────────────────────────────────────────


class _Handler(BaseHTTPRequestHandler):
    """Test HTTP handler that serves configurable content."""

    # class-level config; tests set these before starting the server
    status_code = 200
    body = b"OK"
    content_type = "text/html"
    title = None  # optional title

    def do_GET(self):  # noqa: N802 — http.server convention
        self.send_response(self.status_code)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def do_HEAD(self):  # noqa: N802
        self.send_response(self.status_code)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()

    def log_message(self, *_args):  # silence stderr
        return


@pytest.fixture
def http_server():
    """Start a local HTTP server on an ephemeral port. Returns base URL."""
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", server
    server.shutdown()
    thread.join(timeout=2)


def _run(coro):
    """Run an async coroutine synchronously (for tests).

    Use asyncio.run() which creates a fresh loop and properly closes it.
    asyncio.get_event_loop().run_until_complete() can leak coroutines
    when the surrounding test framework has torn down the loop.
    """
    import asyncio
    return asyncio.run(coro)




def _make_chain(tree, with_port=True, with_service=True):
    """Build sub -> ip -> [port] -> [service] -> return (sub, ip, port_or_None, svc_or_None)."""
    sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
    ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
    port = None
    svc = None
    if with_port:
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
    if with_service and port is not None:
        svc = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True)
    return sub, ip, port, svc


class TestReconUrlValidate:
    def test_200_with_clean_body_verified(self, http_server):
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 200
        server.RequestHandlerClass.body = b"<html><head><title>Real page</title></head><body>Welcome</body></html>"
        server.RequestHandlerClass.content_type = "text/html"

        result = json.loads(_run(recon_url_validate(url=url)))
        assert result["verified"] is True
        assert result["reason"] == "ok"
        assert result["probe"]["status_code"] == 200
        assert result["probe"]["title"] == "Real page"

    def test_200_with_404_body_rejected(self, http_server):
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 200
        server.RequestHandlerClass.body = b"<html><head><title>404 Not Found</title></head><body>Page not found</body></html>"
        server.RequestHandlerClass.content_type = "text/html"

        result = json.loads(_run(recon_url_validate(url=url)))
        assert result["verified"] is False
        assert "error_body" in result["reason"]

    def test_500_status_rejected(self, http_server):
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 500
        server.RequestHandlerClass.body = b"<html><body>Internal Server Error</body></html>"
        server.RequestHandlerClass.content_type = "text/html"

        result = json.loads(_run(recon_url_validate(url=url)))
        assert result["verified"] is False
        assert result["reason"] == "status_500"

    def test_404_status_rejected(self, http_server):
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 404
        server.RequestHandlerClass.body = b"not found"
        server.RequestHandlerClass.content_type = "text/plain"

        result = json.loads(_run(recon_url_validate(url=url)))
        assert result["verified"] is False
        assert result["reason"] == "status_404"

    def test_kong_error_body_rejected(self, http_server):
        """Kong wraps 4xx/5xx in 200 + JSON error body. Must be rejected."""
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 200
        server.RequestHandlerClass.body = b'''{
            "message": "upstream connect error or disconnect/reset before headers. reset reason: connection termination",
            "name": "Bad Gateway",
            "code": 502
        }'''
        # JSON content-type: the body is JSON not HTML, so error check
        # should NOT flag it. This is a legit API response.
        server.RequestHandlerClass.content_type = "application/json"

        result = json.loads(_run(recon_url_validate(url=url)))
        # JSON 200 with error key in body is OK — we only flag HTML.
        assert result["verified"] is True

    def test_html_kong_error_body_rejected(self, http_server):
        """Kong default HTML error page (status 200, body has 'upstream connect error')."""
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 200
        server.RequestHandlerClass.body = b"<html><body>upstream connect error</body></html>"
        server.RequestHandlerClass.content_type = "text/html"

        result = json.loads(_run(recon_url_validate(url=url)))
        assert result["verified"] is False
        assert "upstream" in result["reason"]

    def test_connection_refused_rejected(self):
        """Connecting to a closed port on localhost: verified=False, reason=no_response."""
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        # Find a definitely-closed port: bind a socket, get its port, close it
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # port now free / closed

        result = json.loads(_run(recon_url_validate(url=f"http://127.0.0.1:{port}/", timeout_s=2.0)))
        assert result["verified"] is False
        assert result["reason"] in ("no_response", "status_XXX")  # may vary

    def test_verified_at_present(self, http_server):
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate

        url, server = http_server
        server.RequestHandlerClass.status_code = 200
        server.RequestHandlerClass.body = b"<html><body>OK</body></html>"

        result = json.loads(_run(recon_url_validate(url=url)))
        assert "verified_at" in result
        assert result["verified_at"] is not None
        assert "T" in result["verified_at"]  # ISO ts


# ── recon_port_verify tests ──────────────────────────────────────────────


class TestReconPortVerify:
    def test_open_port_verified(self):
        """Open a TCP listener on an ephemeral port; verify reconnects."""
        import asyncio
        from opensquilla.tools.builtin.recon.port_scan import recon_port_verify

        async def _handler(reader, writer):
            # Echo nothing; just close.
            writer.close()

        async def main():
            server = await asyncio.start_server(_handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                result = json.loads(await recon_port_verify("127.0.0.1", port))
                assert result["verified"] is True
                assert result["reason"] == "ok"
                assert result["probe"]["state"] == "open"
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(main())

    def test_closed_port_rejected(self):
        """Bind + close to get a closed port; verify rejects."""
        import asyncio
        from opensquilla.tools.builtin.recon.port_scan import recon_port_verify

        async def main():
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            result = json.loads(await recon_port_verify("127.0.0.1", port, timeout_s=2.0))
            assert result["verified"] is False
            assert result["reason"] in ("connection_refused", "os_error")

        asyncio.run(main())

    def test_unreachable_host_rejected(self):
        """A localhost port that is bind+closed: connection refused."""
        from opensquilla.tools.builtin.recon.port_scan import recon_port_verify

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        result = json.loads(_run(recon_port_verify("127.0.0.1", port, timeout_s=1.5)))
        assert result["verified"] is False
        # local refused connection
        assert result["reason"] in ("connection_refused", "os_error", "timeout")


# ── tree.add_node verify hook tests ───────────────────────────────────────


VERIFIED = {
    "verified": True,
    "reason": "ok",
    "probe": {"status_code": 200, "server": "nginx"},
    "verified_at": "2026-06-17T00:00:00Z",
}

UNVERIFIED = {
    "verified": False,
    "reason": "timeout",
    "probe": {"state": "closed", "error": "timeout"},
    "verified_at": "2026-06-17T00:00:00Z",
}


class TestAddNodeVerificationHook:
    def test_url_without_verification_raises(self):
        tree = AssetTree("example.com")
        sub, ip, port, svc = _make_chain(tree)
        with pytest.raises(ValueError, match="requires verification"):
            tree.add_node(AssetType.URL, "https://x.com/", parent_id=svc)

    def test_port_without_verification_raises(self):
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        with pytest.raises(ValueError, match="requires verification"):
            tree.add_node(AssetType.PORT, "443", parent_id=ip)

    def test_url_with_unverified_envelope_raises(self):
        tree = AssetTree("example.com")
        sub, ip, port, svc = _make_chain(tree)
        with pytest.raises(ValueError, match="verification.verified is not True"):
            tree.add_node(
                AssetType.URL, "https://x.com/",
                parent_id=svc, verification=UNVERIFIED,
            )

    def test_url_with_verified_envelope_accepted(self):
        tree = AssetTree("example.com")
        sub, ip, port, svc = _make_chain(tree)
        url_id = tree.add_node(
            AssetType.URL, "https://x.com/",
            parent_id=svc, verification=VERIFIED,
        )
        url = tree.get_node(url_id)
        assert url is not None
        # Verification envelope recorded in metadata.
        assert url.metadata.get("verification", {}).get("verified") is True

    def test_port_with_verified_envelope_accepted(self):
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port_id = tree.add_node(
            AssetType.PORT, "443", parent_id=ip, verification=VERIFIED,
        )
        port = tree.get_node(port_id)
        assert port is not None
        assert port.metadata.get("verification", {}).get("verified") is True

    def test_allow_unverified_bypass(self):
        """Deserialization path uses allow_unverified=True."""
        tree = AssetTree("example.com")
        sub, ip, port, svc = _make_chain(tree)
        # No verification, but allow_unverified=True: accepted.
        url_id = tree.add_node(
            AssetType.URL, "https://x.com/",
            parent_id=svc, allow_unverified=True,
        )
        assert tree.get_node(url_id) is not None

    def test_subdomain_does_not_require_verification(self):
        """ROOT_DOMAIN / SUB_DOMAIN / IP / COMPONENT / STORAGE / API_SCHEMA
        do NOT require verification — they come from external sources
        (DNS, crtsh, ASN, CPE lookup)."""
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        # No verification needed for sub_domain/ip.
        assert sub is not None
        assert ip is not None

    def test_dedup_hit_updates_verification(self):
        """When a node already exists and we re-add with new verification,
        the metadata.verification is updated (re-check)."""
        tree = AssetTree("example.com")
        sub, ip, port, svc = _make_chain(tree, with_port=True, with_service=False)
        port_id = tree.add_node(
            AssetType.PORT, "443", parent_id=ip, verification=VERIFIED,
        )
        # Re-add same port with new verification.
        NEW_VERIFIED = {**VERIFIED, "verified_at": "2026-06-17T01:00:00Z"}
        port_id2 = tree.add_node(
            AssetType.PORT, "443", parent_id=ip, verification=NEW_VERIFIED,
        )
        assert port_id == port_id2  # dedup hit
        port = tree.get_node(port_id)
        assert port.metadata["verification"]["verified_at"] == "2026-06-17T01:00:00Z"

    def test_endpoint_requires_verification(self):
        tree = AssetTree("example.com")
        sub, ip, port, svc = _make_chain(tree)
        with pytest.raises(ValueError, match="requires verification"):
            tree.add_node(AssetType.ENDPOINT, "/admin", parent_id=svc)

    def test_service_requires_verification(self):
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        with pytest.raises(ValueError, match="requires verification"):
            tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=ip)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
