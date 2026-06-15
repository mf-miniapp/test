"""Tests for the recon_dns_resolve and recon_dns_over_https tools.

Tests use mocked asyncio loop.getaddrinfo so they don't hit real DNS in CI.
"""

from __future__ import annotations

import asyncio
import json
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opensquilla.tools.builtin.recon import dns as recon_dns


def _make_loop_with_getaddrinfo(behaviour):
    """Return a stub loop whose getaddrinfo returns `behaviour` (sync-list or exc)."""
    loop = MagicMock()
    loop.getaddrinfo = AsyncMock(side_effect=behaviour)
    return loop


def _patch_loop_getaddrinfo(return_value=None, side_effect=None):
    """Patch the loop.getaddrinfo called by recon_dns.recon_dns_resolve.

    The production code does `loop.getaddrinfo(...)` and `await
    asyncio.wait_for(...)`. We patch by replacing the call chain directly:
    substitute `asyncio.wait_for` to invoke our side_effect/return_value
    without involving real timing.
    """
    if side_effect is not None:
        async def fake_wait_for(awaitable, timeout):
            raise side_effect if isinstance(side_effect, BaseException) else side_effect
        return patch.object(recon_dns.asyncio, "wait_for", side_effect=fake_wait_for)
    else:
        async def fake_wait_for(awaitable, timeout):
            return return_value
        return patch.object(recon_dns.asyncio, "wait_for", side_effect=fake_wait_for)


def _run(coro):
    """Helper: run async coro to completion in a fresh event loop."""
    return asyncio.run(coro)


def test_dns_resolve_returns_ips() -> None:
    """recon_dns_resolve returns a JSON with `ips` populated."""
    fake_infos = [
        (2, 1, 6, "", ("1.2.3.4", 0)),   # AF_INET, SOCK_STREAM
        (10, 1, 6, "", ("::1", 0, 0, 0)),  # AF_INET6
    ]
    with _patch_loop_getaddrinfo(return_value=fake_infos):
        result = _run(recon_dns.recon_dns_resolve("example.com"))
    data = json.loads(result)
    assert data["hostname"] == "example.com"
    assert "1.2.3.4" in data["ips"]
    assert "::1" in data["ips"]
    assert data["error"] is None


def test_dns_resolve_dedupes_repeated_ips() -> None:
    """Multiple getaddrinfo entries for the same IP must collapse to one."""
    fake_infos = [
        (2, 1, 6, "", ("1.2.3.4", 0)),
        (2, 1, 6, "", ("1.2.3.4", 0)),
        (2, 1, 6, "", ("1.2.3.4", 0)),
    ]
    with _patch_loop_getaddrinfo(return_value=fake_infos):
        result = _run(recon_dns.recon_dns_resolve("example.com"))
    data = json.loads(result)
    assert data["ips"] == ["1.2.3.4"]


def test_dns_resolve_handles_timeout() -> None:
    """TimeoutError is surfaced as `error` field, not raised."""
    with _patch_loop_getaddrinfo(side_effect=asyncio.TimeoutError()):
        result = _run(recon_dns.recon_dns_resolve("nx.example.com"))
    data = json.loads(result)
    assert data["ips"] == []
    assert "timeout" in (data["error"] or "")


def test_dns_resolve_handles_gaierror() -> None:
    """socket.gaierror is surfaced as `error` field."""
    with _patch_loop_getaddrinfo(side_effect=socket.gaierror("Name or service not known")):
        result = _run(recon_dns.recon_dns_resolve("nx.example.com"))
    data = json.loads(result)
    assert data["ips"] == []
    assert "gaierror" in (data["error"] or "")


def test_dns_over_https_falls_back_to_resolver_on_failure() -> None:
    """DoH transport failure must NOT crash; must fall back to system resolver."""
    import urllib.error
    import urllib.request

    fallback_infos = [(2, 1, 6, "", ("1.2.3.4", 0))]

    # Patch asyncio.wait_for to:
    #   - first call (DoH urlopen via run_in_executor) → raise URLError
    #   - subsequent calls (fallback getaddrinfo) → return fallback_infos
    call_count = {"n": 0}

    async def fake_wait_for(awaitable, timeout):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # The DoH call — make the executor raise URLError.
            # We do that by patching urlopen AND letting the executor actually run.
            # To keep this simple, raise URLError directly.
            raise urllib.error.URLError("doh transport failed")
        return fallback_infos

    with patch.object(recon_dns.asyncio, "wait_for", side_effect=fake_wait_for):
        result = _run(
            recon_dns.recon_dns_over_https("example.com", provider="cloudflare")
        )
    data = json.loads(result)
    assert "1.2.3.4" in data["ips"]
    assert "doh_failed" in (data["error"] or "")