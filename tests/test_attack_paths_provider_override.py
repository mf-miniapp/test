"""Provider override: chat-flow can pin a local llama/qwen endpoint
without editing ``~/.opensquilla/config.toml``.

Tests exercise:

  - ``BuildAndRunOptions`` accepts the new ``base_url`` / ``api_key``
    fields without crashing.
  - The RPC handler ``_as_optional_str`` helper trims / None-coerces
    properly.
  - The RPC handler passes ``base_url`` / ``api_key`` through to
    ``build_and_run_attack_paths`` so a /attack-paths run from chat
    can hit a local Qwen3.6 endpoint.
"""
from __future__ import annotations

import pytest

from opensquilla.gateway.rpc_attack_paths import _as_optional_str


def test_as_optional_str_coercion():
    assert _as_optional_str(None) is None
    assert _as_optional_str("") is None
    assert _as_optional_str("   ") is None
    assert _as_optional_str("hello") == "hello"
    assert _as_optional_str("  http://localhost:9091/v1  ") == "http://localhost:9091/v1"


def test_build_options_accepts_provider_override():
    """``BuildAndRunOptions`` should accept base_url/api_key without
    surprising the rest of the helper."""
    from opensquilla.orchestrator.run_attack_paths import BuildAndRunOptions
    opts = BuildAndRunOptions(
        tree_id="tree-x",
        dry_run=True,
        base_url="http://127.0.0.1:9091/v1",
        api_key="local-dev-key",
        provider="openai",
        model="qwen3.6-35b",
    )
    assert opts.base_url == "http://127.0.0.1:9091/v1"
    assert opts.api_key == "local-dev-key"
    assert opts.provider == "openai"
    assert opts.model == "qwen3.6-35b"


def test_rpc_passes_base_url_through(monkeypatch):
    """End-to-end-ish: the RPC handler should forward
    ``base_url``/``api_key`` to ``build_and_run_attack_paths`` so
    the operator can pin a local llama endpoint per call."""
    from opensquilla.gateway.rpc import RpcContext
    from opensquilla.gateway.rpc_attack_paths import rpc_attack_paths_run

    captured: dict = {}

    async def fake_build(opts):
        captured["opts"] = opts
        from opensquilla.orchestrator.run_attack_paths import BuildAndRunError
        raise BuildAndRunError("2:tree 'tree-x' not found")

    # Patch the symbol at its source module so the lazy import inside
    # ``rpc_attack_paths_run`` picks up our fake.  We use ``sys.modules``
    # to grab the real module object (the public package attribute
    # ``opensquilla.orchestrator.run_attack_paths`` is shadowed by the
    # function re-exported in __init__.py).
    import sys
    mod = sys.modules["opensquilla.orchestrator.run_attack_paths"]
    monkeypatch.setattr(mod, "build_and_run_attack_paths", fake_build)

    import asyncio
    with pytest.raises(RuntimeError, match="not found"):
        asyncio.run(rpc_attack_paths_run(
            {
                "tree_id": "tree-x",
                "base_url": "http://127.0.0.1:9091/v1",
                "api_key": "local-dev-key",
                "provider": "openai",
                "model": "qwen3.6-35b",
            },
            RpcContext(conn_id="t", config=None),
        ))
    opts = captured["opts"]
    assert opts.base_url == "http://127.0.0.1:9091/v1"
    assert opts.api_key == "local-dev-key"
    assert opts.provider == "openai"
    assert opts.model == "qwen3.6-35b"
