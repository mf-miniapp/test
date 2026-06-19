"""End-to-end smoke for ``build_and_run_attack_paths(dry_run=True)``.

The v6 chat-flow path used to crash with
``AttributeError: 'GatewayConfig' object has no attribute 'load_default'``
because the helper called a method that doesn't exist on
``GatewayConfig``. This test exercises the helper with a stub backend
in dry-run mode (no LLM provider is actually built) to ensure the
helper no longer touches the broken API surface.

The test is intentionally *small*: it only asserts the helper does
not raise before reaching the LLM build step.
"""
from __future__ import annotations

import pytest

from tests._stubs.in_memory_backend import InMemoryStubBackend


@pytest.fixture()
def stub_tree(monkeypatch):
    """Wire a stub backend with a tiny L0->L1 tree."""
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.asset_tree.web import store as _store_mod

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    monkeypatch.setattr(_store_mod, "_backend", lambda: be)

    async def _setup():
        await be.upsert_tree("tree-dry", root_domain="dry.com", root_node_id="n-root")
        await be.add_node(
            "tree-dry", "n-root", "sub_domain", "api.dry.com",
            parent_id="n-root", path_depth=1,
        )
    import asyncio
    asyncio.run(_setup())
    return be


def test_dry_run_no_attribute_error(stub_tree):
    """``dry_run=True`` must reach run_attack_paths and return a result
    without touching GatewayConfig.load_default."""
    import asyncio
    from opensquilla.orchestrator.run_attack_paths import (
        BuildAndRunOptions, build_and_run_attack_paths,
    )
    result = asyncio.run(build_and_run_attack_paths(BuildAndRunOptions(
        tree_id="tree-dry", dry_run=True, max_depth=3,
    )))
    # dry_run stops at "paths generated", no dispatch.
    assert result.tree_id == "tree-dry"
    assert result.failed == 0
    assert result.completed == 0
