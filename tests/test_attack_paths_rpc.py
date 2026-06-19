"""attack_paths.run gateway RPC handler — params parsing + dispatch wiring.

We don't dispatch a real LLM (that path is covered by the orchestrator
integration tests); we assert the RPC layer:

  - surfaces params correctly to ``build_and_run_attack_paths``
  - surfaces ``BuildAndRunError`` codes back as RuntimeError
  - rejects missing ``tree_id`` with ``ValueError``
  - is registered with ``operator.write`` scope
"""
from __future__ import annotations

import pytest

from opensquilla.gateway.rpc import RpcContext, get_registry, validate_classification
from opensquilla.gateway.rpc_attack_paths import (
    _as_bool,
    _as_int,
    _as_states,
    rpc_attack_paths_run)


def _ctx() -> RpcContext:
    return RpcContext(conn_id="test", config=None)


def test_as_bool_coercion():
    assert _as_bool(None) is False
    assert _as_bool(None, default=True) is True
    assert _as_bool(True) is True
    assert _as_bool(0) is False
    assert _as_bool(1) is True
    assert _as_bool("true") is True
    assert _as_bool("YES") is True
    assert _as_bool("off") is False
    # unknown string is not in the truthy set
    assert _as_bool("anything", default=True) is False
    # non-coercible type falls back to default
    assert _as_bool([], default=True) is True
    assert _as_bool(object(), default=False) is False


def test_as_int_coercion():
    assert _as_int(None, 7) == 7
    assert _as_int("5", 7) == 5
    assert _as_int("not-a-number", 7) == 7
    assert _as_int(3, 7) == 3
    assert _as_int(3.7, 7) == 3


def test_as_states_coercion():
    assert _as_states(None) == ("unseen", "discovered", "triaged")
    assert _as_states("a,b,c") == ("a", "b", "c")
    assert _as_states(["x", "y"]) == ("x", "y")
    assert _as_states(42) == ("unseen", "discovered", "triaged")


def test_rpc_rejects_missing_tree_id():
    import asyncio
    with pytest.raises(ValueError, match="tree_id"):
        asyncio.run(rpc_attack_paths_run({}, _ctx()))
    with pytest.raises(ValueError, match="params must be a dict"):
        asyncio.run(rpc_attack_paths_run("not-a-dict", _ctx()))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="tree_id"):
        asyncio.run(rpc_attack_paths_run({"tree_id": ""}, _ctx()))
    with pytest.raises(ValueError, match="tree_id"):
        asyncio.run(rpc_attack_paths_run({"tree_id": "  "}, _ctx()))


def test_rpc_unknown_tree_surfaces_code2(monkeypatch):
    """When the tree is missing, the RPC layer should surface code=2 as
    a ``RuntimeError`` with the original message in the body."""
    import asyncio
    from tests._stubs.in_memory_backend import InMemoryStubBackend
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.asset_tree.web import store as _store_mod
    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    monkeypatch.setattr(_store_mod, "_backend", lambda: be)
    fake_id = "tree-does-not-exist-zzz"
    with pytest.raises(RuntimeError, match="not found"):
        asyncio.run(rpc_attack_paths_run({"tree_id": fake_id}, _ctx()))


def test_rpc_registered_with_write_scope():
    reg = get_registry()
    entry = reg.get_entry("attack_paths.run")
    assert entry is not None
    assert entry.required_scope == "operator.write"
    # Make sure all registered methods still pass scope validation.
    validate_classification()
