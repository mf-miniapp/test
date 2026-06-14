"""Tests for the asset_tree builtin tools.

Covers Phase 1 MVP: asset_tree_create, asset_tree_add_nodes, asset_tree_find_unseen.
Uses a tempdir for state persistence so tests don't pollute ~/.opensquilla.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

import pytest

from opensquilla.tools.builtin.asset_tree import tree as at_tools

pytestmark = pytest.mark.requires_mysql


@pytest.fixture
def tmp_state_dir(monkeypatch, mysql_backend_url):
    """Redirect OPEN_SQUILLA_STATE_DIR + ASSET_TREE_DB_URL to a fresh
    tempdir and point AssetTree at the test MySQL instance.

    AssetTree is MySQL-only; this fixture requires ``TEST_MYSQL_URL`` to
    be set (the ``mysql_backend_url`` fixture skips the test if not).
    """
    tmp = Path(tempfile.mkdtemp(prefix="asset-tree-test-"))
    monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(tmp))
    monkeypatch.setenv("ASSET_TREE_DB_URL", mysql_backend_url)
    # Reset the cached default backend so the new URL takes effect.
    from opensquilla.asset_tree.db.backend import set_default_backend
    set_default_backend(None)
    yield tmp
    set_default_backend(None)


async def _create(tree_id: str, root_domain: str = "example.com") -> dict:
    result = await at_tools.asset_tree_create(root_domain, tree_id=tree_id)
    return json.loads(result)


async def test_create_returns_tree_id_and_root(tmp_state_dir):
    payload = await _create("tree-test")
    assert payload["tree_id"] == "tree-test"
    assert payload["root_node_id"]
    assert payload["root_domain"] == "example.com"
    assert Path(payload["persisted_path"]).exists()


async def test_create_rejects_duplicate(tmp_state_dir):
    await _create("dup")
    with pytest.raises(Exception, match="already exists"):
        await _create("dup")


async def test_create_rejects_invalid_id(tmp_state_dir):
    with pytest.raises(Exception, match="Invalid tree_id"):
        await at_tools.asset_tree_create("example.com", tree_id="../escape")


async def test_add_nodes_creates_children(tmp_state_dir):
    payload = await _create("t")
    root_id = payload["root_node_id"]

    result = await at_tools.asset_tree_add_nodes(
        tree_id="t",
        parent_id=root_id,
        asset_type="sub_domain",
        values=["api.example.com", "www.example.com"],
        source_wave="W0.test",
    )
    data = json.loads(result)
    assert len(data["added"]) == 2
    assert len(data["deduped"]) == 0
    assert len(data["errors"]) == 0


async def test_add_nodes_dedupes(tmp_state_dir):
    payload = await _create("t")
    root_id = payload["root_node_id"]

    # First add
    await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=root_id, asset_type="sub_domain",
        values=["api.example.com"],
    )
    # Second add with overlap
    result = await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=root_id, asset_type="sub_domain",
        values=["api.example.com", "new.example.com"],
    )
    data = json.loads(result)
    assert len(data["added"]) == 1  # new.example.com
    assert len(data["deduped"]) == 1  # api.example.com


async def test_add_nodes_cross_parent_legit(tmp_state_dir):
    """Same IP value under different parents is legal and produces distinct nodes."""
    payload = await _create("t")
    root_id = payload["root_node_id"]

    api = (await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=root_id, asset_type="sub_domain",
        values=["api.example.com"],
    ))
    api_id = json.loads(api)["added"][0]["node_id"]
    admin = (await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=root_id, asset_type="sub_domain",
        values=["admin.example.com"],
    ))
    admin_id = json.loads(admin)["added"][0]["node_id"]

    # Same IP under both parents
    r1 = json.loads(await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=api_id, asset_type="ip",
        values=["1.2.3.4"],
    ))
    r2 = json.loads(await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=admin_id, asset_type="ip",
        values=["1.2.3.4"],
    ))

    # Both adds should report `added` (not deduped), and IDs must differ
    assert len(r1["added"]) == 1
    assert len(r2["added"]) == 1
    assert r1["added"][0]["node_id"] != r2["added"][0]["node_id"]


async def test_add_nodes_validates_parent_child(tmp_state_dir):
    """Illegal parent→child pair is recorded as an error (not silently added)."""
    payload = await _create("t")
    root_id = payload["root_node_id"]

    # ROOT_DOMAIN → IP is illegal (must go through SUB_DOMAIN first)
    result = json.loads(await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=root_id, asset_type="ip",
        values=["1.2.3.4"],
    ))
    assert result["added"] == []
    assert result["deduped"] == []
    assert any("Invalid parent" in e["error"] for e in result["errors"]), (
        f"expected parent validation error, got: {result['errors']}"
    )


async def test_find_unseen_filters_by_type(tmp_state_dir):
    payload = await _create("t")
    root_id = payload["root_node_id"]

    # Add some sub_domain children
    await at_tools.asset_tree_add_nodes(
        tree_id="t", parent_id=root_id, asset_type="sub_domain",
        values=["api.example.com"],
    )

    # All UNSEEN: root_domain + sub_domain
    all_result = json.loads(await at_tools.asset_tree_find_unseen("t"))
    assert all_result["count"] == 2

    # Filtered to sub_domain only
    sub_result = json.loads(await at_tools.asset_tree_find_unseen("t", asset_type="sub_domain"))
    assert sub_result["count"] == 1
    assert sub_result["unseen"][0]["asset_type"] == "sub_domain"


async def test_find_unseen_unknown_tree(tmp_state_dir):
    with pytest.raises(Exception, match="Tree not found"):
        await at_tools.asset_tree_find_unseen("ghost")


async def test_add_nodes_missing_tree(tmp_state_dir):
    with pytest.raises(Exception, match="Tree not found"):
        await at_tools.asset_tree_add_nodes(
            tree_id="ghost", parent_id="x", asset_type="sub_domain", values=["a"],
        )