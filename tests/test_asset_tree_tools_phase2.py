"""Phase 2 asset_tree tool tests: update_state / get_subtree /
list_siblings / stats / complete.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.requires_mysql

from opensquilla.tools.builtin.asset_tree import tree as at_tools


@pytest.fixture
def tmp_state_dir(monkeypatch, mysql_backend_url):
    """Point AssetTree at the test MySQL instance; reset default backend.

    AssetTree is MySQL-only; this fixture requires ``TEST_MYSQL_URL`` to
    be set (the ``mysql_backend_url`` fixture skips the test if not).
    """
    monkeypatch.setenv("ASSET_TREE_DB_URL", mysql_backend_url)
    from opensquilla.asset_tree.db.backend import set_default_backend
    set_default_backend(None)
    yield
    set_default_backend(None)


async def _build_tree(tree_id: str = "t2") -> dict:
    create = json.loads(await at_tools.asset_tree_create("example.com", tree_id=tree_id))
    root_id = create["root_node_id"]

    # Add 2 sub_domains
    api_id = json.loads(await at_tools.asset_tree_add_nodes(
        tree_id=tree_id, parent_id=root_id, asset_type="sub_domain",
        values=["api.example.com"],
    ))["added"][0]["node_id"]
    admin_id = json.loads(await at_tools.asset_tree_add_nodes(
        tree_id=tree_id, parent_id=root_id, asset_type="sub_domain",
        values=["admin.example.com"],
    ))["added"][0]["node_id"]

    # Add an IP under api
    ip_id = json.loads(await at_tools.asset_tree_add_nodes(
        tree_id=tree_id, parent_id=api_id, asset_type="ip",
        values=["1.2.3.4"],
    ))["added"][0]["node_id"]

    return {
        "tree_id": tree_id,
        "root_id": root_id,
        "api_id": api_id,
        "admin_id": admin_id,
        "ip_id": ip_id,
    }


async def test_update_state_changes_state(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_update_state(
        tree_id=ctx["tree_id"], node_id=ctx["api_id"], state="discovered",
    ))
    assert result["old_state"] == "unseen"
    assert result["new_state"] == "discovered"

    # Subsequent update
    result = json.loads(await at_tools.asset_tree_update_state(
        tree_id=ctx["tree_id"], node_id=ctx["api_id"], state="triaged",
    ))
    assert result["old_state"] == "discovered"
    assert result["new_state"] == "triaged"


async def test_update_state_validates_state_value(tmp_state_dir):
    ctx = await _build_tree()
    with pytest.raises(Exception, match="Invalid state"):
        await at_tools.asset_tree_update_state(
            tree_id=ctx["tree_id"], node_id=ctx["api_id"], state="bogus",
        )


async def test_update_state_unknown_node(tmp_state_dir):
    ctx = await _build_tree()
    with pytest.raises(Exception, match="Node not found"):
        await at_tools.asset_tree_update_state(
            tree_id=ctx["tree_id"], node_id="ghost", state="discovered",
        )


async def test_get_subtree_renders_human_text(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_get_subtree(
        tree_id=ctx["tree_id"], node_id=ctx["root_id"], max_depth=5,
    ))
    rendered = result["rendered"]
    assert "example.com" in rendered
    assert "api.example.com" in rendered
    assert "admin.example.com" in rendered
    assert "1.2.3.4" in rendered


async def test_get_subtree_max_depth_limits_render(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_get_subtree(
        tree_id=ctx["tree_id"], node_id=ctx["root_id"], max_depth=1,
    ))
    rendered = result["rendered"]
    assert "api.example.com" in rendered  # depth 1
    assert "1.2.3.4" not in rendered  # depth 2, excluded


async def test_get_subtree_defaults_to_root(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_get_subtree(
        tree_id=ctx["tree_id"], max_depth=1,
    ))
    assert result["node_id"] == ctx["root_id"]


async def test_list_siblings_excludes_self(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_list_siblings(
        tree_id=ctx["tree_id"], node_id=ctx["api_id"],
    ))
    sibling_values = {s["value"] for s in result["siblings"]}
    assert sibling_values == {"admin.example.com"}
    assert result["count"] == 1


async def test_list_siblings_root_has_none(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_list_siblings(
        tree_id=ctx["tree_id"], node_id=ctx["root_id"],
    ))
    assert result["siblings"] == []
    assert result["count"] == 0


async def test_stats_returns_summary(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_stats(tree_id=ctx["tree_id"]))
    assert result["total_nodes"] == 4  # root + 2 subs + 1 IP
    assert result["root_domain"] == "example.com"
    assert "by_type" in result
    assert result["by_type"]["sub_domain"] == 2


async def test_complete_returns_tree_path(tmp_state_dir):
    ctx = await _build_tree()
    result = json.loads(await at_tools.asset_tree_complete(tree_id=ctx["tree_id"]))
    assert result["tree_id"] == ctx["tree_id"]
    assert Path(result["tree_path"]).exists()
    assert "stats" in result