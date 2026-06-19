"""v6 (2026-06-19) attack_paths 模块单测。"""
from __future__ import annotations

import asyncio

import pytest

from opensquilla.asset_tree.attack_paths import (
    compute_path_hash,
    create_attack_paths_for_tree,
)
from opensquilla.asset_tree.models import AssetState, AssetType
from opensquilla.asset_tree.tree import AssetTree
from tests._stubs.in_memory_backend import InMemoryStubBackend


# ── helper ────────────────────────────────────────────────


def _add(tree, atype, value, parent):
    return tree.add_node(atype, value, parent_id=parent, allow_unverified=True)


def _build_two_branch_tree() -> AssetTree:
    tree = AssetTree("example.com")
    sub1 = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
    sub2 = _add(tree, AssetType.SUB_DOMAIN, "b.example.com", tree.root_id)
    _add(tree, AssetType.IP, "1.1.1.1", sub1)
    _add(tree, AssetType.IP, "2.2.2.2", sub2)
    return tree


# ── compute_path_hash ────────────────────────────────────────


class TestComputePathHash:
    def test_stable(self):
        from opensquilla.asset_tree.models import AttackEdge
        e = AttackEdge(
            edge_index=0, from_node_id="a" * 12, to_node_id="b" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="a.example.com",
        )
        h1 = compute_path_hash([e])
        h2 = compute_path_hash([e])
        assert h1 == h2
        assert len(h1) == 40  # SHA1 hex

    def test_differs_for_different_edges(self):
        from opensquilla.asset_tree.models import AttackEdge
        e1 = AttackEdge(
            edge_index=0, from_node_id="a" * 12, to_node_id="b" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="a.example.com",
        )
        e2 = AttackEdge(
            edge_index=0, from_node_id="a" * 12, to_node_id="c" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="b.example.com",
        )
        assert compute_path_hash([e1]) != compute_path_hash([e2])


# ── create_attack_paths_for_tree ─────────────────────────────


class TestCreateAttackPaths:
    def test_empty_tree(self):
        tree = AssetTree("example.com")
        backend = InMemoryStubBackend()
        out = asyncio.run(create_attack_paths_for_tree(
            tree=tree, backend=backend, tree_id="tree-example.com",
        ))
        assert out["path_count"] == 0
        assert out["leaf_type_histogram"] == {}
        assert any("empty" in w for w in out["warnings"])

    def test_two_branches(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        out = asyncio.run(create_attack_paths_for_tree(
            tree=tree, backend=backend, tree_id="tree-example.com",
        ))
        assert out["path_count"] == 2
        assert out["leaf_type_histogram"] == {"ip": 2}
        assert out["written"] == 2
        # 路径应被 backend 持久化
        stored = asyncio.run(backend.list_attack_paths("tree-example.com"))
        assert len(stored) == 2
        for row in stored:
            assert row["status"] == "pending"
            assert row["path_id"]
            assert len(row["path_hash"]) == 40

    def test_idempotent_rerun(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        kwargs = dict(tree=tree, backend=backend, tree_id="tree-example.com")
        out1 = asyncio.run(create_attack_paths_for_tree(**kwargs))
        out2 = asyncio.run(create_attack_paths_for_tree(**kwargs))
        # 两次写入, 但 path 数量不变 (upsert 走 path_hash UNIQUE)
        assert out1["path_count"] == out2["path_count"] == 2
        stored = asyncio.run(backend.list_attack_paths("tree-example.com"))
        assert len(stored) == 2

    def test_tree_id_mismatch_raises(self):
        tree = AssetTree("example.com", tree_id="tree-real")
        backend = InMemoryStubBackend()
        with pytest.raises(ValueError, match="tree_id mismatch"):
            asyncio.run(create_attack_paths_for_tree(
                tree=tree, backend=backend, tree_id="wrong-id",
            ))

    def test_warnings_when_max_depth_not_reached(self):
        tree = AssetTree("example.com")
        sub = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        _add(tree, AssetType.IP, "1.1.1.1", sub)  # max_depth=2
        backend = InMemoryStubBackend()
        out = asyncio.run(create_attack_paths_for_tree(
            tree=tree, backend=backend, tree_id="tree-example.com",
            max_depth=7,
        ))
        assert out["path_count"] == 1
        assert any("max_depth_reached" in w for w in out["warnings"])

    def test_path_summaries_complete(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        out = asyncio.run(create_attack_paths_for_tree(
            tree=tree, backend=backend, tree_id="tree-example.com",
        ))
        for s in out["paths"]:
            assert "path_id" in s
            assert s["leaf_type"] == "ip"
            assert s["leaf_value"] in {"1.1.1.1", "2.2.2.2"}
            assert s["edge_count"] == 2  # root_domain → sub_domain → ip
            assert "→" in s["scope_string"]
