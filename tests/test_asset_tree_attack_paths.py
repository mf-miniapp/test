"""AssetTree v6 攻击路径枚举测试 (2026-06-19)。

覆盖 enumerate_root_to_leaf_paths:
  - 空树: 返回 []
  - 单链 L0..L7: 1 条 path
  - 多分支: 多条 path, 各自 path_id 唯一
  - max_depth 截断
  - include_states 过滤 (EXPLOITED/ABANDONED 默认排除)
  - 边状态同步 to_node.state
  - SECRET 是合法叶子
  - compute_path_id 稳定
  - AttackPath.mark_started / mark_completed / mark_failed
  - AttackPath.to_dict 字段完整

注: ROOT_DOMAIN / SUB_DOMAIN 等是 shared-singleton, add_node 必须
显式传 parent_id=tree.root_id 才挂到正确父下。
"""

from __future__ import annotations

import pytest

from opensquilla.asset_tree.models import (
    AssetState,
    AssetType,
    AttackEdge,
    AttackPath,
)
from opensquilla.asset_tree.tree import AssetTree


# ── 辅助构造器 ──────────────────────────────────────────────


_NEXT_TYPE = {
    AssetType.ROOT_DOMAIN: AssetType.SUB_DOMAIN,
    AssetType.SUB_DOMAIN: AssetType.IP,
    AssetType.IP: AssetType.PORT,
    AssetType.PORT: AssetType.SERVICE,
    AssetType.SERVICE: AssetType.URL,
    AssetType.URL: AssetType.ENDPOINT,
    AssetType.ENDPOINT: AssetType.PARAMETER,
}


def _add(tree: AssetTree, asset_type: AssetType, value: str, parent_id: str) -> str:
    """add_node with allow_unverified=True for fixture builds."""
    return tree.add_node(
        asset_type, value, parent_id=parent_id, allow_unverified=True,
    )


def _build_chain(tree: AssetTree, depth: int) -> list[str]:
    """构造一条 L0..L{depth} 的单链, 返回所有节点 id。"""
    ids = [tree.root_id]
    cur_id = tree.root_id
    cur_type = AssetType.ROOT_DOMAIN
    for i in range(depth):
        nxt = _NEXT_TYPE[cur_type]
        cur_id = _add(tree, nxt, f"v_{nxt.value}_{i}", cur_id)
        ids.append(cur_id)
        cur_type = nxt
    return ids


# ── 基础测试 ────────────────────────────────────────────────


class TestEnumerateEmpty:
    def test_empty_tree(self):
        tree = AssetTree("example.com")
        assert tree.enumerate_root_to_leaf_paths() == []


class TestEnumerateSingleChain:
    def test_l0_to_l7_returns_one_path(self):
        tree = AssetTree("example.com")
        _build_chain(tree, 7)
        paths = tree.enumerate_root_to_leaf_paths()
        assert len(paths) == 1
        p = paths[0]
        assert p.tree_id == (tree._tree_id or f"tree-{tree.root_domain}")
        assert p.leaf_type == AssetType.PARAMETER
        assert len(p.edges) == 7
        assert p.edges[0].from_type == AssetType.ROOT_DOMAIN
        assert p.edges[0].to_type == AssetType.SUB_DOMAIN
        assert p.edges[-1].from_type == AssetType.ENDPOINT
        assert p.edges[-1].to_type == AssetType.PARAMETER

    def test_scope_string_contains_all_segments(self):
        tree = AssetTree("example.com")
        _build_chain(tree, 7)
        p = tree.enumerate_root_to_leaf_paths()[0]
        s = p.scope_string
        assert "root_domain=example.com" in s
        assert s.count(" -> ") == 7  # 7 段都含 " -> " (from→to 段内分隔)


class TestEnumerateMultipleBranches:
    def test_two_subdomains_produce_two_paths(self):
        tree = AssetTree("example.com")
        sub1 = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        sub2 = _add(tree, AssetType.SUB_DOMAIN, "b.example.com", tree.root_id)
        _add(tree, AssetType.IP, "1.1.1.1", sub1)
        _add(tree, AssetType.IP, "2.2.2.2", sub2)
        paths = tree.enumerate_root_to_leaf_paths()
        assert len(paths) == 2
        leaf_ips = {p.leaf_value for p in paths}
        assert leaf_ips == {"1.1.1.1", "2.2.2.2"}

    def test_path_id_unique_per_topology(self):
        tree = AssetTree("example.com")
        sub1 = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        sub2 = _add(tree, AssetType.SUB_DOMAIN, "b.example.com", tree.root_id)
        _add(tree, AssetType.IP, "1.1.1.1", sub1)
        _add(tree, AssetType.IP, "2.2.2.2", sub2)
        paths = tree.enumerate_root_to_leaf_paths()
        ids = [p.path_id for p in paths]
        assert len(set(ids)) == 2

    def test_path_id_stable_across_calls(self):
        tree = AssetTree("example.com")
        _build_chain(tree, 5)
        p1 = tree.enumerate_root_to_leaf_paths()[0]
        p2 = tree.enumerate_root_to_leaf_paths()[0]
        assert p1.path_id == p2.path_id


class TestMaxDepth:
    def test_max_depth_truncates(self):
        tree = AssetTree("example.com")
        _build_chain(tree, 7)
        paths = tree.enumerate_root_to_leaf_paths(max_depth=3)
        assert len(paths) == 1
        # 3 条边 -> L0->L1->L2->L3 (PORT 节点)
        assert len(paths[0].edges) == 3
        assert paths[0].leaf_type == AssetType.PORT


class TestIncludeStates:
    def test_default_skips_exploited(self):
        tree = AssetTree("example.com")
        sub = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        ip1 = _add(tree, AssetType.IP, "1.1.1.1", sub)
        ip2 = _add(tree, AssetType.IP, "2.2.2.2", sub)
        tree.update_state(ip1, AssetState.EXPLOITED)
        paths = tree.enumerate_root_to_leaf_paths()
        assert len(paths) == 1
        assert paths[0].leaf_value == "2.2.2.2"

    def test_include_explicit_states(self):
        tree = AssetTree("example.com")
        sub = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        ip1 = _add(tree, AssetType.IP, "1.1.1.1", sub)
        tree.update_state(ip1, AssetState.EXPLOITED)
        paths = tree.enumerate_root_to_leaf_paths(
            include_states=(AssetState.UNSEEN, AssetState.DISCOVERED, AssetState.EXPLOITED),
        )
        assert len(paths) == 1
        assert paths[0].leaf_value == "1.1.1.1"


class TestEdgeState:
    def test_edge_state_reflects_to_node(self):
        tree = AssetTree("example.com")
        sub = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        ip = _add(tree, AssetType.IP, "1.1.1.1", sub)
        tree.update_state(ip, AssetState.TRIAGED)
        p = tree.enumerate_root_to_leaf_paths()[0]
        assert p.edges[-1].edge_state == AssetState.TRIAGED


class TestSecret:
    def test_secret_is_valid_leaf(self):
        tree = AssetTree("example.com")
        sub = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
        _add(tree, AssetType.SECRET, "AKIAXXX", sub)
        paths = tree.enumerate_root_to_leaf_paths()
        assert len(paths) == 1
        assert paths[0].leaf_type == AssetType.SECRET


# ── AttackPath 模型测试 ────────────────────────────────────────


class TestAttackPathModel:
    def test_compute_path_id_12hex(self):
        e = AttackEdge(
            edge_index=0,
            from_node_id="a" * 12, to_node_id="b" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="a.example.com",
        )
        pid = AttackPath.compute_path_id([e])
        assert len(pid) == 12
        assert all(c in "0123456789abcdef" for c in pid)

    def test_compute_path_id_differs_for_different_edges(self):
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
        assert AttackPath.compute_path_id([e1]) != AttackPath.compute_path_id([e2])

    def test_mark_lifecycle(self):
        e = AttackEdge(
            edge_index=0, from_node_id="a" * 12, to_node_id="b" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="a.example.com",
        )
        p = AttackPath(
            path_id="a" * 12, tree_id="t1", edges=[e],
            leaf_node_id="b" * 12, leaf_type=AssetType.SUB_DOMAIN,
            leaf_value="a.example.com",
            scope_string="root_domain=example.com → sub_domain=a.example.com",
        )
        assert p.status == "pending"
        p.mark_started()
        assert p.status == "in_progress"
        assert p.started_at is not None
        p.mark_completed(3)
        assert p.status == "completed"
        assert p.vuln_count == 3
        assert p.completed_at is not None

    def test_mark_failed(self):
        e = AttackEdge(
            edge_index=0, from_node_id="a" * 12, to_node_id="b" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="a.example.com",
        )
        p = AttackPath(
            path_id="a" * 12, tree_id="t1", edges=[e],
            leaf_node_id="b" * 12, leaf_type=AssetType.SUB_DOMAIN,
            leaf_value="a.example.com", scope_string="x",
        )
        p.mark_failed("boom")
        assert p.status == "failed"
        assert p.error == "boom"
        assert p.completed_at is not None

    def test_to_dict_complete(self):
        e = AttackEdge(
            edge_index=0, from_node_id="a" * 12, to_node_id="b" * 12,
            from_type=AssetType.ROOT_DOMAIN, to_type=AssetType.SUB_DOMAIN,
            from_value="example.com", to_value="a.example.com",
        )
        p = AttackPath(
            path_id="a" * 12, tree_id="t1", edges=[e],
            leaf_node_id="b" * 12, leaf_type=AssetType.SUB_DOMAIN,
            leaf_value="a.example.com", scope_string="x",
            metadata={"k": "v"},
        )
        d = p.to_dict()
        assert d["path_id"] == "a" * 12
        assert d["tree_id"] == "t1"
        assert d["leaf_type"] == "sub_domain"
        assert d["metadata"] == {"k": "v"}
        assert d["status"] == "pending"
        assert d["created_at"] is not None
        assert d["started_at"] is None
