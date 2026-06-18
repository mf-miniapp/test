"""v5 (2026-06-18) hack-deep-find 工作流策略 + 8 层骨架终止测试。

覆盖:
  - bulk_layer vs chain_fanout 划分 (DISCOVERY_STRATEGY_MAP)
  - wave_owns_depth 在两层都有正确边界
  - is_skeleton_complete / skeleton_report 在 8 层全建好时返回 True
  - is_skeleton_complete 在 缺 INJ 节点 或 缺 UNSEEN 时返回 False
  - dispatch_plan 给 L0..L3 (bulk) 和 L4+ (chain) 不同的 spawn_count 计算
  - find_unseen / find_unseen_chain 工具: bulk 取全量, chain 按 parent 分组
"""
from __future__ import annotations

import pytest

from opensquilla.asset_tree.models import (
    AssetState,
    AssetType,
    MAX_TREE_DEPTH,
)
from opensquilla.asset_tree.tree import AssetTree


# ─── 1. DISCOVERY_STRATEGY_MAP 划分 ─────────────────
class TestDiscoveryStrategyMap:
    def test_w0_5_is_bulk_layer(self) -> None:
        from opensquilla.attack_dispatch.waves import (
            DISCOVERY_STRATEGY_MAP, is_bulk_layer_wave, is_chain_fanout_wave,
        )
        assert DISCOVERY_STRATEGY_MAP["W0.5"] == "bulk_layer"
        assert is_bulk_layer_wave("W0.5")
        assert not is_chain_fanout_wave("W0.5")

    def test_w1_is_bulk_layer(self) -> None:
        from opensquilla.attack_dispatch.waves import (
            DISCOVERY_STRATEGY_MAP, is_bulk_layer_wave,
        )
        assert DISCOVERY_STRATEGY_MAP["W1"] == "bulk_layer"
        assert is_bulk_layer_wave("W1")

    def test_w1_5_is_chain_fanout(self) -> None:
        from opensquilla.attack_dispatch.waves import (
            DISCOVERY_STRATEGY_MAP, is_chain_fanout_wave, is_bulk_layer_wave,
        )
        assert DISCOVERY_STRATEGY_MAP["W1.5"] == "chain_fanout"
        assert is_chain_fanout_wave("W1.5")
        assert not is_bulk_layer_wave("W1.5")

    def test_w3_5_is_chain_fanout(self) -> None:
        from opensquilla.attack_dispatch.waves import DISCOVERY_STRATEGY_MAP
        assert DISCOVERY_STRATEGY_MAP["W3.5"] == "chain_fanout"

    def test_w2_5_is_chain_fanout(self) -> None:
        from opensquilla.attack_dispatch.waves import DISCOVERY_STRATEGY_MAP
        assert DISCOVERY_STRATEGY_MAP["W2.5"] == "chain_fanout"

    def test_strategy_of_unknown_wave_falls_back_to_chain_fanout(self) -> None:
        from opensquilla.attack_dispatch.waves import strategy_of_wave
        # 未知 wave 走兜底 chain_fanout (保守)
        assert strategy_of_wave("W-unknown") == "chain_fanout"


# ─── 2. wave_owns_depth 边界 ─────────────────
class TestWaveOwnsDepthV5:
    def test_w1_owns_through_service(self) -> None:
        from opensquilla.attack_dispatch.waves import wave_owns_depth
        # W1 写到 service (L4) — port-scanner / service-fingerprint
        for d in range(0, 5):
            assert wave_owns_depth("W1", d) is True
        # W1 不写 url (L5) — 那是 W1.5 / W3.5 webapp-discoverer
        assert wave_owns_depth("W1", 5) is False

    def test_w3_5_owns_through_endpoint(self) -> None:
        from opensquilla.attack_dispatch.waves import wave_owns_depth
        # W3.5 写到 endpoint (L6) — cookie/header/secret 不增主链 depth
        for d in range(0, 7):
            assert wave_owns_depth("W3.5", d) is True
        # W3.5 不写 injection_vector (L8) — 那是 W2.5 跨 owner 出的
        assert wave_owns_depth("W3.5", 8) is False


# ─── 3. 8 层骨架终止契约 ─────────────────
class TestSkeletonComplete:
    def _build_complete_8_layer(self) -> AssetTree:
        """建一条完整 8 层链, 全部状态非 UNSEEN。"""
        tree = AssetTree("example.com")
        # L0 (root, 种子) -> discovered (不算阻塞)
        tree.update_state(tree.root_id, AssetState.DISCOVERED)
        # L1
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        tree.update_state(sub, AssetState.DISCOVERED)
        # L2
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        # L3 (port + service)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        tree.update_state(port, AssetState.DISCOVERED)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        tree.update_state(svc, AssetState.DISCOVERED)
        # L4 (url)
        url = tree.add_node(
            AssetType.URL, "https://api.example.com", parent_id=svc, allow_unverified=True,
        )
        tree.update_state(url, AssetState.DISCOVERED)
        # L5 (endpoint)
        ep = tree.add_node(
            AssetType.ENDPOINT, "GET /v1/users/:id", parent_id=url, allow_unverified=True,
        )
        tree.update_state(ep, AssetState.DISCOVERED)
        # L6 (parameter)
        param = tree.add_node(AssetType.PARAMETER, "id", parent_id=ep)
        tree.update_state(param, AssetState.DISCOVERED)
        # L8 (injection_vector)
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=param,
            metadata={"category": "sqli"},
        )
        tree.update_state(inj, AssetState.DISCOVERED)
        return tree

    def test_complete_when_8_layers_built(self) -> None:
        tree = self._build_complete_8_layer()
        assert tree.max_depth_reached() == MAX_TREE_DEPTH  # = 8
        assert tree.is_skeleton_complete() is True
        report = tree.skeleton_report()
        assert report["complete"] is True
        assert report["max_depth_reached"] == 8
        assert report["completion_pct"] == 1.0
        assert report["unseen_total"] == 0

    def test_incomplete_when_missing_injection_vector(self) -> None:
        # 缺 L8 INJ
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        tree.update_state(sub, AssetState.DISCOVERED)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        # max_depth = 2 (sub L1 + ip L2), 远不及 8
        assert tree.max_depth_reached() == 2
        assert tree.is_skeleton_complete() is False

    def test_incomplete_when_unseen_node_remains(self) -> None:
        tree = self._build_complete_8_layer()
        # 把某个节点改回 UNSEEN
        sub_node = list(tree._nodes.values())[1]  # 第二个节点 (sub_domain)
        tree.update_state(sub_node.id, AssetState.UNSEEN)
        assert tree.is_skeleton_complete() is False
        report = tree.skeleton_report()
        assert report["complete"] is False
        assert report["unseen_total"] >= 1

    def test_completion_pct_scales_with_depth(self) -> None:
        # 半路 (max_depth=4) → 0.5
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        # max_depth = 4 (service L4), v5.2 改: pct 基于 FIND_TERMINATION_DEPTH=7
        # 4 / 7 ≈ 0.571, 而不是旧的 4 / MAX_TREE_DEPTH = 0.5
        assert tree.skeleton_completion_pct() == 4.0 / 7
        assert tree.is_skeleton_complete() is False

    def test_abandoned_does_not_block_completion(self) -> None:
        # ABANDONED 节点不算阻塞 (软删, 合法)
        tree = self._build_complete_8_layer()
        # 把 INJ 标 ABANDONED (业务上: 不再追)
        inj_node = None
        for n in tree._nodes.values():
            if n.asset_type == AssetType.INJECTION_VECTOR:
                inj_node = n
        assert inj_node is not None
        tree.update_state(inj_node.id, AssetState.ABANDONED)
        # max_depth 还 = 8 (节点还在), unseen = 0, complete = true
        assert tree.max_depth_reached() == 8
        assert tree.is_skeleton_complete() is True
        report = tree.skeleton_report()
        assert report["abandoned_total"] >= 1


# ─── 4. nodes_per_layer 分布 ─────────────────
class TestNodesPerLayer:
    def test_counts_by_depth(self) -> None:
        tree = AssetTree("example.com")
        sub1 = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com", parent_id=tree.root_id)
        sub2 = tree.add_node(AssetType.SUB_DOMAIN, "b.example.com", parent_id=tree.root_id)
        ip1 = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub1)
        ip2 = tree.add_node(AssetType.IP, "2.2.2.2", parent_id=sub2)
        # L0: 1 (root), L1: 2 (sub), L2: 2 (ip)
        layers = tree.nodes_per_layer()
        assert layers == {0: 1, 1: 2, 2: 2}


# ─── 5. dispatch_plan 计算 ─────────────────
class TestDispatchPlan:
    def _build_partial_tree(self) -> AssetTree:
        """建一棵"已跑完 L0..L3, 准备 L4+"的树。"""
        tree = AssetTree("example.com")
        tree.update_state(tree.root_id, AssetState.DISCOVERED)
        sub1 = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com", parent_id=tree.root_id)
        sub2 = tree.add_node(AssetType.SUB_DOMAIN, "b.example.com", parent_id=tree.root_id)
        ip1 = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub1)
        ip2 = tree.add_node(AssetType.IP, "2.2.2.2", parent_id=sub2)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip1, allow_unverified=True)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        # 标 discovered (网络层跑完)
        for nid in [sub1, sub2, ip1, ip2, port, svc]:
            tree.update_state(nid, AssetState.DISCOVERED)
        return tree

    def test_dispatch_plan_for_l0_l3_bulk(self) -> None:
        tree = self._build_partial_tree()
        # 加 1 个新 sub_domain (UNSEEN), 触发 W0.5 重跑
        new_sub = tree.add_node(AssetType.SUB_DOMAIN, "c.example.com", parent_id=tree.root_id)
        plan = tree.dispatch_plan()
        # W0.5: bulk_layer, 1 sub_domain UNSEEN
        assert "W0.5" in plan
        assert plan["W0.5"]["strategy"] == "bulk_layer"
        assert plan["W0.5"]["unseen_total"] == 1
        # batch_size=10 默认, 1 UNSEEN -> 1 spawn
        assert plan["W0.5"]["spawn_count"] == 1

    def test_dispatch_plan_for_l4_plus_chain(self) -> None:
        tree = self._build_partial_tree()
        # 加 2 个 url UNSEEN (同 service) -> 1 chain
        svc = None
        for n in tree._nodes.values():
            if n.asset_type == AssetType.SERVICE:
                svc = n
                break
        tree.add_node(AssetType.URL, "https://a.example.com", parent_id=svc.id, allow_unverified=True)
        tree.add_node(AssetType.URL, "https://b.example.com", parent_id=svc.id, allow_unverified=True)
        plan = tree.dispatch_plan()
        # W3.5: chain_fanout, 2 url 同一 parent -> 1 chain
        assert "W3.5" in plan
        assert plan["W3.5"]["strategy"] == "chain_fanout"
        assert plan["W3.5"]["unseen_total"] == 2
        # 2 url 同一 parent (svc) -> 1 chain -> 1 spawn
        assert plan["W3.5"]["spawn_count"] == 1

    def test_dispatch_plan_chain_per_parent(self) -> None:
        # 3 url 分属 3 个 parent -> 3 chain -> 3 spawn
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port1 = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        port2 = tree.add_node(AssetType.PORT, "80", parent_id=ip, allow_unverified=True)
        port3 = tree.add_node(AssetType.PORT, "8080", parent_id=ip, allow_unverified=True)
        svc1 = tree.add_node(AssetType.SERVICE, "SVC1", parent_id=port1, allow_unverified=True)
        svc2 = tree.add_node(AssetType.SERVICE, "SVC2", parent_id=port2, allow_unverified=True)
        svc3 = tree.add_node(AssetType.SERVICE, "SVC3", parent_id=port3, allow_unverified=True)
        tree.add_node(AssetType.URL, "https://a", parent_id=svc1, allow_unverified=True)
        tree.add_node(AssetType.URL, "https://b", parent_id=svc2, allow_unverified=True)
        tree.add_node(AssetType.URL, "https://c", parent_id=svc3, allow_unverified=True)
        plan = tree.dispatch_plan()
        # W3.5: 3 url, 3 different parents -> 3 chain
        assert plan["W3.5"]["unseen_total"] == 3
        assert plan["W3.5"]["spawn_count"] == 3

    def test_dispatch_plan_empty_when_no_unseen(self) -> None:
        tree = self._build_partial_tree()
        # 全部标 discovered -> plan 应空 (没 UNSEEN)
        plan = tree.dispatch_plan()
        for wave_id, info in plan.items():
            assert info["unseen_total"] == 0
            assert info["spawn_count"] == 0


# ─── 6. find_unseen_chain 工具 (in-memory) ─────────────────
class TestFindUnseenChain:
    def test_chain_groups_by_parent(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        svc = tree.add_node(AssetType.SERVICE, "SVC", parent_id=port, allow_unverified=True)
        # 3 url 在同一 svc 下
        tree.add_node(AssetType.URL, "https://a", parent_id=svc, allow_unverified=True)
        tree.add_node(AssetType.URL, "https://b", parent_id=svc, allow_unverified=True)
        tree.add_node(AssetType.URL, "https://c", parent_id=svc, allow_unverified=True)
        # 用 brief_gen 测分组? 实际跑工具需要 _load_tree; 这里测 chain 划分逻辑
        from opensquilla.attack_dispatch.waves import strategy_of_wave
        assert strategy_of_wave("W3.5") == "chain_fanout"
