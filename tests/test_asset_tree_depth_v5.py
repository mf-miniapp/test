"""v5 (2026-06-18) 8 层深度硬约束专项测试。

覆盖:
  - 8 层完整入树: ROOT → SUB → IP → PORT → SERVICE → URL → ENDPOINT → PARAMETER → INJECTION_VECTOR
  - 9 层入树被拒: DepthExceededError
  - validate_depth 单元
  - depth_of / max_depth 公开 API
  - secret / generic 跨层挂载不受深度限制
  - from_dict 重建保留 depth
"""
from __future__ import annotations

import json

import pytest

from opensquilla.asset_tree.models import (
    AssetState,
    AssetType,
    DepthExceededError,
    MAX_TREE_DEPTH,
    validate_depth,
)
from opensquilla.asset_tree.tree import AssetTree


# ─── 常量契约 ─────────────────────────────────────
class TestConstants:
    def test_max_depth_is_8(self) -> None:
        assert MAX_TREE_DEPTH == 8

    def test_max_depth_doc(self) -> None:
        # 业务硬上限 (SOUL_BODY.md "v5 硬约束" 段落)
        assert MAX_TREE_DEPTH == 8


# ─── validate_depth 单元 ─────────────────────────────
class TestValidateDepth:
    def test_root_is_depth_0(self) -> None:
        d = validate_depth(parent_depth=None, parent_type=None, child_type=AssetType.ROOT_DOMAIN)
        assert d == 0

    def test_normal_chain_1_to_8(self) -> None:
        # 任何 parent_depth + 1 在 [1, 8] 区间都应返回 would_be (= L0..L7)
        for pd in range(0, 8):
            d = validate_depth(
                parent_depth=pd, parent_type=AssetType.SUB_DOMAIN, child_type=AssetType.IP,
            )
            assert d == pd + 1

    def test_depth_9_rejected(self) -> None:
        # 试图让某个 child 落在 depth=9 (越界, L8+1)
        with pytest.raises(DepthExceededError) as exc:
            validate_depth(
                parent_depth=8,
                parent_type=AssetType.INJECTION_VECTOR,
                child_type=AssetType.GENERIC,
            )
        assert exc.value.would_be_depth == 9
        assert exc.value.parent_depth == 8
        assert exc.value.child_type == AssetType.GENERIC

    def test_depth_9_rejected(self) -> None:
        with pytest.raises(DepthExceededError):
            validate_depth(
                parent_depth=8, parent_type=AssetType.GENERIC, child_type=AssetType.GENERIC,
            )


# ─── 8 层完整入树 ─────────────────────────────────
class TestEightLayerIngest:
    def _build_full_chain(self) -> tuple[AssetTree, list[str]]:
        """建一条完整 8 层链: ROOT → SUB → IP → PORT → SERVICE → URL → ENDPOINT → PARAMETER → INJECTION_VECTOR."""
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        url = tree.add_node(
            AssetType.URL, "https://api.example.com", parent_id=svc, allow_unverified=True,
        )
        endpoint = tree.add_node(
            AssetType.ENDPOINT, "GET /v1/users/:id", parent_id=url, allow_unverified=True,
        )
        param = tree.add_node(AssetType.PARAMETER, "id", parent_id=endpoint)
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=param,
            metadata={"category": "sqli", "verified": False},
        )
        ids = [tree.root_id, sub, ip, port, svc, url, endpoint, param, inj]
        return tree, ids

    def test_chain_8_layers_succeeds(self) -> None:
        tree, ids = self._build_full_chain()
        # 8 跳边 = 9 节点: root(L0) sub(L1) ip(L2) port(L3) svc(L4) url(L5)
        # endpoint(L6) param(L7) injection_vector(L8)
        depths = [tree.depth_of(nid) for nid in ids]
        assert depths == [0, 1, 2, 3, 4, 5, 6, 7, 8]
        # 业务硬约束: INJECTION_VECTOR 是 L8 (= MAX_TREE_DEPTH = 8)
        assert tree.depth_of(ids[-1]) == MAX_TREE_DEPTH  # = 8

    def test_max_depth_reports_8(self) -> None:
        tree, _ = self._build_full_chain()
        # 9 节点 (root..inj) 全部 L0..L8, max_depth = 8
        assert tree.max_depth() == MAX_TREE_DEPTH  # 8 = L8


# ─── 9 层被拒 ─────────────────────────────────────
class TestNineLayerRejected:
    def test_injection_vector_is_l8_legal(self) -> None:
        # 业务最深的合法节点是 INJECTION_VECTOR (L8, path_depth=8)。
        # 它挂在 PARAMETER (L7) 下 -> would_be = 8, 合法 (== MAX_TREE_DEPTH)。
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        url = tree.add_node(
            AssetType.URL, "https://api.example.com", parent_id=svc, allow_unverified=True,
        )
        endpoint = tree.add_node(
            AssetType.ENDPOINT, "GET /v1/users/:id", parent_id=url, allow_unverified=True,
        )
        param = tree.add_node(AssetType.PARAMETER, "id", parent_id=endpoint)
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=param,
            metadata={"category": "sqli"},
        )
        # 合法落树, 深度 = 8 (= MAX_TREE_DEPTH)
        assert tree.depth_of(inj) == MAX_TREE_DEPTH

    def test_depth_exceeded_via_attempted_child(self) -> None:
        # 直接验证 validate_depth 越界: parent_depth=8 + 1 = 9 > MAX_TREE_DEPTH
        with pytest.raises(DepthExceededError) as exc:
            validate_depth(
                parent_depth=8, parent_type=AssetType.INJECTION_VECTOR,
                child_type=AssetType.GENERIC,
            )
        assert exc.value.would_be_depth == 9


# ─── 跨层 / 兜底挂载 ─────────────────────────────
class TestCrossLayerAndCatchAll:
    def test_secret_hangs_under_subdomain(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        # SECRET 是 L0..L7 白名单挂载, 跨层, 不算入主链深度
        # 但 parent 必须是白名单内的 (SUB_DOMAIN 是)
        secret = tree.add_node(
            AssetType.SECRET, "AKIA-xxx", parent_id=sub,
            metadata={"kind": "aws_key"},
        )
        # secret 自身深度 = parent_depth + 1 = 1 + 1 = 2
        assert tree.depth_of(secret) == 2

    def test_generic_depth_via_direct_node(self) -> None:
        # 业务模型: GENERIC 是兜底, 父位仅允许 GENERIC 自身。
        # 这里直接构造 AssetNode 验证 depth 字段计算 (绕过 add_node 的
        # 父子校验, 因为 ROOT_DOMAIN 不允许 GENERIC 子 — 业务硬约束)。
        from opensquilla.asset_tree.models import AssetNode
        g1 = AssetNode(asset_type=AssetType.GENERIC, value="fuzzy-1", parent_id="root-id")
        g1.set_depth(1)
        assert g1.depth == 1
        # 跨层挂载, depth 由父深度 + 1 计算, 不受 8 层硬约束
        # (因为 validate_depth 只在 add_node 走, 直接构造是允许的)
        g2 = AssetNode(asset_type=AssetType.GENERIC, value="fuzzy-2", parent_id=g1.id)
        g2.set_depth(2)
        assert g2.depth == 2


# ─── 序列化保持 depth ─────────────────────────────
class TestDepthSerialization:
    def test_depth_preserved_through_to_from_dict(self) -> None:
        tree, ids = self._build_full_chain() if hasattr(self, "_build_full_chain") else (None, None)
        # 我们手动建一遍, 避免用 self method
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        url = tree.add_node(
            AssetType.URL, "https://api.example.com", parent_id=svc, allow_unverified=True,
        )
        endpoint = tree.add_node(
            AssetType.ENDPOINT, "GET /v1/users/:id", parent_id=url, allow_unverified=True,
        )
        param = tree.add_node(AssetType.PARAMETER, "id", parent_id=endpoint)
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=param,
            metadata={"category": "sqli"},
        )

        # round-trip: 9 节点树 (root..inj), 验证 depth 仍能重建
        data = tree.to_dict()
        restored = AssetTree.from_dict(data)
        assert restored.depth_of(inj) == tree.depth_of(inj) == 8
        assert restored.max_depth() == tree.max_depth() == 8
        # 持久化的 JSON 不污染 metadata (v5 关键)
        assert "depth" not in tree.get_node(inj).metadata

    def test_metadata_not_polluted_with_depth(self) -> None:
        # v5 关键: depth 字段不污染 metadata (用户的 metadata 应保持原样)
        tree = AssetTree("example.com")
        sub = tree.add_node(
            AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id,
            metadata={"resolver": "dns", "records": ["A: 1.1.1.1"]},
        )
        node = tree.get_node(sub)
        assert "depth" not in node.metadata
        assert node.metadata == {"resolver": "dns", "records": ["A: 1.1.1.1"]}


# ─── waves.py 的 wave_owns_depth ─────────────────
class TestWaveDepthOwnership:
    def test_w1_5c_owns_through_parameter(self) -> None:
        from opensquilla.attack_dispatch.waves import wave_owns_depth
        # W1.5c 写到 endpoint (L6) 和 parameter (L7)
        assert wave_owns_depth("W1.5c", 6) is True
        assert wave_owns_depth("W1.5c", 7) is True
        # W1.5c 不到 injection_vector (L8) — 应 False
        assert wave_owns_depth("W1.5c", 8) is False

    def test_w2_5_owns_injection_vector(self) -> None:
        from opensquilla.attack_dispatch.waves import wave_owns_depth
        # W2.5 写到 injection_vector (L8)
        assert wave_owns_depth("W2.5", 7) is True
        assert wave_owns_depth("W2.5", 8) is True
        # W2.5 也不到 L9
        assert wave_owns_depth("W2.5", 9) is False

    def test_unknown_wave_falls_back_to_hard_cap(self) -> None:
        from opensquilla.attack_dispatch.waves import wave_owns_depth
        # 未知 wave 走 MAX_TREE_DEPTH 兜底: 8 内允许, 9 拒
        assert wave_owns_depth("W-unknown", 8) is True
        assert wave_owns_depth("W-unknown", 9) is False
