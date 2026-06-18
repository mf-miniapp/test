"""v5 (2026-06-18) asset_tree_complete 8 层硬关卡测试。

覆盖:
- 树只到 L3 (UNSEEN=0, max_depth<8): 调 asset_tree_complete 应 raise IncompleteSkeletonError
- 树到 L8 + 无 UNSEEN: 调 asset_tree_complete 应成功
- force=True 可绕过 (审计标记)
- IncompleteSkeletonError 字段: tree_id, max_depth_reached, missing_waves 等
"""
from __future__ import annotations

import json
import pytest

from opensquilla.asset_tree.models import (
    AssetState,
    AssetType,
    IncompleteSkeletonError,
)
from opensquilla.asset_tree.tree import AssetTree


# ─── 1. 单元: IncompleteSkeletonError ─────────────────
class TestIncompleteSkeletonError:
    def test_construction(self) -> None:
        err = IncompleteSkeletonError(
            tree_id="t-1",
            max_depth_reached=3,
            max_depth_required=8,
            unseen_total=0,
            completion_pct=0.375,
            missing_waves=["W1.5", "W1.5c", "W2.5", "W3.5"],
        )
        assert err.tree_id == "t-1"
        assert err.max_depth_reached == 3
        assert err.unseen_total == 0
        assert err.completion_pct == 0.375
        assert err.missing_waves == ["W1.5", "W1.5c", "W2.5", "W3.5"]
        msg = str(err)
        assert "DO NOT emit find-complete-v1" in msg
        assert "F-resume" in msg
        assert "W1.5" in msg

    def test_inherits_runtime_error(self) -> None:
        err = IncompleteSkeletonError(
            tree_id="t", max_depth_reached=0, unseen_total=1, completion_pct=0.0,
        )
        assert isinstance(err, RuntimeError)


# ─── 2. 单元: 硬关卡行为 ─────────────────
class TestAssetTreeCompleteHardGate:
    """直接调 _detect_missing_waves + is_skeleton_complete 验证语义。

    工具函数本身的 end-to-end 测试需要 _load_tree (文件系统), 这里覆盖核心
    判定逻辑, 工具集成测试在 test_asset_tree_tools_phase2 跑过 e2e。
    """

    def _build_l3_tree(self) -> AssetTree:
        """建一棵只到 L3 的树, 模拟 10jqka.com.cn bug 场景。"""
        tree = AssetTree("example.com")
        tree.update_state(tree.root_id, AssetState.DISCOVERED)
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        tree.update_state(sub, AssetState.DISCOVERED)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        tree.update_state(port, AssetState.DISCOVERED)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        tree.update_state(svc, AssetState.DISCOVERED)
        return tree

    def test_l3_only_tree_not_complete(self) -> None:
        tree = self._build_l3_tree()
        assert tree.max_depth_reached() == 4  # service L4, 实际 L3
        assert tree.is_skeleton_complete() is False

    def test_l3_only_tree_skeleton_report(self) -> None:
        tree = self._build_l3_tree()
        report = tree.skeleton_report()
        assert report["complete"] is False
        assert report["max_depth_reached"] == 4
        assert report["completion_pct"] < 1.0
        assert report["unseen_total"] == 0  # L3 节点全 discovered

    def test_unseen_node_blocks_completion(self) -> None:
        tree = self._build_l3_tree()
        # 把 service 改回 UNSEEN
        svc_id = None
        for n in tree._nodes.values():
            if n.asset_type == AssetType.SERVICE:
                svc_id = n.id
        tree.update_state(svc_id, AssetState.UNSEEN)
        assert tree.is_skeleton_complete() is False
        report = tree.skeleton_report()
        assert report["unseen_total"] == 1

    def test_complete_8_layer_tree(self) -> None:
        tree = AssetTree("example.com")
        tree.update_state(tree.root_id, AssetState.DISCOVERED)
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        tree.update_state(sub, AssetState.DISCOVERED)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        tree.update_state(port, AssetState.DISCOVERED)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        tree.update_state(svc, AssetState.DISCOVERED)
        url = tree.add_node(
            AssetType.URL, "https://api.example.com", parent_id=svc, allow_unverified=True,
        )
        tree.update_state(url, AssetState.DISCOVERED)
        ep = tree.add_node(
            AssetType.ENDPOINT, "GET /v1/users/:id", parent_id=url, allow_unverified=True,
        )
        tree.update_state(ep, AssetState.DISCOVERED)
        param = tree.add_node(AssetType.PARAMETER, "id", parent_id=ep)
        tree.update_state(param, AssetState.DISCOVERED)
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=param,
            metadata={"category": "sqli"},
        )
        tree.update_state(inj, AssetState.DISCOVERED)
        # max_depth=8, all discovered
        assert tree.max_depth_reached() == 8
        assert tree.is_skeleton_complete() is True
        report = tree.skeleton_report()
        assert report["complete"] is True
        assert report["completion_pct"] == 1.0
        assert report["unseen_total"] == 0


# ─── 3. 工具层: 模拟 LLM 调 asset_tree_complete ─────────────────
class TestCompleteToolIntegration:
    """通过 tools/builtin/asset_tree/tree.py 直接调 asset_tree_complete。"""

    def test_complete_refuses_incomplete_skeleton(self, tmp_path, monkeypatch) -> None:
        # 让 _tree_path 写到 tmp
        import os
        from opensquilla.tools.builtin.asset_tree import tree as tools_tree
        monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(tmp_path))
        # 建一棵只到 L3 的树
        tree = AssetTree("example.com")
        tree.update_state(tree.root_id, AssetState.DISCOVERED)
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        tree.update_state(sub, AssetState.DISCOVERED)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        tree.update_state(port, AssetState.DISCOVERED)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        tree.update_state(svc, AssetState.DISCOVERED)
        # 保存
        tools_tree._save_tree(tree, "t-l3")
        # 调 complete 应 raise IncompleteSkeletonError
        with pytest.raises(IncompleteSkeletonError) as exc_info:
            import asyncio
            asyncio.run(tools_tree.asset_tree_complete("t-l3"))
        err = exc_info.value
        assert err.tree_id == "t-l3"
        assert err.max_depth_reached < 8
        assert "DO NOT emit find-complete-v1" in str(err)
        assert "F-resume" in str(err)
        # missing_waves 应包含 W1.5 / W1.5c / W2.5 / W3.5
        assert any("W1.5" in w for w in err.missing_waves)

    def test_complete_force_bypasses_gate(self, tmp_path, monkeypatch) -> None:
        import asyncio
        from opensquilla.tools.builtin.asset_tree import tree as tools_tree
        monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(tmp_path))
        tree = AssetTree("example.com")
        tree.update_state(tree.root_id, AssetState.DISCOVERED)
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        tree.update_state(sub, AssetState.DISCOVERED)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        tree.update_state(port, AssetState.DISCOVERED)
        svc = tree.add_node(
            AssetType.SERVICE, "HTTPS/NGINX", parent_id=port, allow_unverified=True,
        )
        tree.update_state(svc, AssetState.DISCOVERED)
        tools_tree._save_tree(tree, "t-l3-force")
        # force=True 应跳过
        result_str = asyncio.run(tools_tree.asset_tree_complete("t-l3-force", force=True))
        result = json.loads(result_str)
        assert result["force_used"] is True
        assert result["skeleton"]["complete"] is False  # 骨架仍未完成
        assert result["tree_path"] != ""
