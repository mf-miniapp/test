"""v5.2 (2026-06-18) hack-deep-find 终止契约改写 + 不委派 hack-deep 测试。

v5.2 重大变更:
1. find 终止深度从 L8 (INJECTION_VECTOR) 改为 L7 (PARAMETER) — 业务
   资产层 L0..L7 共 8 节点层 = "8 层深度" 资产树。
2. L8 INJECTION_VECTOR 是漏洞向量, 不属于 find 责任范围, 由
   hack-deep 在 attack phase 自行写入。
3. find 自身**不**委派 hack-deep: 不 spawn `agent_id="hack-deep"`,
   不发 `w2.5-dispatch-v1`, 不发 `drill-in-request-v1`。
4. W2.5 (per-port attack plan) 整体不在 find 责任范围, 由
   hack-deep 在 attack phase 自行执行。

测试目标:
  - is_skeleton_complete 在 L7 (PARAMETER) 触及 + 无 UNSEEN 时 True
  - is_skeleton_complete 在 L6 (ENDPOINT) 只到时 False (缺 W1.5c)
  - skeleton_report 包含 find_termination_depth 字段
  - skeleton_completion_pct 在 L7+ clamp 到 1.0
  - W2.5 不在 _detect_missing_waves 推荐里
  - asset_tree_complete 工具 raise IncompleteSkeletonError 时
    missing_waves 不含 W2.5
"""
from __future__ import annotations

import json

import pytest

from opensquilla.asset_tree.models import (
    AssetState,
    AssetType,
    FIND_TERMINATION_DEPTH,
    IncompleteSkeletonError,
    MAX_TREE_DEPTH,
)
from opensquilla.asset_tree.tree import AssetTree


# ─── 1. FIND_TERMINATION_DEPTH 常量契约 ─────────────────
class TestFindTerminationDepthConstant:
    def test_max_tree_depth_unchanged(self) -> None:
        # 业务硬上限保留 = 8 (path_depth ∈ [0, 8], 9 节点层)
        assert MAX_TREE_DEPTH == 8

    def test_find_termination_depth_is_7(self) -> None:
        # v5.2: find 终止深度 = 7 (L7 PARAMETER, 业务最深资产层)
        assert FIND_TERMINATION_DEPTH == 7

    def test_find_termination_depth_less_than_max(self) -> None:
        # find 不写漏洞向量, 所以 FIND_TERMINATION_DEPTH < MAX_TREE_DEPTH
        assert FIND_TERMINATION_DEPTH < MAX_TREE_DEPTH


# ─── 2. is_skeleton_complete L7 终止契约 ─────────────────
class TestIsSkeletonCompleteAtL7:
    def _build_l7_tree(self) -> AssetTree:
        """建一条完整 8 节点层 (L0..L7) 链, 全部 DISCOVERED。"""
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
        return tree

    def test_l7_chain_complete(self) -> None:
        """L7 PARAMETER 触及 + 全部 DISCOVERED = find 终止。"""
        tree = self._build_l7_tree()
        assert tree.max_depth_reached() == 7
        assert tree.is_skeleton_complete() is True

    def test_l6_chain_not_complete(self) -> None:
        """max_depth=6 (ENDPOINT) 仍不是 find 终止, 缺 W1.5c (PARAMETER)。"""
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
        assert tree.max_depth_reached() == 6
        assert tree.is_skeleton_complete() is False  # < FIND_TERMINATION_DEPTH

    def test_l7_with_l8_inj_still_complete(self) -> None:
        """L7+ 有 L8 INJ 节点, 仍 complete (find 不写 L8 但允许它存在)。"""
        tree = self._build_l7_tree()
        # 加 INJ 模拟 hack-deep attack phase 写入
        last_param = None
        for n in tree._nodes.values():
            if n.asset_type == AssetType.PARAMETER:
                last_param = n
        assert last_param is not None
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=last_param.id,
            metadata={"category": "sqli"},
        )
        tree.update_state(inj, AssetState.DISCOVERED)
        assert tree.max_depth_reached() == 8
        assert tree.is_skeleton_complete() is True


# ─── 3. skeleton_report 包含 find_termination_depth ─────────────────
class TestSkeletonReportV52:
    def _build_l7_tree(self) -> AssetTree:
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
        return tree

    def test_report_has_find_termination_depth(self) -> None:
        tree = self._build_l7_tree()
        report = tree.skeleton_report()
        assert "find_termination_depth" in report
        assert report["find_termination_depth"] == 7

    def test_report_has_max_depth_cap(self) -> None:
        # 兼容字段保留
        tree = self._build_l7_tree()
        report = tree.skeleton_report()
        assert "max_depth_cap" in report
        assert report["max_depth_cap"] == 8

    def test_completion_pct_clamps_at_l7(self) -> None:
        tree = self._build_l7_tree()
        report = tree.skeleton_report()
        assert report["completion_pct"] == 1.0

    def test_completion_pct_clamps_above_l7(self) -> None:
        tree = self._build_l7_tree()
        # 加 INJ
        last_param = None
        for n in tree._nodes.values():
            if n.asset_type == AssetType.PARAMETER:
                last_param = n
        inj = tree.add_node(
            AssetType.INJECTION_VECTOR, "id:sqli", parent_id=last_param.id,
            metadata={"category": "sqli"},
        )
        tree.update_state(inj, AssetState.DISCOVERED)
        # max_depth=8 > FIND_TERMINATION_DEPTH=7, 但 clamp 到 1.0
        report = tree.skeleton_report()
        assert report["completion_pct"] == 1.0


# ─── 4. _detect_missing_waves 不再推荐 W2.5 ─────────────────
class TestDetectMissingWavesNoW25:
    def test_w25_not_in_missing_waves_for_l4_chain(self) -> None:
        """v5.2: W2.5 不在 find 责任范围, 不再被 _detect_missing_waves 推荐。"""
        from opensquilla.tools.builtin.asset_tree import tree as tools_tree

        # 建一棵 max_depth=5 (URL 触及, L4+) 的树, 应该建议 W1.5 / W1.5c / W3.5
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
        missing = tools_tree._detect_missing_waves(tree)
        # 仍可能建议 W1.5 / W1.5c / W3.5 (但**不**含 W2.5)
        assert "W2.5" not in missing, f"W2.5 仍被建议: {missing}"


# ─── 5. asset_tree_complete 工具集成 (L3 tree 应 raise) ─────────────────
class TestAssetTreeCompleteV52Integration:
    def test_complete_refuses_l3_tree(self, tmp_path, monkeypatch) -> None:
        """L3 树调 complete 应 raise IncompleteSkeletonError, max_depth_required=7。"""
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
        tools_tree._save_tree(tree, "t-l3-v52")

        with pytest.raises(IncompleteSkeletonError) as exc_info:
            import asyncio
            asyncio.run(tools_tree.asset_tree_complete("t-l3-v52"))
        err = exc_info.value
        assert err.max_depth_reached < 7
        assert err.max_depth_required == 7  # v5.2: required = FIND_TERMINATION_DEPTH
        assert "W2.5" not in err.missing_waves  # v5.2: W2.5 不在 find 责任

    def test_complete_succeeds_for_l7_tree(self, tmp_path, monkeypatch) -> None:
        """L7 完整树调 complete 应成功 (find 终止)。"""
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
        tools_tree._save_tree(tree, "t-l7-v52")

        result_str = asyncio_run_safe(tools_tree.asset_tree_complete, "t-l7-v52")
        result = json.loads(result_str)
        assert result["skeleton"]["complete"] is True
        assert result["skeleton"]["find_termination_depth"] == 7
        assert result["skeleton"]["max_depth_reached"] == 7


def asyncio_run_safe(coro_fn, *args, **kwargs):
    """Helper to run a coroutine in a new event loop (pytest-asyncio 兼容)."""
    import asyncio
    return asyncio.run(coro_fn(*args, **kwargs))
