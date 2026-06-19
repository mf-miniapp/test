"""v6 (2026-06-19) orchestrator.run_attack_paths 单测。

覆盖:
  - 空树: 0 paths, 不 dispatch
  - dry_run: 生成 paths, 不 dispatch
  - 单条 path 成功: completed, vuln_count 累加
  - 单条 path 失败: failed, 错误累积, 后续 path 继续
  - 已 completed 的 path 跳过 (幂等)
  - dispatcher 抛异常: 标 failed
"""
from __future__ import annotations

import asyncio
import pytest

from opensquilla.asset_tree.attack_paths import compute_path_hash
from opensquilla.asset_tree.models import AssetState, AssetType
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.orchestrator import (
    RunAttackPathsOptions,
    run_attack_paths,
)
from opensquilla.orchestrator.run_attack_paths import AttackPathOutcome
from tests._stubs.in_memory_backend import InMemoryStubBackend


# ── helpers ───────────────────────────────────────────────


def _add(tree, atype, value, parent):
    return tree.add_node(atype, value, parent_id=parent, allow_unverified=True)


def _build_two_branch_tree() -> AssetTree:
    tree = AssetTree("example.com")
    sub1 = _add(tree, AssetType.SUB_DOMAIN, "a.example.com", tree.root_id)
    sub2 = _add(tree, AssetType.SUB_DOMAIN, "b.example.com", tree.root_id)
    _add(tree, AssetType.IP, "1.1.1.1", sub1)
    _add(tree, AssetType.IP, "2.2.2.2", sub2)
    return tree


class _RecordingDispatcher:
    """记录调用, 返回预设结果, 模拟 hack-deep 接单。"""

    def __init__(self, outcomes: list[AttackPathOutcome] | None = None,
                 default_vuln: int = 0) -> None:
        self.calls: list[dict] = []
        self.outcomes = list(outcomes or [])
        self._default_vuln = default_vuln

    async def dispatch(self, **kwargs) -> AttackPathOutcome:
        self.calls.append(kwargs)
        if self.outcomes:
            return self.outcomes.pop(0)
        return AttackPathOutcome(status="completed", vuln_count=self._default_vuln)


class _BoomDispatcher:
    async def dispatch(self, **kwargs):
        raise RuntimeError("boom")


# ── tests ─────────────────────────────────────────────────


class TestRunAttackPaths:
    def test_empty_tree(self):
        tree = AssetTree("example.com")
        backend = InMemoryStubBackend()
        disp = _RecordingDispatcher()
        result = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp,
        )))
        assert result.path_count == 0
        assert result.completed == 0
        assert result.failed == 0
        assert disp.calls == []

    def test_dry_run(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        disp = _RecordingDispatcher()
        result = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp,
            dry_run=True,
        )))
        assert result.path_count == 2
        assert result.written == 2
        # dry_run 不 dispatch
        assert disp.calls == []

    def test_one_path_completed(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        disp = _RecordingDispatcher(default_vuln=2)
        result = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp,
        )))
        assert result.path_count == 2
        assert result.completed == 2
        assert result.failed == 0
        assert result.vuln_total == 4  # 2 paths * 2 vulns
        assert len(disp.calls) == 2
        for call in disp.calls:
            assert call["edge_count"] == 2
            assert call["leaf_type"] == "ip"
            assert len(call["ancestor_path"]) == 1  # 2 edges, ancestor = first edge

    def test_path_failure_isolated(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        disp = _RecordingDispatcher(outcomes=[
            AttackPathOutcome(status="failed", error="x failed"),
            AttackPathOutcome(status="completed", vuln_count=1),
        ])
        result = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp,
        )))
        assert result.completed == 1
        assert result.failed == 1
        assert result.vuln_total == 1
        assert len(result.errors) == 1
        # 后续 path 仍然跑
        assert len(disp.calls) == 2

    def test_dispatcher_raises_marked_failed(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        disp = _BoomDispatcher()
        result = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp,
        )))
        assert result.completed == 0
        assert result.failed == 2
        assert len(result.errors) == 2
        # path 状态被标 failed
        async def check():
            return await backend.list_attack_paths("tree-example.com")
        stored = asyncio.run(check())
        assert all(r["status"] == "failed" for r in stored)
        assert all(r["error"] and "boom" in r["error"] for r in stored)

    def test_idempotent_skips_completed(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        # 第一次跑
        disp1 = _RecordingDispatcher(default_vuln=1)
        result1 = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp1,
        )))
        assert result1.completed == 2
        # 第二次跑 — 0 pending, 全部 skipped
        disp2 = _RecordingDispatcher()
        result2 = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp2,
        )))
        assert result2.path_count == 2
        assert result2.completed == 0
        assert result2.skipped == 2
        assert disp2.calls == []

    def test_path_status_transitions_recorded(self):
        tree = _build_two_branch_tree()
        backend = InMemoryStubBackend()
        disp = _RecordingDispatcher(default_vuln=3)
        asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="tree-example.com",
            tree=tree, backend=backend, dispatcher=disp,
        )))
        async def check():
            return await backend.list_attack_paths("tree-example.com")
        stored = asyncio.run(check())
        for row in stored:
            assert row["status"] == "completed"
            assert row["vuln_count"] == 3
            assert row["started_at"] is not None
            assert row["completed_at"] is not None
