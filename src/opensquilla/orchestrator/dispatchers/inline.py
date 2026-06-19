"""InlineDispatcher — 单测 / 离线回放用的 AttackPathDispatcher。

不依赖 LLM, 直接给固定 ``AttackPathOutcome``。和 v6 重构
``tests/test_orchestrator_run_attack_paths.py::TestRunAttackPaths`` 里的
``_RecordingDispatcher`` 同思路; 这里抽到包内, 让单测之外的代码也能用
(比如 dry-run replay 历史记录)。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from opensquilla.orchestrator.run_attack_paths import AttackPathOutcome


@dataclass
class InlineOutcome:
    """单条 path 的预录结果 — 喂给 ``InlineDispatcher(outcomes=[...])``。"""
    status: str = "completed"
    vuln_count: int = 0
    error: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None


class InlineDispatcher:
    """按 path_id 顺序消费预录结果 — 单测 / 重放专用。

    行为:
      - 每次 ``dispatch()`` 从 ``outcomes`` 队列头取一个 InlineOutcome,
        包成 ``AttackPathOutcome`` 返回。
      - 队列空 → 永远返回 ``status="completed" vuln_count=0``。
      - ``raise_on`` 设了 path_id → 抛 ``raise_on(path_id)`` 给的异常
        (模拟 hack-deep 接单失败)。
    """

    def __init__(
        self,
        outcomes: list[InlineOutcome] | None = None,
        *,
        default_vuln_count: int = 0,
        raise_on: dict[str, BaseException] | None = None,
    ) -> None:
        self._outcomes = list(outcomes or [])
        self._default_vuln_count = default_vuln_count
        self._raise_on = raise_on or {}
        self.calls: list[dict[str, Any]] = []

    async def dispatch(
        self,
        *,
        path_id: str,
        tree_id: str,
        scope_string: str,
        leaf_node_id: str,
        leaf_type: str,
        leaf_value: str,
        edge_count: int,
        ancestor_path: list[dict[str, Any]],
    ) -> AttackPathOutcome:
        self.calls.append({
            "path_id": path_id, "tree_id": tree_id,
            "leaf_node_id": leaf_node_id, "leaf_value": leaf_value,
            "leaf_type": leaf_type, "edge_count": edge_count,
            "scope": scope_string, "ancestor_path": ancestor_path,
        })
        if path_id in self._raise_on:
            raise self._raise_on[path_id]
        if self._outcomes:
            pre = self._outcomes.pop(0)
            return AttackPathOutcome(
                status=pre.status,
                vuln_count=pre.vuln_count,
                error=pre.error,
                evidence=pre.evidence,
            )
        return AttackPathOutcome(
            status="completed", vuln_count=self._default_vuln_count,
        )
