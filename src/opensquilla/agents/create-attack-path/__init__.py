"""create-attack-path — 把一棵资产树的所有 L0..L7 路径打包成 AttackPath 列表。

v1.0 (2026-06-19): v6 重构新增的 specialist-like 编排辅助 agent,
接受一个 tree_id, 调 ``AssetTree.enumerate_root_to_leaf_paths`` 枚举
全部根到叶路径, 写 ``vuln_attack_paths`` 表 (status=pending), 输
出 ``attack-path-list-v1`` envelope 给上层 orchestrator 串行消费。

本 agent **不**做漏洞扫描 / 攻击执行, 也不 spawn 任何 specialist —
它只"读树, 列边, 写表"。编排器 (orchestrator/run_attack_paths.py)
拿到 ``attack-path-list-v1`` 后逐条 sessions_spawn(hack-deep, ...)。
"""
from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent

SOUL_BODY: str = ""
ATTRIBUTION_BODY: str = ""


def _load() -> None:
    global SOUL_BODY, ATTRIBUTION_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")
    ATTRIBUTION_BODY = (_HERE / "ATTRIBUTION_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    _load()


_load()

__all__ = ["SOUL_BODY", "ATTRIBUTION_BODY", "reload"]
