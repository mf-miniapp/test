"""orchestrator — v6 (2026-06-19) 高层编排入口。

把 create-attack-path + hack-deep + 漏洞写入 + 资产反哺 串起来。
CLI 入口见 ``cli.py`` (TODO)。
"""
from opensquilla.orchestrator.run_attack_paths import (
    BuildAndRunError,
    BuildAndRunOptions,
    RunAttackPathsOptions,
    RunAttackPathsResult,
    build_and_run_attack_paths,
    run_attack_paths,
)

__all__ = [
    "BuildAndRunError",
    "BuildAndRunOptions",
    "RunAttackPathsOptions",
    "RunAttackPathsResult",
    "build_and_run_attack_paths",
    "run_attack_paths",
]
