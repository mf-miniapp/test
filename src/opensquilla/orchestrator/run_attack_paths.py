"""run_attack_paths — 串行按 attack-path 攻击主循环 (v6, 2026-06-19)。

本模块是 ``hack-deep`` 编排链路的 v6 入口:

```
                  ┌─────────────────────────┐
                  │ orchestrator            │
                  │  .run_attack_paths()    │
                  └──────┬──────────────────┘
                         │
            ┌────────────▼──────────────┐
            │ create-attack-path agent   │  一次, 写 vuln_attack_paths
            └────────────┬──────────────┘
                         │ list pending paths
            ┌────────────▼──────────────┐
            │ for path in pending:        │
            │   hack-deep.attack-path    │  串行, 1 条 1 个 sessions_spawn
            │   write vulns + feed back  │
            └───────────────────────────┘
```

设计要点:
  - **纯 Python 编排**: 不直接调 sessions_spawn, 通过
    ``AttackPathDispatcher`` 抽象注入 (生产用 sessions_spawn,
    测试用 InMemoryDispatcher)。这样本模块不依赖运行时 event loop,
    也好做单测。
  - **幂等**: 重跑 run_attack_paths 不会重跑已 completed 的 path
    (state machine: pending → in_progress → completed/failed)。
  - **失败隔离**: 单条 path 失败不影响后续 path; 每条 path 单独
    标记 status, 不批量回滚。

Public surface
==============

- ``RunAttackPathsOptions`` — 参数 (tree_id, max_depth, include_states, dry_run)
- ``RunAttackPathsResult``   — 结果 (path_count, completed, failed, vuln_total)
- ``run_attack_paths(...)``  — 主入口, 同步 API
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Protocol

from opensquilla.asset_tree.attack_paths import (
    create_attack_paths_for_tree,
)
from opensquilla.asset_tree.db.backend import AssetTreeBackend
from opensquilla.asset_tree.tree import AssetTree


logger = logging.getLogger(__name__)


# ── 类型 ────────────────────────────────────────────────


class AttackPathDispatcher(Protocol):
    """hack-deep 接单抽象 — 生产用 sessions_spawn, 测试用 inline mock。"""

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
    ) -> "AttackPathOutcome":
        ...


@dataclass(frozen=True)
class AttackPathOutcome:
    """hack-deep 接单后的结果。"""
    status: str                        # "completed" | "failed"
    vuln_count: int = 0
    error: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None


@dataclass
class RunAttackPathsOptions:
    tree_id: str
    tree: AssetTree                        # 已经组装好的 AssetTree
    backend: AssetTreeBackend
    dispatcher: AttackPathDispatcher
    max_depth: int = 7
    include_states: tuple = (
        "unseen", "discovered", "triaged",
    )
    dry_run: bool = False                  # True = 只生成 paths 不攻击


@dataclass
class RunAttackPathsResult:
    tree_id: str
    path_count: int = 0
    written: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    vuln_total: int = 0
    errors: list[str] = field(default_factory=list)


# ── 主入口 ────────────────────────────────────────────────


async def run_attack_paths(opts: RunAttackPathsOptions) -> RunAttackPathsResult:
    """主入口: 1) 生成 paths  2) 串行 dispatch  3) 收口汇总。"""
    result = RunAttackPathsResult(tree_id=opts.tree_id)

    # ── Step 1: create-attack-path agent ─────────────────────
    summary = await create_attack_paths_for_tree(
        tree=opts.tree,
        backend=opts.backend,
        tree_id=opts.tree_id,
        max_depth=opts.max_depth,
    )
    result.path_count = summary["path_count"]
    result.written = summary["written"]
    if not summary["paths"]:
        logger.info("run_attack_paths: tree_id=%s has 0 paths; nothing to do",
                    opts.tree_id)
        return result

    if opts.dry_run:
        logger.info("run_attack_paths: dry_run=True; skipping dispatch")
        return result

    # ── Step 2: 读已写入的 paths, 过滤出 pending (跳过 completed) ─────
    stored = await opts.backend.list_attack_paths(opts.tree_id)
    # 稳定顺序: 按 path_id (确定性, 方便 diff)
    pending = sorted(
        (r for r in stored if r.get("status") == "pending"),
        key=lambda r: r["path_id"],
    )
    skipped = sum(1 for r in stored if r.get("status") in {"completed", "failed", "abandoned"})
    result.skipped = skipped

    # ── Step 3: 串行 dispatch ──────────────────────────────────
    for row in pending:
        path_id = row["path_id"]
        try:
            outcome = await _dispatch_one(opts, row)
        except Exception as exc:  # noqa: BLE001
            logger.exception("dispatch failed for path_id=%s", path_id)
            result.failed += 1
            result.errors.append(f"{path_id}: {exc!r}")
            await _mark_path_status(
                opts.backend, path_id,
                status="failed", error=repr(exc),
            )
            continue

        if outcome.status == "completed":
            result.completed += 1
            result.vuln_total += outcome.vuln_count
            await _mark_path_status(
                opts.backend, path_id,
                status="completed", vuln_count=outcome.vuln_count,
                mark_completed=True,
            )
        else:
            result.failed += 1
            result.errors.append(f"{path_id}: {outcome.error or 'unknown'}")
            await _mark_path_status(
                opts.backend, path_id,
                status="failed", error=outcome.error,
            )

    return result


async def _dispatch_one(
    opts: RunAttackPathsOptions, row: dict[str, Any],
) -> AttackPathOutcome:
    """对单条 path: in_progress → dispatcher.dispatch → outcome."""
    path_id = row["path_id"]
    await _mark_path_status(opts.backend, path_id, status="in_progress",
                            mark_started=True)
    # 解析 edge_chain_json → ancestor_path (去掉最后一条 — leaf 边)
    ecj = row.get("edge_chain_json") or {}
    if isinstance(ecj, str):
        import json
        try:
            ecj = json.loads(ecj)
        except Exception:
            ecj = {}
    edges = (ecj or {}).get("edges", [])
    ancestor = edges[:-1] if len(edges) > 1 else []
    return await opts.dispatcher.dispatch(
        path_id=path_id,
        tree_id=row["tree_id"],
        scope_string=row["scope_string"],
        leaf_node_id=row["leaf_node_id"],
        leaf_type=row["leaf_type"],
        leaf_value=row["leaf_value"],
        edge_count=len(edges),
        ancestor_path=ancestor,
    )


async def _mark_path_status(
    backend: AssetTreeBackend, path_id: str, *,
    status: str,
    vuln_count: Optional[int] = None,
    error: Optional[str] = None,
    mark_started: bool = False,
    mark_completed: bool = False,
) -> None:
    """代理 backend.update_attack_path_status, 捕获异常 (静默写)."""
    try:
        await backend.update_attack_path_status(
            path_id=path_id, status=status,
            vuln_count=vuln_count, error=error,
            mark_started=mark_started, mark_completed=mark_completed,
        )
    except Exception:
        logger.exception("update_attack_path_status failed path_id=%s", path_id)


# ── 高层 helper: CLI / RPC / TUI 共用的"配 dispatcher + 跑"封装 ──────────


@dataclass
class BuildAndRunOptions:
    """``build_and_run_attack_paths`` 的输入。

    字段跟 CLI / RPC 的入参尽量对齐, 避免各 surface 重复定义。
    """
    tree_id: str
    dry_run: bool = False
    max_depth: int = 7
    include_states: tuple[str, ...] = (
        "unseen", "discovered", "triaged",
    )
    model: Optional[str] = None
    provider: Optional[str] = None
    # base_url / api_key let callers force a specific endpoint without
    # editing ``~/.opensquilla/config.toml``.  Useful for the chat-flow
    # "/attack-paths" slash where the operator wants the run to use a
    # local llama.cpp / vllm / ollama server instead of the gateway's
    # default provider.
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    vuln_extractor: str = "default"
    auto_approve: bool = True


class BuildAndRunError(RuntimeError):
    """``build_and_run_attack_paths`` 失败时的统一异常。"""


def _err(msg: str, code: int = 1) -> "BuildAndRunError":
    return BuildAndRunError(f"{code}:{msg}")


async def build_and_run_attack_paths(
    opts: BuildAndRunOptions,
) -> "RunAttackPathsResult":
    """根据 opts 装配 dispatcher + 调 ``run_attack_paths``。

    复用入口: CLI ``opensquilla attack-paths run`` /
    Gateway RPC ``attack_paths.run`` / TUI ``/attack-paths`` 都走它,
    避免 surface 之间逻辑漂移。

    错误约定
    --------
    - 树不存在          -> ``BuildAndRunError(code=2)``
    - LLM provider 没配  -> ``BuildAndRunError(code=3)``
    - vuln_extractor 错 -> ``BuildAndRunError(code=4)``

    内部 ``run_attack_paths`` 返回值正常透传; 单条 path 失败不影响其它。
    """
    from opensquilla.asset_tree.db import get_default_backend
    from opensquilla.asset_tree.web.store import TreeStore
    from opensquilla.orchestrator.dispatchers import (
        InlineDispatcher,
        SessionsSpawnDispatcher,
        SessionsSpawnDispatcherOptions,
    )
    from opensquilla.orchestrator.dispatchers.sessions_spawn import (
        SessionsSpawnDispatcher as _SSD,
        _DefaultVulnWriter,
    )
    from opensquilla.orchestrator.evidence_parser import (
        DefaultVulnerabilityExtractor,
    )

    backend = get_default_backend()
    tree_row = await backend.get_tree(opts.tree_id)
    if tree_row is None:
        raise _err(f"tree '{opts.tree_id}' not found", code=2)

    store = TreeStore()
    try:
        tree = await store.get_tree(opts.tree_id)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"failed to load tree: {exc!r}", code=2) from exc

    # 配 dispatcher
    if opts.dry_run:
        dispatcher: Any = InlineDispatcher()
    else:
        # 配 LLMProvider + model (跟 CLI 行为一致)
        import os as _os
        from opensquilla.gateway.config import GatewayConfig
        from opensquilla.provider.selector import ModelSelector, build_provider
        try:
            # ``GatewayConfig.load()`` auto-discovers config (CLI flag >
            # cwd/opensquilla.toml > ~/.opensquilla/config.toml).  Passing
            # ``None`` keeps the discovery behaviour but avoids a hard
            # crash if no config file exists (Pydantic Settings then
            # applies env-var overrides + built-in defaults).
            cfg = GatewayConfig.load()
            # ``cfg.llm`` is a ``LlmProviderConfig`` (settings-style), but
            # the provider layer expects a plain ``ProviderConfig``
            # dataclass.  Project the relevant fields explicitly so the
            # types line up regardless of which Pydantic settings
            # surfaces extra fields the runtime doesn't need.
            from opensquilla.provider.selector import (
                ProviderConfig,
                build_provider as _build_provider_from_config,
            )
            llm_cfg = cfg.llm
            # ``opts`` wins over ``cfg.llm`` so the chat-flow slash
            # command can pin a local qwen3.6 endpoint without forcing
            # the operator to rewrite ``~/.opensquilla/config.toml``.
            provider_cfg = ProviderConfig(
                provider=opts.provider or llm_cfg.provider,
                model=opts.model or llm_cfg.model,
                api_key=opts.api_key if opts.api_key is not None else llm_cfg.api_key,
                base_url=opts.base_url or llm_cfg.base_url,
                proxy=llm_cfg.proxy,
                provider_routing=dict(llm_cfg.provider_routing or {}),
            )
            llm_provider = _build_provider_from_config(
                provider=provider_cfg.provider,
                model=provider_cfg.model,
                api_key=provider_cfg.api_key,
                base_url=provider_cfg.base_url,
            )
            model_id = opts.model or _os.environ.get(
                "OPEN_SQUILLA_HACK_DEEP_MODEL", "claude-sonnet-4-20250514",
            )
        except Exception as exc:  # noqa: BLE001
            raise _err(f"failed to build LLM provider: {exc!r}", code=3) from exc

        # 配 vulnerability extractor
        if opts.vuln_extractor == "default":
            extractor: Any = DefaultVulnerabilityExtractor()
        else:
            raise _err(f"unknown vuln_extractor: {opts.vuln_extractor}", code=4)

        # 配 vuln writer (写到 backend)
        writer: Any = _DefaultVulnWriter(backend=backend)
        system_prompt = _SSD.build_default_system_prompt()
        dispatcher = SessionsSpawnDispatcher(SessionsSpawnDispatcherOptions(
            provider=llm_provider, model=model_id,
            system_prompt=system_prompt,
            auto_approve=opts.auto_approve,
            vuln_extractor=extractor,
            vuln_writer=writer,
        ))

    return await run_attack_paths(RunAttackPathsOptions(
        tree_id=opts.tree_id, tree=tree, backend=backend,
        dispatcher=dispatcher,
        max_depth=opts.max_depth, include_states=opts.include_states,
        dry_run=opts.dry_run,
    ))


__all__ = [
    "AttackPathDispatcher",
    "AttackPathOutcome",
    "RunAttackPathsOptions",
    "RunAttackPathsResult",
    "run_attack_paths",
    "BuildAndRunOptions",
    "BuildAndRunError",
    "build_and_run_attack_paths",
]
