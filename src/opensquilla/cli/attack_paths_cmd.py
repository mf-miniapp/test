"""CLI: opensquilla attack-paths — v6 (2026-06-19) 按 attack-path 攻击入口。

```
opensquilla attack-paths run <tree_id> [--dry-run] [--max-depth N]
                                  [--include-states s1,s2,...]
                                  [--model M] [--provider P]
```

工作流:
  1. 从 MySQL 读 AssetTree (id = <tree_id>)
  2. 调 ``orchestrator.run_attack_paths`` 串行跑所有 L0..L7 路径
  3. 每条 path 通过 ``SessionsSpawnDispatcher`` 调 LLM
  4. 写 vulnerabilities + 反哺 vuln_node_vulns
  5. 输出 summary (path_count, completed, failed, vuln_total)
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import typer

from opensquilla.cli.ui import console


logger = logging.getLogger(__name__)


attack_paths_app = typer.Typer(
    help="v6 attack-path orchestrator: run L0..L7 paths serially through hack-deep.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


def _print_summary(result) -> None:
    """Print a compact summary table. 兼容 RunAttackPathsResult 形状。"""
    console.print(
        f"\n[bold]attack-paths run summary[/bold]\n"
        f"  tree_id    : {result.tree_id}\n"
        f"  path_count : {result.path_count}\n"
        f"  written    : {result.written}\n"
        f"  completed  : [green]{result.completed}[/green]\n"
        f"  failed     : [red]{result.failed}[/red]\n"
        f"  skipped    : {result.skipped}\n"
        f"  vuln_total : [cyan]{result.vuln_total}[/cyan]\n"
    )
    if result.errors:
        console.print("[yellow]errors:[/yellow]")
        for e in result.errors[:20]:
            console.print(f"  - {e}")
        if len(result.errors) > 20:
            console.print(f"  ... +{len(result.errors) - 20} more")


@attack_paths_app.command("run")
def attack_paths_run(
    tree_id: str = typer.Argument(..., help="AssetTree id (e.g. 'tree-example.com')."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Generate attack paths but do not dispatch.",
    ),
    max_depth: int = typer.Option(7, "--max-depth", help="Max path depth (default L7)."),
    include_states: str = typer.Option(
        "unseen,discovered,triaged",
        "--include-states",
        help="Comma-separated asset states to consider for attack.",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", help="LLM model override (e.g. 'claude-sonnet-4-20250514').",
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", help="LLM provider name override.",
    ),
    vuln_extractor: str = typer.Option(
        "default", "--vuln-extractor",
        help="Vulnerability extractor impl ('default' = structured + regex).",
    ),
    auto_approve: bool = typer.Option(
        True, "--auto-approve/--no-auto-approve",
        help="Auto-approve specialist tool calls (v3.3 hack-deep).",
    ),
) -> None:
    """Run v6 attack-path orchestrator on a single AssetTree.

    Thin wrapper over :func:`orchestrator.run_attack_paths.build_and_run_attack_paths`
    so the CLI / RPC / TUI surfaces stay in lockstep.
    """
    from opensquilla.orchestrator.run_attack_paths import (
        BuildAndRunError,
        BuildAndRunOptions,
        build_and_run_attack_paths,
    )

    states = tuple(s.strip() for s in include_states.split(",") if s.strip())

    async def _run() -> int:
        try:
            result = await build_and_run_attack_paths(BuildAndRunOptions(
                tree_id=tree_id, dry_run=dry_run,
                max_depth=max_depth, include_states=states,
                model=model, provider=provider,
                vuln_extractor=vuln_extractor, auto_approve=auto_approve,
            ))
        except BuildAndRunError as exc:
            msg = str(exc)
            if msg.startswith("2:"):
                console.print(f"[red]{msg[2:]}[/red]")
                return 2
            if msg.startswith("3:"):
                console.print(f"[red]{msg[2:]}[/red]")
                return 3
            if msg.startswith("4:"):
                console.print(f"[red]{msg[2:]}[/red]")
                return 4
            console.print(f"[red]{msg}[/red]")
            return 1
        _print_summary(result)
        return 0 if result.failed == 0 else 1

    raise typer.Exit(asyncio.run(_run()))


@attack_paths_app.command("list")
def attack_paths_list(
    tree_id: Optional[str] = typer.Option(
        None, "--tree-id", help="Filter by tree id.",
    ),
    status: Optional[str] = typer.Option(
        None, "--status", help="Filter by status (pending/in_progress/completed/failed/abandoned).",
    ),
) -> None:
    """List attack paths (table)."""
    from opensquilla.asset_tree.db import get_default_backend

    async def _run() -> None:
        be = get_default_backend()
        rows = await be.list_attack_paths(tree_id, status=status) if tree_id else []
        if not tree_id:
            console.print("[yellow]cross-tree listing not yet supported; pass --tree-id[/yellow]")
            return
        if not rows:
            console.print("[dim]no attack paths[/dim]")
            return
        for r in rows:
            console.print(
                f"  {r['path_id']}  {r['status']:<12}  "
                f"leaf={r['leaf_type']}={r['leaf_value']}  "
                f"vulns={r.get('vuln_count', 0)}"
            )
    asyncio.run(_run())
