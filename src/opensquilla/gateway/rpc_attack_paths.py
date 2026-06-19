"""attack_paths.run — gateway RPC handler for v6 attack-path orchestrator.

Web chat slash ``/attack-paths run <tree_id>`` → :func:`rpc_attack_paths_run`
→ :func:`orchestrator.run_attack_paths.build_and_run_attack_paths` →
串行按 attack-path 调 hack-deep。

This module is intentionally thin: it just adapts the gateway ``params``
dict into a :class:`BuildAndRunOptions` and surfaces the result. The
heavy lifting lives in ``orchestrator.run_attack_paths``.
"""

from __future__ import annotations

import logging
from typing import Any

from opensquilla.gateway.rpc import RpcContext, get_dispatcher

logger = logging.getLogger(__name__)

_d = get_dispatcher()


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _as_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        return v or None
    return str(value)


def _as_states(value: Any) -> tuple[str, ...]:
    if value is None:
        return ("unseen", "discovered", "triaged")
    if isinstance(value, (list, tuple)):
        return tuple(str(s).strip() for s in value if str(s).strip())
    if isinstance(value, str):
        return tuple(s.strip() for s in value.split(",") if s.strip())
    return ("unseen", "discovered", "triaged")


@_d.method("attack_paths.run", scope="operator.write")
async def rpc_attack_paths_run(
    params: dict | None, _ctx: RpcContext,
) -> dict[str, Any]:
    """Run v6 attack-path orchestrator on a single AssetTree.

    Expected params
    ---------------

    - ``tree_id`` (str, required) — AssetTree id
    - ``dry_run`` (bool, optional) — skip dispatch, only generate paths
    - ``max_depth`` (int, optional) — default 7
    - ``include_states`` (list|str, optional) — default ``"unseen,discovered,triaged"``
    - ``model`` (str, optional) — LLM model override
    - ``provider`` (str, optional) — LLM provider override
    - ``vuln_extractor`` (str, optional) — default ``"default"``
    - ``auto_approve`` (bool, optional) — default ``True``

    Returns
    -------

    A JSON-friendly dict shaped like :class:`RunAttackPathsResult`:

    .. code-block:: python

        {
            "tree_id": "...",
            "path_count": N,
            "written":   N,
            "completed": N,
            "failed":    N,
            "skipped":   N,
            "vuln_total": N,
            "errors":    [...],
        }

    On bad input (e.g. missing tree_id) the handler raises a :class:`ValueError`
    which the gateway turns into an RPC error.
    """
    if not isinstance(params, dict):
        raise ValueError("params must be a dict")
    tree_id = params.get("tree_id")
    if not isinstance(tree_id, str) or not tree_id.strip():
        raise ValueError("params.tree_id (str) is required")

    from opensquilla.orchestrator.run_attack_paths import (
        BuildAndRunError,
        BuildAndRunOptions,
        build_and_run_attack_paths,
    )

    try:
        result = await build_and_run_attack_paths(BuildAndRunOptions(
            tree_id=tree_id.strip(),
            dry_run=_as_bool(params.get("dry_run"), default=False),
            max_depth=_as_int(params.get("max_depth"), default=7),
            include_states=_as_states(params.get("include_states")),
            model=_as_optional_str(params.get("model")),
            provider=_as_optional_str(params.get("provider")),
            # base_url / api_key let the operator pin a local llama.cpp /
            # vllm / ollama endpoint without editing the gateway config.
            base_url=_as_optional_str(params.get("base_url")),
            api_key=_as_optional_str(params.get("api_key")),
            vuln_extractor=str(params.get("vuln_extractor") or "default"),
            auto_approve=_as_bool(params.get("auto_approve"), default=True),
        ))
    except BuildAndRunError as exc:
        # BuildAndRunError 编码 ``{code}:{msg}``. Strip the leading
        # ``code:`` prefix so the chat surface can present a single,
        # user-friendly message without the surface layer having to
        # re-split it.
        msg = str(exc)
        _, _, body = msg.partition(":")
        raise RuntimeError(body or msg) from exc
    return {
        "tree_id": result.tree_id,
        "path_count": result.path_count,
        "written": result.written,
        "completed": result.completed,
        "failed": result.failed,
        "skipped": result.skipped,
        "vuln_total": result.vuln_total,
        "errors": list(result.errors or []),
    }
