"""v6 (2026-06-19) AttackPath 生成 / 反哺 helper。

`create_attack_paths_for_tree` 是 create-attack-path agent 的核心
实现: 拿到 (tree, backend, tree_id), 枚举全树 L0..L7 路径, 写入
``vuln_attack_paths`` 表 (靠 path_hash UNIQUE 约束做幂等), 返回
AttackPathList 摘要。

不依赖 sessions_spawn / LLM, 可被 orchestrator / CLI / 测试直接调。
"""
from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from opensquilla.asset_tree.db.backend import AssetTreeBackend
from opensquilla.asset_tree.models import (
    AttackPath,
    AttackPathStatus,
)
from opensquilla.asset_tree.tree import AssetTree


def compute_path_hash(edges: list) -> str:
    """稳定 SHA1 hex, 与 AttackPath.compute_path_id 互补 — 这里只算
    edge chain 的指纹, 用于 vuln_attack_paths.path_hash UNIQUE 索引。
    """
    buf = "|".join(
        f"{e.from_node_id}->{e.to_node_id}:{e.from_type.value}:{e.to_type.value}:{e.from_value}:{e.to_value}"
        for e in edges
    )
    return hashlib.sha1(buf.encode("utf-8")).hexdigest()


async def create_attack_paths_for_tree(
    *,
    tree: AssetTree,
    backend: AssetTreeBackend,
    tree_id: str,
    max_depth: int = 7,
) -> dict[str, Any]:
    """枚举 tree 的所有 root→leaf 路径, 写入 vuln_attack_paths, 返回摘要。

    Returns:
        dict 含 ``path_count``, ``leaf_type_histogram``, ``paths`` (list of
        summary dicts), ``warnings``。这是给 AttackPathListEvidence 用
        的纯 dict, 不带 Pydantic 包装, 方便序列化。

    Raises:
        ValueError: tree_id 与 tree 不一致 / tree 没有 root。
    """
    # ``AssetTree.from_dict`` does not populate ``_tree_id`` (it bypasses
    # ``__init__``), so we use ``getattr`` for the consistency check.
    tree_internal_id = getattr(tree, "_tree_id", None)
    if tree_internal_id and tree_id != tree_internal_id:
        raise ValueError(
            f"tree_id mismatch: tree._tree_id={tree_internal_id!r} vs "
            f"caller tree_id={tree_id!r}"
        )

    paths: list[AttackPath] = tree.enumerate_root_to_leaf_paths(
        max_depth=max_depth,
    )

    # 写表 — 幂等 (path_hash UNIQUE)
    written = 0
    for p in paths:
        path_hash = compute_path_hash(p.edges)
        await backend.upsert_attack_path(
            path_id=p.path_id,
            tree_id=tree_id,
            path_hash=path_hash,
            status="pending",
            scope_string=p.scope_string,
            edge_chain_json={"edges": [e.model_dump(mode="json") for e in p.edges]},
            leaf_node_id=p.leaf_node_id,
            leaf_type=p.leaf_type.value,
            leaf_value=p.leaf_value,
            metadata=p.metadata,
        )
        written += 1

    histogram = Counter(p.leaf_type.value for p in paths)

    return {
        "tree_id": tree_id,
        "path_count": len(paths),
        "written": written,
        "leaf_type_histogram": dict(histogram),
        "paths": [
            {
                "path_id": p.path_id,
                "leaf_type": p.leaf_type.value,
                "leaf_value": p.leaf_value,
                "scope_string": p.scope_string,
                "edge_count": len(p.edges),
            }
            for p in paths
        ],
        "warnings": _build_warnings(tree, max_depth),
    }


def _build_warnings(tree: AssetTree, max_depth: int) -> list[str]:
    out: list[str] = []
    max_reached = tree.max_depth_reached()
    if max_reached is not None and max_reached < max_depth:
        out.append(
            f"max_depth_reached={max_reached} < max_depth={max_depth}; "
            f"some paths may terminate short of L{max_depth}."
        )
    if len(tree) == 1:
        out.append("empty tree (only root, no children)")
    return out
