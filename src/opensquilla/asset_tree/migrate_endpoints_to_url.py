"""One-shot data migration: SERVICE → ENDPOINT  →  SERVICE → URL → ENDPOINT.

旧数据中 ENDPOINT 直接挂在 SERVICE 之下。新约束要求走 URL 中转。
本脚本做一次性改造：

  1. 扫描所有 ``(parent_id -> ENDPOINT)`` 边，且 ``parent`` 是 ``SERVICE``。
  2. 按 SERVICE 聚合：每个 SERVICE 创建（或复用）一个共享的 URL 节点。
     URL 值推断顺序：
       a) SERVICE.metadata.base_url
       b) SERVICE.metadata.url
       c) 父链中 SUB_DOMAIN 的 value + PORT.value → ``https://{sub}:{port}``
     失败兜底：``"https://unknown/{service_value}"``。
  3. 把旧 ENDPOINT 的 parent_id 改为新 URL，记录迁移溯源到 metadata：
     ``{"_migrated_from": "<old_service_id>", "migrated_at": "<iso>"}``。
  4. （可选）把 SERVICE 也重挂到对应的 URL 之下，保持一致层级。
  5. 校验：迁移完成后不存在 ``SERVICE -> ENDPOINT`` 边。

两种使用方式::

    # Python API
    from opensquilla.asset_tree.db import SqliteBackend, build_engine_from_url, build_session_factory
    from opensquilla.asset_tree.migrate_endpoints_to_url import migrate

    engine = build_engine_from_url("sqlite+aiosqlite:///tmp/asset_tree.db")
    factory = build_session_factory(engine)
    backend = SqliteBackend(engine, factory)
    report = asyncio.run(migrate(backend, dry_run=False))
    print(report)

    # CLI
    python -m opensquilla.asset_tree.migrate_endpoints_to_url \
        --url sqlite+aiosqlite:///tmp/asset_tree.db --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from opensquilla.asset_tree.db.backend import AssetTreeBackend

logger = logging.getLogger(__name__)


@dataclass
class MigrationReport:
    trees_scanned: int = 0
    services_touched: int = 0
    urls_created: int = 0
    urls_reused: int = 0
    endpoints_moved: int = 0
    invariants_violated: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trees_scanned": self.trees_scanned,
            "services_touched": self.services_touched,
            "urls_created": self.urls_created,
            "urls_reused": self.urls_reused,
            "endpoints_moved": self.endpoints_moved,
            "invariants_violated": self.invariants_violated,
        }


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _infer_url_value(service_row: dict[str, Any], sub_domain: str | None, port: str | None) -> str:
    """从 service metadata 推断 base URL。

    顺序：base_url → url → https://{sub_domain}:{port} → 兜底。
    """
    meta = service_row.get("metadata") or {}
    for key in ("base_url", "url"):
        v = meta.get(key)
        if isinstance(v, str) and v:
            return v
    if sub_domain:
        port_suffix = f":{port}" if port and port not in ("80", "443") else ""
        return f"https://{sub_domain}{port_suffix}"
    return f"https://unknown/{service_row['value']}"


async def _list_trees(backend: AssetTreeBackend) -> list[str]:
    engine = backend._engine  # type: ignore[attr-defined]
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT tree_id FROM asset_trees"))
        return [r[0] for r in rows]


async def _fetch_service_endpoints(
    backend: AssetTreeBackend, tree_id: str
) -> list[dict[str, Any]]:
    """返回所有需要迁移的 (service_id, endpoint_id) 对。"""
    engine = backend._engine  # type: ignore[attr-defined]
    sql = text(
        """
        SELECT ep.tree_id, ep.id AS ep_id, ep.value AS ep_value, ep.metadata AS ep_meta,
               ep.parent_id AS service_id, ep.material_path AS ep_path, ep.path_depth AS ep_depth,
               svc.value AS svc_value, svc.metadata AS svc_meta
        FROM asset_nodes ep
        JOIN asset_nodes svc
          ON svc.tree_id = ep.tree_id AND svc.id = ep.parent_id
        WHERE ep.tree_id = :tid
          AND ep.asset_type = 'endpoint'
          AND svc.asset_type = 'service'
        """
    )
    async with engine.connect() as conn:
        rows = await conn.execute(sql, {"tid": tree_id})
        return [dict(r._mapping) for r in rows]


async def _fetch_node(backend: AssetTreeBackend, tree_id: str, node_id: str) -> dict[str, Any] | None:
    engine = backend._engine  # type: ignore[attr-defined]
    async with engine.connect() as conn:
        row = await conn.execute(
            text("SELECT * FROM asset_nodes WHERE tree_id=:t AND id=:i"),
            {"t": tree_id, "i": node_id},
        )
        r = row.first()
        return dict(r._mapping) if r else None


async def _walk_to_subdomain(backend: AssetTreeBackend, tree_id: str, service_id: str) -> tuple[str | None, str | None]:
    """沿父链找最近的 sub_domain 与 port。"""
    engine = backend._engine  # type: ignore[attr-defined]
    sql = text(
        """
        WITH RECURSIVE chain(tree_id, id, parent_id, asset_type, value) AS (
            SELECT tree_id, id, parent_id, asset_type, value
            FROM asset_nodes
            WHERE tree_id = :t AND id = :sid
            UNION ALL
            SELECT n.tree_id, n.id, n.parent_id, n.asset_type, n.value
            FROM asset_nodes n
            JOIN chain c ON n.tree_id = c.tree_id AND n.id = c.parent_id
        )
        SELECT asset_type, value FROM chain
        WHERE asset_type IN ('sub_domain', 'port')
        """
    )
    async with engine.connect() as conn:
        rows = await conn.execute(sql, {"t": tree_id, "sid": service_id})
        types = {r[0]: r[1] for r in rows}
    return types.get("sub_domain"), types.get("port")


async def _find_existing_url(
    backend: AssetTreeBackend, tree_id: str, parent_id: str, value: str
) -> str | None:
    engine = backend._engine  # type: ignore[attr-defined]
    async with engine.connect() as conn:
        row = await conn.execute(
            text(
                "SELECT id FROM asset_nodes WHERE tree_id=:t AND parent_id=:p "
                "AND asset_type='url' AND value=:v LIMIT 1"
            ),
            {"t": tree_id, "p": parent_id, "v": value},
        )
        r = row.first()
        return r[0] if r else None


async def _update_parent(backend: AssetTreeBackend, tree_id: str, node_id: str, new_parent: str) -> None:
    engine = backend._engine  # type: ignore[attr-defined]
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE asset_nodes SET parent_id=:np WHERE tree_id=:t AND id=:i"),
            {"np": new_parent, "t": tree_id, "i": node_id},
        )
        # 边表同步：删旧边，插新边
        await conn.execute(
            text("DELETE FROM asset_edges WHERE tree_id=:t AND child_id=:i"),
            {"t": tree_id, "i": node_id},
        )
        # 拿 child_order
        co_row = await conn.execute(
            text(
                "SELECT COALESCE(MAX(child_order),-1)+1 FROM asset_edges "
                "WHERE tree_id=:t AND parent_id=:p"
            ),
            {"t": tree_id, "p": new_parent},
        )
        next_order = co_row.scalar() or 0
        await conn.execute(
            text(
                "INSERT INTO asset_edges (tree_id, parent_id, child_id, child_order) "
                "VALUES (:t, :p, :c, :o)"
            ),
            {"t": tree_id, "p": new_parent, "c": node_id, "o": next_order},
        )


async def _patch_endpoint_meta(
    backend: AssetTreeBackend, tree_id: str, node_id: str, old_service_id: str
) -> None:
    """在 endpoint.metadata 上写入迁移溯源，保留旧字段。"""
    engine = backend._engine  # type: ignore[attr-defined]
    async with engine.begin() as conn:
        # 读现有 metadata (SQLite 端走 JSON 提取)
        row = await conn.execute(
            text("SELECT metadata FROM asset_nodes WHERE tree_id=:t AND id=:i"),
            {"t": tree_id, "i": node_id},
        )
        cur = row.scalar() or "{}"
        # SQLAlchemy JSON 字段在 SQLite 返回 str；在 MySQL 返回 dict。这里统一处理。
        import json as _json
        if isinstance(cur, str):
            meta = _json.loads(cur) if cur else {}
        else:
            meta = dict(cur) if cur else {}
        meta["_migrated_from"] = old_service_id
        meta["migrated_at"] = _utcnow_iso()
        await conn.execute(
            text("UPDATE asset_nodes SET metadata=:m WHERE tree_id=:t AND id=:i"),
            {"m": _json.dumps(meta, ensure_ascii=False), "t": tree_id, "i": node_id},
        )


async def _verify_no_service_to_endpoint(backend: AssetTreeBackend, tree_id: str) -> list[str]:
    """校验不再存在 SERVICE → ENDPOINT 边。返回违规节点 id 列表。"""
    engine = backend._engine  # type: ignore[attr-defined]
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                """
                SELECT ep.id FROM asset_nodes ep
                JOIN asset_nodes svc
                  ON svc.tree_id = ep.tree_id AND svc.id = ep.parent_id
                WHERE ep.tree_id = :t AND ep.asset_type = 'endpoint'
                  AND svc.asset_type = 'service'
                """
            ),
            {"t": tree_id},
        )
        return [r[0] for r in rows]


async def migrate(backend: AssetTreeBackend, *, dry_run: bool = False) -> MigrationReport:
    """执行迁移。``dry_run=True`` 只统计不写库。"""
    report = MigrationReport()
    trees = await _list_trees(backend)
    report.trees_scanned = len(trees)

    for tree_id in trees:
        pairs = await _fetch_service_endpoints(backend, tree_id)
        if not pairs:
            continue

        # 按 service_id 聚合
        by_service: dict[str, list[dict[str, Any]]] = {}
        for p in pairs:
            by_service.setdefault(p["service_id"], []).append(p)

        for service_id, eps in by_service.items():
            report.services_touched += 1
            service_row = await _fetch_node(backend, tree_id, service_id)
            if service_row is None:
                report.invariants_violated.append(f"missing service {service_id}")
                continue
            sub, port = await _walk_to_subdomain(backend, tree_id, service_id)
            url_value = _infer_url_value(service_row, sub, port)

            existing_url = await _find_existing_url(backend, tree_id, service_id, url_value)
            if existing_url:
                url_id = existing_url
                report.urls_reused += 1
            else:
                url_id = _new_id()
                if not dry_run:
                    # 用 backend.add_node 创建 URL
                    # 计算 material_path 与 path_depth
                    parent_path = service_row.get("material_path") or service_id
                    parent_depth = int(service_row.get("path_depth") or 0)
                    await backend.add_node(
                        node_id=url_id,
                        tree_id=tree_id,
                        asset_type="url",
                        value=url_value,
                        state="unseen",
                        parent_id=service_id,
                        material_path=f"{parent_path}/{url_id}",
                        path_depth=parent_depth + 1,
                        metadata={"inferred_from": "service", "source_service_id": service_id},
                    )
                report.urls_created += 1

            for ep in eps:
                if not dry_run:
                    await _update_parent(backend, tree_id, ep["ep_id"], url_id)
                    await _patch_endpoint_meta(backend, tree_id, ep["ep_id"], service_id)
                report.endpoints_moved += 1

        # 校验
        violations = await _verify_no_service_to_endpoint(backend, tree_id)
        if violations:
            report.invariants_violated.extend(
                f"tree={tree_id} service→endpoint remaining: {violations}"
            )

    return report


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asset-tree-migrate-endpoints",
        description="Migrate legacy SERVICE→ENDPOINT edges to SERVICE→URL→ENDPOINT.",
    )
    p.add_argument(
        "--url",
        default=None,
        help="SQLAlchemy DB URL. Defaults to $ASSET_TREE_DB_URL or "
             "sqlite+aiosqlite:///tmp/asset_tree_default.db.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute the migration report without writing anything.",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    return p


async def _amain() -> int:
    args = _build_arg_parser().parse_args()
    logging.basicConfig(
        level=args.log_level, format="%(asctime)s %(levelname)s %(message)s"
    )

    from opensquilla.asset_tree.db.pool import (
        build_engine_from_url,
        build_session_factory,
    )

    engine = build_engine_from_url(args.url)
    factory = build_session_factory(engine)
    url = str(engine.url)
    if url.startswith("sqlite"):
        from opensquilla.asset_tree.db.backend import SqliteBackend
        backend = SqliteBackend(engine, factory)
    else:
        from opensquilla.asset_tree.db.backend import MysqlBackend
        backend = MysqlBackend(engine, factory)

    try:
        report = await migrate(backend, dry_run=args.dry_run)
        for k, v in report.to_dict().items():
            print(f"{k}: {v}")
    finally:
        await backend.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_amain()))
