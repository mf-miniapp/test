"""One-shot migration: ~/.opensquilla/state/asset_trees/*.json -> MySQL.

Idempotent (INSERT ... ON DUPLICATE KEY UPDATE). Safe to re-run.
Fixes the Z-suffix ISO datetime bug by parsing strings to datetime objects.
"""
import asyncio
import json as _json
import os
import sys
from datetime import datetime
from pathlib import Path

# Ensure project root on path so we can import the package.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault(
    "ASSET_TREE_DB_URL",
    "mysql+aiomysql://vulnark:zZcC123456%21%40%23%24%25%5E@127.0.0.1:3306/opensquilla",
)

from sqlalchemy.dialects.mysql import insert as mysql_insert  # noqa: E402

from opensquilla.asset_tree.db import schema as _schema  # noqa: E402
from opensquilla.asset_tree.db.backend import MysqlBackend  # noqa: E402
from opensquilla.asset_tree.db.pool import (  # noqa: E402
    build_engine_from_url,
    build_session_factory,
)

SRC = Path.home() / ".opensquilla" / "state" / "asset_trees"


def _parse_dt(value):
    """ISO 8601 with optional Z suffix -> datetime (or None)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        s = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


async def _migrate_one(engine, be, fp: Path) -> dict:
    with open(fp) as f:
        data = _json.load(f)
    tree_id = fp.stem
    root_id = data.get("root_id")
    nodes = data.get("nodes") or {}
    edges = data.get("edges") or {}
    if not root_id or root_id not in nodes:
        return {"tree_id": tree_id, "skipped": True, "reason": "no root"}

    root_domain = nodes[root_id].get("value", "<unknown>")
    await be.upsert_tree(
        tree_id=tree_id,
        root_domain=root_domain,
        root_node_id=root_id,
        description=f"Imported from {fp.name} ({datetime.utcnow().date()})",
    )

    inserted_nodes = 0
    async with engine.begin() as conn:
        for nid, nd in nodes.items():
            row = {
                "tree_id": tree_id,
                "id": nid,
                "asset_type": nd.get("asset_type", "generic"),
                "value": (nd.get("value") or "")[:2048],
                "state": nd.get("state", "unseen"),
                "parent_id": nd.get("parent_id") or "",
                "material_path": nd.get("material_path", f"/{nid}"),
                "path_depth": int(nd.get("path_depth") or 0),
                "source_wave": nd.get("source_wave"),
                "assigned_wave": nd.get("assigned_wave"),
                "metadata": _json.dumps(nd.get("metadata") or {}),
                "first_seen": _parse_dt(nd.get("first_seen")),
                "last_seen": _parse_dt(nd.get("last_seen")),
            }
            stmt = mysql_insert(_schema.asset_nodes).values(row)
            stmt = stmt.on_duplicate_key_update(
                value=stmt.inserted.value,
                state=stmt.inserted.state,
                last_seen=stmt.inserted.last_seen,
                metadata=stmt.inserted.metadata,
            )
            result = await conn.execute(stmt)
            inserted_nodes += result.rowcount

        for parent_id, child_ids in edges.items():
            for order, cid in enumerate(child_ids):
                row = {
                    "tree_id": tree_id,
                    "parent_id": parent_id,
                    "child_id": cid,
                    "child_order": order,
                }
                stmt = mysql_insert(_schema.asset_edges).values(row)
                stmt = stmt.on_duplicate_key_update(
                    child_order=stmt.inserted.child_order,
                )
                await conn.execute(stmt)

    stats = await be.stats(tree_id)
    return {
        "tree_id": tree_id,
        "root_domain": root_domain,
        "input_nodes": len(nodes),
        "input_edges": sum(len(v) for v in edges.values()),
        "db_total": stats.get("total_nodes"),
        "db_depth": stats.get("depth"),
    }


async def main() -> int:
    if not SRC.is_dir():
        print(f"source dir not found: {SRC}", file=sys.stderr)
        return 1
    files = sorted(SRC.glob("*.json"))
    if not files:
        print(f"no JSON files in {SRC}")
        return 0

    engine = build_engine_from_url(os.environ["ASSET_TREE_DB_URL"])
    factory = build_session_factory(engine)
    be = MysqlBackend(engine=engine, session_factory=factory)

    print(f"migrating {len(files)} tree JSON file(s) from {SRC}")
    for fp in files:
        result = await _migrate_one(engine, be, fp)
        print(f"  {result}")
    await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
