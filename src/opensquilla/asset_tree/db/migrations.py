"""Idempotent AssetTree schema migration.

``migrate()`` creates all tables + indexes if missing. Safe to re-run.

Usage::

    # Python API
    from opensquilla.asset_tree.db import MysqlBackend, build_engine_from_url
    from opensquilla.asset_tree.db.migrations import migrate
    engine = build_engine_from_url('mysql+aiomysql://...')
    backend = MysqlBackend(engine, ...)
    await migrate(backend)

    # CLI (script)
    python -m opensquilla.asset_tree.db.migrations --url 'mysql+aiomysql://...'
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from opensquilla.asset_tree.db.backend import AssetTreeBackend


logger = logging.getLogger(__name__)


async def migrate(backend: AssetTreeBackend) -> None:
    """Create the schema if missing. Idempotent."""
    await backend.init_schema()
    logger.info("asset_tree_migrate_ok", backend=type(backend).__name__)


async def reset(backend: AssetTreeBackend) -> None:
    """Drop and recreate. DESTRUCTIVE — tests only."""
    await backend.drop_schema()
    await backend.init_schema()
    logger.info("asset_tree_reset_ok", backend=type(backend).__name__)


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asset-tree-migrate",
        description="Run AssetTree DB migrations (idempotent CREATE TABLE).",
    )
    p.add_argument(
        "--url",
        default=None,
        help="SQLAlchemy DB URL. Defaults to $ASSET_TREE_DB_URL or "
             "sqlite+aiosqlite:///tmp/asset_tree_default.db.",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="DROP all tables first (DESTRUCTIVE — tests only).",
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
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(message)s",
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
        if args.reset:
            await reset(backend)
            print(f"Reset complete on {url}")
        else:
            await migrate(backend)
            print(f"Migration complete on {url}")
    finally:
        await backend.close()
    return 0


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    sys.exit(main())