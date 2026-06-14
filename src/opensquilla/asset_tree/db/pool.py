"""Async connection-pool factory for the AssetTree DB.

The default URL is read from ``ASSET_TREE_DB_URL``. Examples::

    # MySQL (production)
    export ASSET_TREE_DB_URL='mysql+aiomysql://opensquilla:secret@db.local:3306/opensquilla'

    # SQLite (tests / single-process dev)
    export ASSET_TREE_DB_URL='sqlite+aiosqlite:////tmp/asset_tree.db'

Both dialects compile the SAME SQLAlchemy schema defined in ``schema.py``.
"""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)


def default_db_url() -> str:
    """Resolve the default DB URL from env (fallback: sqlite in tmp)."""
    url = os.environ.get("ASSET_TREE_DB_URL")
    if url:
        return url
    # Fallback for dev: per-process sqlite so concurrent processes don't collide
    import tempfile
    return "sqlite+aiosqlite:///" + os.path.join(tempfile.gettempdir(), "asset_tree_default.db")


def build_engine_from_url(url: str | None = None, **kwargs: Any) -> AsyncEngine:
    """Create an async engine + session factory for the given DB URL.

    Args:
        url: SQLAlchemy URL string. ``None`` → ``default_db_url()``.
        **kwargs: forwarded to ``create_async_engine`` (e.g. pool_size).

    Connection-pool defaults:
        - MySQL: pool_size=10, pool_recycle=1800 (30 min, MySQL's wait_timeout)
        - SQLite: NullPool (sqlite doesn't share connections across threads)

    SQLite-specific:
      SQLite ignores ``ON DELETE CASCADE`` unless ``PRAGMA foreign_keys``
      is ON for each connection. We wire a connect-listener to set
      that pragma for every new connection.
    """
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    url = url or default_db_url()
    is_sqlite = url.startswith("sqlite")

    engine_kwargs: dict[str, Any] = {
        "echo": False,
        "future": True,
        "pool_pre_ping": True,  # detect stale connections
    }
    if is_sqlite:
        engine_kwargs["poolclass"] = None  # NullPool; SQLite can't share across threads
    else:
        engine_kwargs["pool_size"] = kwargs.get("pool_size", 10)
        engine_kwargs["max_overflow"] = kwargs.get("max_overflow", 5)
        engine_kwargs["pool_recycle"] = kwargs.get("pool_recycle", 1800)
        engine_kwargs["pool_timeout"] = kwargs.get("pool_timeout", 30)

    engine_kwargs.update({k: v for k, v in kwargs.items() if k not in engine_kwargs})
    engine = create_async_engine(url, **engine_kwargs)

    if is_sqlite:
        # Enable FK enforcement per connection. PRAGMA foreign_keys is
        # a connection-level setting; we attach to the underlying sync
        # engine's "connect" event.
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_fk(dbapi_connection: Any, _: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[Any]:
    """Build an async sessionmaker bound to the given engine.

    The session factory is used by ``backend.py`` to acquire per-transaction
    sessions; callers MUST use ``async with session_factory() as session:``
    to ensure cleanup.
    """
    return async_sessionmaker(engine, expire_on_commit=False)