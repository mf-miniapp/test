"""Async connection-pool factory for the AssetTree DB.

The DB URL is read from ``ASSET_TREE_DB_URL`` and MUST be a MySQL
``mysql+aiomysql://`` URL — SQLite is not supported by AssetTree.

Examples::

    export ASSET_TREE_DB_URL='mysql+aiomysql://opensquilla:secret@db.local:3306/opensquilla'
"""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)


class AssetTreeConfigError(RuntimeError):
    """Raised when AssetTree is asked to use an unsupported DB dialect.

    AssetTree only supports MySQL (production). SQLite URLs are rejected
    at the factory boundary to prevent accidental misuse.
    """


def default_db_url() -> str:
    """Resolve the default DB URL from ``ASSET_TREE_DB_URL``.

    Raises:
        AssetTreeConfigError: if the env var is unset/empty, or points
            to a non-MySQL URL. AssetTree is MySQL-only.
    """
    url = os.environ.get("ASSET_TREE_DB_URL", "").strip()
    if not url:
        raise AssetTreeConfigError(
            "ASSET_TREE_DB_URL is not set. AssetTree requires a MySQL URL, "
            "e.g. 'mysql+aiomysql://user:pass@host:3306/opensquilla'."
        )
    if not url.startswith("mysql"):
        raise AssetTreeConfigError(
            f"AssetTree only supports MySQL (got URL: {url!r}). "
            "Set ASSET_TREE_DB_URL to a 'mysql+aiomysql://...' connection string."
        )
    return url


def build_engine_from_url(url: str | None = None, **kwargs: Any) -> AsyncEngine:
    """Create an async engine for the given MySQL DB URL.

    Args:
        url: SQLAlchemy URL string. ``None`` → ``default_db_url()``.
        **kwargs: forwarded to ``create_async_engine`` (e.g. pool_size).

    Connection-pool defaults (MySQL only):
        - pool_size=10
        - max_overflow=5
        - pool_recycle=1800 (30 min, MySQL's wait_timeout)
        - pool_timeout=30
        - pool_pre_ping=True
    """
    url = url or default_db_url()
    if not url.startswith("mysql"):
        raise AssetTreeConfigError(
            f"AssetTree only supports MySQL (got URL: {url!r})."
        )

    engine_kwargs: dict[str, Any] = {
        "echo": False,
        "future": True,
        # pool_pre_ping defaults to False: SQLAlchemy 2.x ``do_ping`` is
        # incompatible with ``aiomysql``'s async ``ping()`` (the dialect
        # adapter passes no ``reconnect`` kwarg, and the aiomysql coroutine
        # requires one). Disable pre-ping; the MySQL server's wait_timeout
        # is handled by ``pool_recycle`` instead.
        "pool_pre_ping": False,
        # Use ``NullPool`` so a single engine can be reused across
        # multiple asyncio event loops (uvicorn workers + any
        # background tasks). ``aiomysql``'s connection binds to the
        # loop that first ``await``s it; a static ``QueuePool`` would
        # fail with ``Future attached to a different loop`` on the
        # second event loop. ``NullPool`` opens & closes per-checkout,
        # which is fine for the asset-tree read/write pattern (low
        # concurrency, long-lived gateway).
        "poolclass": __import__("sqlalchemy.pool", fromlist=["NullPool"]).NullPool,
    }
    return create_async_engine(url, **engine_kwargs)


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[Any]:
    """Build an async sessionmaker bound to the given engine.

    The session factory is used by ``backend.py`` to acquire per-transaction
    sessions; callers MUST use ``async with session_factory() as session:``
    to ensure cleanup.
    """
    return async_sessionmaker(engine, expire_on_commit=False)
