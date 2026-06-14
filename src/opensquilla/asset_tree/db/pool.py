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
        "pool_pre_ping": True,
        "pool_size": kwargs.get("pool_size", 10),
        "max_overflow": kwargs.get("max_overflow", 5),
        "pool_recycle": kwargs.get("pool_recycle", 1800),
        "pool_timeout": kwargs.get("pool_timeout", 30),
    }
    engine_kwargs.update({k: v for k, v in kwargs.items() if k not in engine_kwargs})
    return create_async_engine(url, **engine_kwargs)


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[Any]:
    """Build an async sessionmaker bound to the given engine.

    The session factory is used by ``backend.py`` to acquire per-transaction
    sessions; callers MUST use ``async with session_factory() as session:``
    to ensure cleanup.
    """
    return async_sessionmaker(engine, expire_on_commit=False)
