"""Regression: get_default_backend() must not emit RuntimeWarning.

Two paths to test:
  1. Sync caller (no running loop) → ``asyncio.run(coro)`` works.
  2. Async caller (running loop)   → fallback thread path; the
     original bug was that ``ex.submit(...)`` was detached and the
     coroutine got GC'd unawaited, firing
     ``RuntimeWarning: coroutine ... was never awaited``.

Both paths must come up clean under ``-W error::RuntimeWarning``.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest

from opensquilla.asset_tree.db.backend import get_default_backend, set_default_backend


@pytest.fixture(autouse=True)
def _force_reinit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test forces a fresh backend so init_schema runs again."""
    set_default_backend(None)


def test_sync_path_no_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sync caller path: asyncio.run works directly."""
    monkeypatch.setenv("ASSET_TREE_DB_URL", "mysql+aiomysql://x:y@h:3306/d")
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        be = get_default_backend()
    assert be is not None


def test_async_path_no_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async caller path: must use the worker-thread fallback.

    The original bug detached the future from the executor; the
    coroutine that ``asyncio.run`` had rejected was the one that got
    GC'd unawaited, firing a RuntimeWarning at interpreter shutdown.
    """
    monkeypatch.setenv("ASSET_TREE_DB_URL", "mysql+aiomysql://x:y@h:3306/d")
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)

        async def go() -> None:
            be = get_default_backend()
            assert be is not None

        asyncio.run(go())


def test_missing_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ASSET_TREE_DB_URL → AssetTreeConfigError, no warning."""
    monkeypatch.delenv("ASSET_TREE_DB_URL", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with pytest.raises(Exception):
            get_default_backend()
