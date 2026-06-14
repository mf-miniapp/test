from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_PYTEST_STATE_ROOT = Path(tempfile.gettempdir()) / f"opensquilla-pytest-{os.getpid()}"

os.environ.setdefault("OPENSQUILLA_STATE_DIR", str(_PYTEST_STATE_ROOT / "state"))
os.environ.setdefault("OPENSQUILLA_LOG_DIR", str(_PYTEST_STATE_ROOT / "logs"))
os.environ.setdefault("OPENSQUILLA_TURN_CALL_LOG", "0")


# ── AssetTree MySQL backend fixture ─────────────────────────────
#
# AssetTree is MySQL-only. Tests that exercise the persistence layer
# need a real MySQL instance. The connection URL is read from
# ``TEST_MYSQL_URL`` (e.g. ``mysql+aiomysql://user:pass@host:3306/opensquilla_test``).
#
# If the env var is missing or unreachable, the fixture skips the test
# so unit-only environments stay green.

def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_mysql: mark test as requiring a real MySQL instance "
        "(skipped when TEST_MYSQL_URL is unset/unreachable).",
    )


async def _ping_mysql(url: str) -> bool:
    """Try one round-trip connect to confirm the server is reachable."""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine(url, pool_pre_ping=True)
        async with engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return True
    except Exception:
        return False


@pytest.fixture
def mysql_backend_url(request: pytest.FixtureRequest) -> str:
    """Resolve the test MySQL URL from env, skipping if unavailable.

    Usage::

        @pytest.mark.requires_mysql
        def test_x(mysql_backend_url):
            ...
    """
    url = os.environ.get("TEST_MYSQL_URL", "").strip()
    if not url:
        pytest.skip("TEST_MYSQL_URL not set; skipping MySQL test")
    if not url.startswith("mysql"):
        pytest.skip(f"TEST_MYSQL_URL must be a mysql+aiomysql:// URL (got: {url!r})")

    # Probe connectivity in a fresh event loop.
    async def _probe() -> bool:
        return await _ping_mysql(url)

    try:
        loop = asyncio.new_event_loop()
        try:
            ok = loop.run_until_complete(_probe())
        finally:
            loop.close()
    except Exception:
        ok = False
    if not ok:
        pytest.skip(f"TEST_MYSQL_URL unreachable: {url!r}")
    return url


@pytest.fixture
def mysql_backend(mysql_backend_url: str):
    """Yield a freshly-built ``MysqlBackend`` with the test schema created.

    The DB is wiped on teardown so each test starts clean.
    """
    from opensquilla.asset_tree.db import (
        MysqlBackend,
        build_engine_from_url,
        build_session_factory,
    )
    from opensquilla.asset_tree.db.migrations import reset

    engine = build_engine_from_url(mysql_backend_url)
    factory = build_session_factory(engine)
    backend = MysqlBackend(engine, factory)

    async def _go() -> None:
        await backend.init_schema()
        # Wipe between tests: drop & recreate the schema. Faster than
        # row-by-row truncation and the test DB is dedicated to CI.
        await reset(backend)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_go())
    finally:
        loop.close()

    try:
        yield backend
    finally:
        async def _close() -> None:
            await backend.close()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_close())
        finally:
            loop.close()
