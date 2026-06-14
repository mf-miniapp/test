"""Tests for the AssetTree MySQL backend (Phase 4).

AssetTree is MySQL-only. These tests require a real MySQL instance;
set ``TEST_MYSQL_URL`` (e.g. ``mysql+aiomysql://user:pass@127.0.0.1:3306/opensquilla_test``)
to run them. Without it, every test in this module is skipped.

The ``mysql_backend`` fixture (in ``conftest.py``) wipes + re-creates
the schema for full isolation between tests.
"""

from __future__ import annotations

import asyncio

import pytest

# All tests in this module require a real MySQL server.
pytestmark = pytest.mark.requires_mysql

from opensquilla.asset_tree.db.migrations import migrate  # noqa: E402

# The ``backend`` fixture is provided by ``conftest.py::mysql_backend``.


# ── Fixtures ──────────────────────────────────────────────


@pytest.fixture
def backend(mysql_backend):
    """Alias for the conftest ``mysql_backend`` fixture."""
    return mysql_backend


def _run(coro):
    """Helper: run a coroutine to completion.

    Always create a fresh event loop. We can't use ``asyncio.get_event_loop()``
    because pytest-asyncio closes its loop after each async test, and
    ``asyncio.get_event_loop()`` then raises ``RuntimeError: no current
    event loop`` on subsequent sync invocations.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Schema ──────────────────────────────────────────────


class TestSchema:
    def test_migrate_creates_all_tables(self, backend):
        """migrate() must create 5 tables on a fresh DB."""

        async def _check():
            from sqlalchemy import text
            async with backend._engine.begin() as conn:
                rows = (await conn.execute(text(
                    "SELECT TABLE_NAME AS name FROM information_schema.tables "
                    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'asset_%' "
                    "ORDER BY TABLE_NAME"
                ))).all()
                names = {r[0] for r in rows}
            expected = {
                "asset_trees", "asset_nodes", "asset_edges",
                "asset_state_transitions", "asset_evidence_refs",
            }
            assert expected.issubset(names), (
                f"missing tables: {expected - names}"
            )

        _run(_check())

    def test_migrate_is_idempotent(self, backend):
        """Calling migrate() twice must not raise."""

        async def _check():
            await migrate(backend)
            await migrate(backend)  # no-op on second run

        _run(_check())

    def test_asset_nodes_dedup_constraint_exists(self, backend):
        """The UNIQUE dedup constraint on (tree_id, asset_type, parent_id, value)
        must be enforced — this is the dedup invariant at the DB layer.

        MySQL exposes table indexes via information_schema.statistics;
        we look for ``uq_asset_nodes_dedup`` with NON_UNIQUE = 0.
        """

        async def _check():
            from sqlalchemy import text
            async with backend._engine.begin() as conn:
                rows = (await conn.execute(text(
                    "SELECT INDEX_NAME, NON_UNIQUE FROM information_schema.statistics "
                    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_nodes' "
                    "AND INDEX_NAME = 'uq_asset_nodes_dedup'"
                ))).all()
            assert rows, "uq_asset_nodes_dedup index missing"
            # NON_UNIQUE = 0 means UNIQUE
            assert all(r[1] == 0 for r in rows)

        _run(_check())


# ── Tree CRUD ──────────────────────────────────────────────


class TestTreeCRUD:
    def test_upsert_and_get_tree(self, backend):
        async def _run_async():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            row = await backend.get_tree("t1")
            assert row is not None
            assert row.tree_id == "t1"
            assert row.root_domain == "example.com"
            assert row.root_node_id == "root-id-12"

        _run(_run_async())

    def test_get_missing_tree_returns_none(self, backend):
        async def _run_async():
            assert await backend.get_tree("ghost") is None

        _run(_run_async())

    def test_delete_tree_cascades(self, backend):
        """delete_tree must remove all child nodes / edges via CASCADE."""

        async def _setup():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            await backend.add_node(
                node_id="child-id-1", tree_id="t1",
                asset_type="sub_domain", value="api.example.com",
                state="unseen", parent_id="root-id-12",
                material_path="root-id-12/child-id-1", path_depth=1,
            )

        async def _check():
            await backend.delete_tree("t1")
            # Both nodes must be gone
            assert await backend.get_node("t1", "root-id-12") is None
            assert await backend.get_node("t1", "child-id-1") is None
            assert await backend.get_tree("t1") is None

        _run(_setup())
        _run(_check())


# ── Node CRUD + dedup ──────────────────────────────────────────────


class TestNodeCRUD:
    def test_insert_root_node(self, backend):
        async def _run_async():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            inserted = await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            assert inserted is True
            node = await backend.get_node("t1", "root-id-12")
            assert node is not None
            assert node.value == "example.com"
            assert node.state == "unseen"
            assert node.parent_id is None
            assert node.path_depth == 0

        _run(_run_async())

    def test_dedup_constraint_blocks_duplicate(self, backend):
        """Adding (tree_id, type, parent, value) twice returns False."""

        async def _run_async():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            inserted = await backend.add_node(
                node_id="dup-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="dup-id-12", path_depth=0,
            )
            assert inserted is False

        _run(_run_async())

    def test_cross_parent_duplicates_legal(self, backend):
        """Same IP under different sub_domain parents is LEGITIMATE."""

        async def _run_async():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            # Add two sub_domain parents
            for parent_id, label in [("api-id-12", "api"), ("admin-id-12", "admin")]:
                await backend.add_node(
                    node_id=parent_id, tree_id="t1",
                    asset_type="sub_domain", value=f"{label}.example.com",
                    state="unseen", parent_id="root-id-12",
                    material_path=f"root-id-12/{parent_id}", path_depth=1,
                )
            # Same IP under both parents — must succeed twice
            ok1 = await backend.add_node(
                node_id="ip-aaaaaa00001", tree_id="t1",
                asset_type="ip", value="1.2.3.4",
                state="unseen", parent_id="api-id-12",
                material_path="root-id-12/api-id-12/ip-aaaaaa00001", path_depth=2,
            )
            ok2 = await backend.add_node(
                node_id="ip-bbbbbb00001", tree_id="t1",
                asset_type="ip", value="1.2.3.4",
                state="unseen", parent_id="admin-id-12",
                material_path="root-id-12/admin-id-12/ip-bbbbbb00001", path_depth=2,
            )
            assert ok1 is True and ok2 is True
            nodes = await backend.find_nodes_by_value("t1", "1.2.3.4")
            assert len(nodes) == 2

        _run(_run_async())

    def test_state_transition_recorded(self, backend):
        async def _run_async():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            await backend.update_node_state(
                node_id="root-id-12", tree_id="t1", new_state="discovered",
            )
            await backend.add_state_transition(
                tree_id="t1", node_id="root-id-12",
                from_state="unseen", to_state="discovered",
            )
            node = await backend.get_node("t1", "root-id-12")
            assert node is not None
            assert node.state == "discovered"

        _run(_run_async())


# ── Traversal ──────────────────────────────────────────────


class TestTraversal:
    def _setup_tree(self, backend):
        """Build a small tree: root -> api/admin -> IPs."""

        async def _build():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            await backend.add_node(
                node_id="api-id-12", tree_id="t1",
                asset_type="sub_domain", value="api.example.com",
                state="unseen", parent_id="root-id-12",
                material_path="root-id-12/api-id-12", path_depth=1,
            )
            await backend.add_node(
                node_id="ip-id-0012", tree_id="t1",
                asset_type="ip", value="1.2.3.4",
                state="unseen", parent_id="api-id-12",
                material_path="root-id-12/api-id-12/ip-id-0012", path_depth=2,
            )
            await backend.add_node(
                node_id="admin-id-12", tree_id="t1",
                asset_type="sub_domain", value="admin.example.com",
                state="unseen", parent_id="root-id-12",
                material_path="root-id-12/admin-id-12", path_depth=1,
            )

        _run(_build())

    def test_get_children(self, backend):
        self._setup_tree(backend)
        async def _run_async():
            children = await backend.get_children("t1", "root-id-12")
            values = {c.value for c in children}
            assert values == {"api.example.com", "admin.example.com"}

        _run(_run_async())

    def test_get_parent(self, backend):
        self._setup_tree(backend)
        async def _run_async():
            parent = await backend.get_parent("t1", "ip-id-0012")
            assert parent is not None
            assert parent.value == "api.example.com"

        _run(_run_async())

    def test_get_path_to_root(self, backend):
        self._setup_tree(backend)
        async def _run_async():
            path = await backend.get_path_to_root("t1", "ip-id-0012")
            values = [n.value for n in path]
            assert values == ["example.com", "api.example.com", "1.2.3.4"]

        _run(_run_async())

    def test_get_all_descendants(self, backend):
        self._setup_tree(backend)
        async def _run_async():
            descendants = await backend.get_all_descendants("t1", "root-id-12")
            # Root has 3 descendants: api + admin (sub_domains) + ip (under api)
            values = {d.value for d in descendants}
            assert values == {"api.example.com", "admin.example.com", "1.2.3.4"}

        _run(_run_async())

    def test_find_shared_ips(self, backend):
        """find_shared_ips finds IPs whose parent_id differs across rows."""

        async def _build():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            for sub_id, label in [("api-id-12", "api"), ("admin-id-12", "admin")]:
                await backend.add_node(
                    node_id=sub_id, tree_id="t1",
                    asset_type="sub_domain", value=f"{label}.example.com",
                    state="unseen", parent_id="root-id-12",
                    material_path=f"root-id-12/{sub_id}", path_depth=1,
                )
            await backend.add_node(
                node_id="ip-shared-1", tree_id="t1",
                asset_type="ip", value="1.2.3.4",
                state="unseen", parent_id="api-id-12",
                material_path="root-id-12/api-id-12/ip-shared-1", path_depth=2,
            )
            await backend.add_node(
                node_id="ip-shared-2", tree_id="t1",
                asset_type="ip", value="1.2.3.4",
                state="unseen", parent_id="admin-id-12",
                material_path="root-id-12/admin-id-12/ip-shared-2", path_depth=2,
            )

        async def _check():
            shared = await backend.find_shared_ips("t1")
            assert "1.2.3.4" in shared
            assert set(shared["1.2.3.4"]) == {"api-id-12", "admin-id-12"}

        _run(_build())
        _run(_check())


# ── find_unseen ──────────────────────────────────────────────


class TestFindUnseen:
    def test_find_unseen_with_type_filter(self, backend):
        async def _build():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="discovered", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            await backend.add_node(
                node_id="api-id-12", tree_id="t1",
                asset_type="sub_domain", value="api.example.com",
                state="unseen", parent_id="root-id-12",
                material_path="root-id-12/api-id-12", path_depth=1,
            )

        async def _check():
            unseen = await backend.find_unseen("t1", asset_type="sub_domain")
            assert len(unseen) == 1
            assert unseen[0].value == "api.example.com"
            unseen_all = await backend.find_unseen("t1")
            # root is DISCOVERED, only api shows up
            assert len(unseen_all) == 1

        _run(_build())
        _run(_check())

    def test_find_unseen_orders_by_depth(self, backend):
        async def _build():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            await backend.add_node(
                node_id="root-id-12", tree_id="t1",
                asset_type="root_domain", value="example.com",
                state="unseen", parent_id=None,
                material_path="root-id-12", path_depth=0,
            )
            await backend.add_node(
                node_id="api-id-12", tree_id="t1",
                asset_type="sub_domain", value="api.example.com",
                state="unseen", parent_id="root-id-12",
                material_path="root-id-12/api-id-12", path_depth=1,
            )

        async def _check():
            unseen = await backend.find_unseen("t1")
            assert [n.value for n in unseen] == ["example.com", "api.example.com"]

        _run(_build())
        _run(_check())


# ── Stats ──────────────────────────────────────────────


class TestStats:
    def test_stats_summary(self, backend):
        async def _build():
            await backend.upsert_tree("t1", "example.com", "root-id-12")
            for nid, atype, value, state in [
                ("root-id-12", "root_domain", "example.com", "unseen"),
                ("api-id-12", "sub_domain", "api.example.com", "discovered"),
                ("ip-id-0012", "ip", "1.2.3.4", "unseen"),
            ]:
                await backend.add_node(
                    node_id=nid, tree_id="t1",
                    asset_type=atype, value=value, state=state,
                    parent_id="root-id-12" if nid != "root-id-12" else None,
                    material_path=f"root-id-12/{nid}",
                    path_depth=1 if nid != "root-id-12" else 0,
                )

        async def _check():
            stats = await backend.stats("t1")
            assert stats["total_nodes"] == 3
            assert stats["by_type"]["root_domain"] == 1
            assert stats["by_type"]["sub_domain"] == 1
            assert stats["by_state"]["unseen"] == 2
            assert stats["depth"] == 1

        _run(_build())
        _run(_check())


# ── Concurrent inserts ──────────────────────────────────────────────


class TestConcurrency:
    def test_concurrent_root_inserts_have_only_one_winner(self, backend):
        """100 concurrent inserts of the same (tree, type, value) — only
        one wins, the rest are deduped."""

        async def _setup():
            await backend.upsert_tree("t1", "example.com", "root-id-12")

        async def _race():
            async def attempt(i: int):
                return await backend.add_node(
                    node_id=f"root-{i:012d}", tree_id="t1",
                    asset_type="root_domain", value="example.com",
                    state="unseen", parent_id=None,
                    material_path=f"root-{i:012d}", path_depth=0,
                )

            results = await asyncio.gather(
                *[attempt(i) for i in range(100)]
            )
            winners = sum(1 for r in results if r)
            assert winners == 1, f"expected 1 winner, got {winners}"
            nodes = await backend.find_nodes_by_value("t1", "example.com")
            assert len(nodes) == 1

        _run(_setup())
        _run(_race())