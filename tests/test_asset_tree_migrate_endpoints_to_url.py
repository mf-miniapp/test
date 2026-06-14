"""Tests for the one-shot data migration SERVICE→ENDPOINT  →  SERVICE→URL→ENDPOINT."""
from __future__ import annotations

import asyncio
import json
import tempfile

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.requires_mysql

from opensquilla.asset_tree.db.backend import MysqlBackend
from opensquilla.asset_tree.db.migrations import migrate as run_migrate
from opensquilla.asset_tree.db.pool import build_engine_from_url, build_session_factory
from opensquilla.asset_tree.migrate_endpoints_to_url import migrate as run_endpoint_migration


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _build_legacy_tree(engine, tree_id: str = "t1") -> None:
    """在 MySQL 里手工铺一份旧结构数据。"""

    async def _go() -> None:
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO asset_trees (tree_id, root_domain, root_node_id) "
                "VALUES (:t, 'example.com', 'r1')"
            ), {"t": tree_id})
            # value 用真实域名字符串，便于迁移脚本推断 base URL。
            rows = [
                ('root_domain', 'r1', 'example.com', '', 0, 'r1'),
                ('sub_domain', 'sd1', 'api.example.com', 'r1', 1, 'r1/sd1'),
                ('ip', 'ip1', '1.1.1.1', 'sd1', 2, 'r1/sd1/ip1'),
                ('port', 'p1', '443', 'ip1', 3, 'r1/sd1/ip1/p1'),
                ('service', 'svc1', 'HTTPS/NGINX', 'p1', 4, 'r1/sd1/ip1/p1/svc1'),
                ('endpoint', 'e1', '/v1/users', 'svc1', 5, 'r1/sd1/ip1/p1/svc1/e1'),
                ('endpoint', 'e2', '/v1/orders', 'svc1', 5, 'r1/sd1/ip1/p1/svc1/e2'),
            ]
            for atype, nid, val, parent, depth, path in rows:
                await conn.execute(text(
                    "INSERT INTO asset_nodes (id, tree_id, asset_type, value, state, "
                    "parent_id, material_path, path_depth) "
                    "VALUES (:i, :t, :a, :v, 'unseen', :p, :path, :d)"
                ), {"i": nid, "t": tree_id, "a": atype, "v": val, "p": parent,
                     "path": path, "d": depth})
            edges = [('r1', 'sd1'), ('sd1', 'ip1'), ('ip1', 'p1'),
                     ('p1', 'svc1'), ('svc1', 'e1'), ('svc1', 'e2')]
            for parent, child in edges:
                await conn.execute(text(
                    "INSERT INTO asset_edges (tree_id, parent_id, child_id, child_order) "
                    "VALUES (:t, :p, :c, 0)"
                ), {"t": tree_id, "p": parent, "c": child})

    _run(_go())


def _build_on_backend(backend):
    """Seed the legacy data on top of the conftest-provided MySQL backend."""
    _run(run_migrate(backend))
    _build_legacy_tree(backend._engine)
    return backend


def test_dry_run_no_writes(mysql_backend) -> None:
    backend = _build_on_backend(mysql_backend)
    rep = _run(run_endpoint_migration(backend, dry_run=True))
    assert rep.endpoints_moved == 2

    async def _check() -> int:
        async with backend._engine.connect() as conn:
            bad = await conn.execute(text(
                "SELECT COUNT(*) FROM asset_nodes ep "
                "JOIN asset_nodes svc ON svc.tree_id=ep.tree_id AND svc.id=ep.parent_id "
                "WHERE ep.tree_id='t1' AND ep.asset_type='endpoint' "
                "AND svc.asset_type='service'"
            ))
            return bad.scalar()
    count = _run(_check())
    assert count == 2, "dry_run must not modify the DB"
    # backend cleanup handled by conftest.mysql_backend fixture


def test_real_run_creates_url_and_moves_endpoints(mysql_backend) -> None:
    backend = _build_on_backend(mysql_backend)
    rep = _run(run_endpoint_migration(backend, dry_run=False))
    assert rep.trees_scanned == 1
    assert rep.services_touched == 1
    assert rep.urls_created == 1
    assert rep.endpoints_moved == 2
    assert rep.invariants_violated == []

    async def _check() -> None:
        async with backend._engine.connect() as conn:
            bad = await conn.execute(text(
                "SELECT COUNT(*) FROM asset_nodes ep "
                "JOIN asset_nodes svc ON svc.tree_id=ep.tree_id AND svc.id=ep.parent_id "
                "WHERE ep.tree_id='t1' AND ep.asset_type='endpoint' "
                "AND svc.asset_type='service'"
            ))
            assert bad.scalar() == 0, "service→endpoint should be gone"

            u = await conn.execute(text(
                "SELECT value FROM asset_nodes WHERE tree_id='t1' AND asset_type='url'"
            ))
            assert u.scalar() == "https://api.example.com"

            ep = await conn.execute(text(
                "SELECT parent_id, metadata FROM asset_nodes "
                "WHERE tree_id='t1' AND asset_type='endpoint' ORDER BY id"
            ))
            rows = list(ep)
            assert len(rows) == 2
            for parent, meta in rows:
                assert parent != "svc1"
                m = meta if not isinstance(meta, str) else json.loads(meta)
                assert m["_migrated_from"] == "svc1"
                assert "migrated_at" in m
    _run(_check())
    # backend cleanup handled by conftest.mysql_backend fixture


def test_url_reuse_when_same_value(mysql_backend) -> None:
    """同一 service 下，新增 endpoint 时应复用已存在的同 value URL。"""
    backend = _build_on_backend(mysql_backend)
    # 第一次跑：svc1 下 e1/e2 全部走完，URL 已存在，urls_created=1
    rep = _run(run_endpoint_migration(backend, dry_run=False))
    assert rep.urls_created == 1
    assert rep.endpoints_moved == 2

    async def _add_third_endpoint() -> None:
        async with backend._engine.begin() as conn:
            # 新增的 endpoint 直接挂到 svc1（旧结构）
            await conn.execute(text(
                "INSERT INTO asset_nodes (id, tree_id, asset_type, value, state, "
                "parent_id, material_path, path_depth) "
                "VALUES ('e3','t1','endpoint','/admin','unseen','svc1',"
                "'r1/sd1/ip1/p1/svc1/e3',5)"
            ))
            await conn.execute(text(
                "INSERT INTO asset_edges (tree_id, parent_id, child_id, child_order) "
                "VALUES ('t1','svc1','e3',2)"
            ))
    _run(_add_third_endpoint())

    # 第二次跑：应找到 svc1 下历史已存在的 URL 并复用，urls_created=0, urls_reused=1
    rep2 = _run(run_endpoint_migration(backend, dry_run=False))
    assert rep2.urls_created == 0
    assert rep2.urls_reused == 1
    assert rep2.endpoints_moved == 1
    # backend cleanup handled by conftest.mysql_backend fixture
