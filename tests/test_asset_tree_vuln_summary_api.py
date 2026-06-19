"""v6 (2026-06-19) 资产树页下方漏洞摘要 API 单测。"""
from __future__ import annotations

import asyncio
import pytest
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Mount

from opensquilla.asset_tree.web.routes import create_asset_tree_routes
from opensquilla.asset_tree.web.store import TreeStore
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.asset_tree.models import AssetType
from tests._stubs.in_memory_backend import InMemoryStubBackend


@pytest.fixture()
def backend(monkeypatch):
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.asset_tree.web import store as _store_mod
    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    monkeypatch.setattr(_store_mod, "_backend", lambda: be)
    return be


@pytest.fixture()
def client(backend):
    store = TreeStore()
    routes = create_asset_tree_routes(store)
    app = Starlette(routes=[Mount("/asset-tree", routes=routes)])
    return TestClient(app, raise_server_exceptions=False)


class TestTreeVulnSummary:
    def test_404_unknown_tree(self, client):
        resp = client.get("/asset-tree/api/trees/missing/vulnerabilities-summary")
        assert resp.status_code == 404

    def test_empty_tree(self, client, backend, monkeypatch):
        from opensquilla.asset_tree.web import store as _store_mod
        tree = AssetTree("example.com", tree_id="t1")

        async def fake_get_tree(self, tree_id):
            if tree_id == "t1":
                return tree
            raise KeyError(tree_id)
        monkeypatch.setattr(_store_mod.TreeStore, "get_tree", fake_get_tree)

        resp = client.get("/asset-tree/api/trees/t1/vulnerabilities-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["vulnerabilities"] == []

    def test_returns_summary(self, client, backend, monkeypatch):
        from opensquilla.asset_tree.web import store as _store_mod
        tree = AssetTree("example.com", tree_id="t1")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com",
                            parent_id=tree.root_id, allow_unverified=True)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub, allow_unverified=True)
        nid = ip

        async def setup():
            await backend.upsert_tree(
                tree_id="t1", root_domain="example.com",
                root_node_id=tree.root_id,
            )
            await backend.add_vulnerability(
                vuln_id="v1", tree_id="t1", attack_path_id="a"*12,
                leaf_node_id=nid, cwe="CWE-89", cve="CVE-2024-9999",
                severity="critical", title="SQLi", description="x",
                evidence=None, request=None, response=None, payload=None,
                discovered_by_wave="W4", discovered_by_specialist="pen",
            )
        asyncio.run(setup())

        # mock get_tree 走 TreeStore
        real = _store_mod.TreeStore.get_tree

        async def fake_get_tree(self, tree_id):
            if tree_id == "t1":
                return tree
            raise KeyError(tree_id)
        monkeypatch.setattr(_store_mod.TreeStore, "get_tree", fake_get_tree)

        resp = client.get("/asset-tree/api/trees/t1/vulnerabilities-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 1
        v = data["vulnerabilities"][0]
        assert v["title"] == "SQLi"
        assert v["severity"] == "critical"
        assert v["cve"] == "CVE-2024-9999"
        assert v["leaf_node_id"] == nid
