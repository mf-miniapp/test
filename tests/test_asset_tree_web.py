"""Tests for the Asset Tree web module — API routes and page rendering.

Tests cover:
    - Tree CRUD (create, list, get, delete)
    - Node CRUD (add, list, update state, delete)
    - Tree statistics
    - Error cases (missing tree, invalid data, etc.)
    - Page rendering
"""

from __future__ import annotations

import json
import pytest

from starlette.testclient import TestClient

from opensquilla.asset_tree.web.routes import create_asset_tree_routes
from opensquilla.asset_tree.web.store import TreeStore
from starlette.applications import Starlette
from starlette.routing import Mount


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture()
def store():
    return TreeStore()


@pytest.fixture()
def client(store):
    routes = create_asset_tree_routes(store)
    app = Starlette(routes=[Mount("/asset-tree", routes=routes)])
    return TestClient(app, raise_server_exceptions=False)


# ── Tree CRUD ────────────────────────────────────────────────────


class TestTreeCRUD:
    def test_list_trees_empty(self, client):
        resp = client.get("/asset-tree/api/trees")
        assert resp.status_code == 200
        assert resp.json()["trees"] == []

    def test_create_tree(self, client):
        resp = client.post("/asset-tree/api/trees", json={
            "root_domain": "example.com",
            "description": "Test tree",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["root_domain"] == "example.com"
        assert data["description"] == "Test tree"
        assert data["node_count"] == 1  # root node
        assert "id" in data

    def test_create_tree_custom_id(self, client):
        resp = client.post("/asset-tree/api/trees", json={
            "root_domain": "example.com",
            "tree_id": "my-tree",
        })
        assert resp.status_code == 201
        assert resp.json()["id"] == "my-tree"

    def test_create_tree_duplicate_id(self, client):
        client.post("/asset-tree/api/trees", json={"root_domain": "a.com", "tree_id": "dup"})
        resp = client.post("/asset-tree/api/trees", json={"root_domain": "b.com", "tree_id": "dup"})
        assert resp.status_code == 409
        assert "already exists" in resp.json()["error"]

    def test_create_tree_missing_domain(self, client):
        resp = client.post("/asset-tree/api/trees", json={})
        assert resp.status_code == 400
        assert "root_domain" in resp.json()["error"]

    def test_list_trees_after_create(self, client):
        client.post("/asset-tree/api/trees", json={"root_domain": "a.com"})
        client.post("/asset-tree/api/trees", json={"root_domain": "b.com"})
        resp = client.get("/asset-tree/api/trees")
        assert resp.status_code == 200
        trees = resp.json()["trees"]
        assert len(trees) == 2
        domains = {t["root_domain"] for t in trees}
        assert domains == {"a.com", "b.com"}

    def test_get_tree(self, client):
        client.post("/asset-tree/api/trees", json={"root_domain": "example.com", "tree_id": "t1"})
        resp = client.get("/asset-tree/api/trees/t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["root_domain"] == "example.com"
        assert "tree" in data
        assert data["tree"]["root_domain"] == "example.com"

    def test_get_tree_not_found(self, client):
        resp = client.get("/asset-tree/api/trees/nonexistent")
        assert resp.status_code == 404
        assert "not found" in resp.json()["error"]

    def test_delete_tree(self, client):
        client.post("/asset-tree/api/trees", json={"root_domain": "a.com", "tree_id": "del"})
        resp = client.delete("/asset-tree/api/trees/del")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == "del"
        # Verify gone
        resp = client.get("/asset-tree/api/trees/del")
        assert resp.status_code == 404

    def test_delete_tree_not_found(self, client):
        resp = client.delete("/asset-tree/api/trees/nope")
        assert resp.status_code == 404


# ── Node CRUD ────────────────────────────────────────────────────


class TestNodeCRUD:
    def _create_tree(self, client, tree_id="t1"):
        client.post("/asset-tree/api/trees", json={
            "root_domain": "example.com",
            "tree_id": tree_id,
        })

    def test_add_subdomain_node(self, client):
        self._create_tree(client)
        resp = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain",
            "value": "api.example.com",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["asset_type"] == "sub_domain"
        assert data["value"] == "api.example.com"
        assert data["state"] == "unseen"
        assert data["parent_id"] is not None  # root node

    def test_add_node_with_parent(self, client):
        self._create_tree(client)
        # First add a subdomain
        resp1 = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain",
            "value": "api.example.com",
        })
        sub_id = resp1.json()["id"]
        # Then add IP under it
        resp2 = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "ip",
            "value": "1.2.3.4",
            "parent_id": sub_id,
        })
        assert resp2.status_code == 201
        assert resp2.json()["parent_id"] == sub_id

    def test_add_node_with_metadata(self, client):
        self._create_tree(client)
        resp = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain",
            "value": "api.example.com",
            "metadata": {"resolver": "dns", "records": ["A: 1.2.3.4"]},
        })
        assert resp.status_code == 201
        meta = resp.json()["metadata"]
        assert meta["resolver"] == "dns"

    def test_add_node_missing_fields(self, client):
        self._create_tree(client)
        resp = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain",
        })
        assert resp.status_code == 400

    def test_add_node_invalid_type(self, client):
        self._create_tree(client)
        resp = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "invalid_type",
            "value": "test",
        })
        assert resp.status_code == 400

    def test_add_node_tree_not_found(self, client):
        resp = client.post("/asset-tree/api/trees/nope/nodes", json={
            "asset_type": "sub_domain",
            "value": "test",
        })
        assert resp.status_code == 404

    def test_list_nodes(self, client):
        self._create_tree(client)
        # Create sub_domain first, then ip under it (routing rules)
        sub_resp = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain", "value": "a.example.com",
        })
        sub_id = sub_resp.json()["id"]
        client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "ip", "value": "1.2.3.4", "parent_id": sub_id,
        })
        resp = client.get("/asset-tree/api/trees/t1/nodes")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 3  # root + 2 nodes

    def test_list_nodes_filter_by_type(self, client):
        self._create_tree(client)
        sub_resp = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain", "value": "a.example.com",
        })
        sub_id = sub_resp.json()["id"]
        client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "ip", "value": "1.2.3.4", "parent_id": sub_id,
        })
        resp = client.get("/asset-tree/api/trees/t1/nodes?type=sub_domain")
        assert resp.status_code == 200
        for node in resp.json()["nodes"]:
            assert node["asset_type"] == "sub_domain"

    def test_list_nodes_invalid_type(self, client):
        self._create_tree(client)
        resp = client.get("/asset-tree/api/trees/t1/nodes?type=bad")
        assert resp.status_code == 400

    def test_update_node_state(self, client):
        self._create_tree(client)
        resp1 = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain", "value": "api.example.com",
        })
        node_id = resp1.json()["id"]
        resp2 = client.put(f"/asset-tree/api/trees/t1/nodes/{node_id}", json={
            "state": "discovered",
        })
        assert resp2.status_code == 200
        assert resp2.json()["state"] == "discovered"

    def test_update_node_metadata(self, client):
        self._create_tree(client)
        resp1 = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain", "value": "api.example.com",
        })
        node_id = resp1.json()["id"]
        resp2 = client.put(f"/asset-tree/api/trees/t1/nodes/{node_id}", json={
            "metadata": {"new_key": "new_value"},
        })
        assert resp2.status_code == 200
        assert resp2.json()["metadata"]["new_key"] == "new_value"

    def test_update_node_not_found(self, client):
        self._create_tree(client)
        resp = client.put("/asset-tree/api/trees/t1/nodes/fakeid", json={
            "state": "discovered",
        })
        assert resp.status_code == 404

    def test_update_node_invalid_state(self, client):
        self._create_tree(client)
        resp1 = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain", "value": "api.example.com",
        })
        node_id = resp1.json()["id"]
        resp2 = client.put(f"/asset-tree/api/trees/t1/nodes/{node_id}", json={
            "state": "bad_state",
        })
        assert resp2.status_code == 400

    def test_delete_node(self, client):
        self._create_tree(client)
        resp1 = client.post("/asset-tree/api/trees/t1/nodes", json={
            "asset_type": "sub_domain", "value": "api.example.com",
        })
        node_id = resp1.json()["id"]
        resp2 = client.delete(f"/asset-tree/api/trees/t1/nodes/{node_id}")
        assert resp2.status_code == 200
        assert resp2.json()["deleted"] == node_id

    def test_delete_root_node_forbidden(self, client):
        self._create_tree(client)
        # Get the root node ID
        resp = client.get("/asset-tree/api/trees/t1")
        root_nodes = resp.json()["tree"]["nodes"]
        root_id = [n for n in root_nodes if n["asset_type"] == "root_domain"][0]["id"]
        resp2 = client.delete(f"/asset-tree/api/trees/t1/nodes/{root_id}")
        assert resp2.status_code == 400
        assert "Cannot delete root" in resp2.json()["error"]

    def test_delete_node_not_found(self, client):
        self._create_tree(client)
        resp = client.delete("/asset-tree/api/trees/t1/nodes/nonexistent")
        assert resp.status_code == 404


# ── Stats ────────────────────────────────────────────────────────


class TestStats:
    def test_get_stats(self, client):
        client.post("/asset-tree/api/trees", json={"root_domain": "example.com", "tree_id": "s1"})
        client.post("/asset-tree/api/trees/s1/nodes", json={
            "asset_type": "sub_domain", "value": "api.example.com",
        })
        resp = client.get("/asset-tree/api/trees/s1/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_nodes"] >= 2

    def test_stats_tree_not_found(self, client):
        resp = client.get("/asset-tree/api/trees/nope/stats")
        assert resp.status_code == 404


# ── Page rendering ───────────────────────────────────────────────


class TestPageRendering:
    def test_index_page(self, client):
        resp = client.get("/asset-tree/")
        assert resp.status_code == 200
        assert "Asset Tree" in resp.text or "资产树" in resp.text

    def test_index_page_contains_trees(self, client):
        client.post("/asset-tree/api/trees", json={"root_domain": "example.com"})
        resp = client.get("/asset-tree/")
        assert resp.status_code == 200
        assert "example.com" in resp.text
