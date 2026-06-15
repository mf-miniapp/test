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
def store(monkeypatch):
    # The DB-backed TreeStore requires ASSET_TREE_DB_URL; tests run
    # without MySQL, so we swap in an in-memory stub that covers the
    # surface area ``web/store.py`` actually touches (no AssetTreeBackend
    # ABC conformance required — keep the test surface narrow).
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.asset_tree.web import store as _store_mod
    from tests._stubs.in_memory_backend import InMemoryStubBackend

    backend = InMemoryStubBackend()
    _be_mod.set_default_backend(backend)  # type: ignore[arg-type]
    monkeypatch.setattr(_store_mod, "_backend", lambda: backend)
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
        # routes/api_add_node forces state="discovered" on creation
        assert data["state"] == "discovered"
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


# ── JSON-fallback mode (DB not configured) ──────────────────────


class TestJSONFallbackMode:
    """When ASSET_TREE_DB_URL is unset, the web layer must:

    - render the index page (not 500)
    - read trees from the on-disk JSON snapshots
    - disable / reject write operations with 503 ``db_unavailable``
    - show a banner in the page hinting at the fallback
    """

    @pytest.fixture()
    def store_no_db(self, tmp_path, monkeypatch):
        """Build a TreeStore with the default backend neutralized.

        This simulates ``ASSET_TREE_DB_URL`` being unset. We also seed
        one JSON snapshot in a tmp state dir so the read path can find it.
        """
        # Make sure the default backend is reset, then point the store
        # module's ``_backend()`` helper at a function that raises
        # ``AssetTreeConfigError`` — exactly what the production code
        # does when the env var is unset.
        from opensquilla.asset_tree.db import backend as _be_mod
        from opensquilla.asset_tree.web import store as _store_mod
        from opensquilla.asset_tree.db.pool import AssetTreeConfigError
        from opensquilla.asset_tree.web.store import TreeStore

        # Reset any cached backend (e.g. from another test)
        _be_mod.set_default_backend(None)
        monkeypatch.setattr(
            _store_mod, "_backend",
            lambda: (_ for _ in ()).throw(AssetTreeConfigError(
                "ASSET_TREE_DB_URL is not set (test simulation).",
            )),
        )
        # Plant a JSON snapshot in a tmp state dir
        state_dir = tmp_path / "state" / "asset_trees"
        state_dir.mkdir(parents=True)
        monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(state_dir))

        from opensquilla.asset_tree.tree import AssetTree
        from opensquilla.asset_tree.models import AssetType, AssetState
        tree = AssetTree("fallback.com")
        sub_id = tree.add_node(
            asset_type=AssetType.SUB_DOMAIN,
            value="api.fallback.com",
            parent_id=tree.root_id,
        )
        tree.update_state(sub_id, AssetState.DISCOVERED)
        (state_dir / "tree-fallback.json").write_text(tree.to_json(), encoding="utf-8")

        return TreeStore()

    @pytest.fixture()
    def client_no_db(self, store_no_db):
        routes = create_asset_tree_routes(store_no_db)
        app = Starlette(routes=[Mount("/asset-tree", routes=routes)])
        return TestClient(app, raise_server_exceptions=False)

    def test_db_available_is_false(self, store_no_db):
        """The store probes and discovers no DB is configured."""
        assert store_no_db.db_available is False
        status = store_no_db.db_status_payload()
        assert status["mode"] == "json_fallback"
        assert "ASSET_TREE_DB_URL" in status["hint"]

    def test_index_page_renders(self, client_no_db):
        """The HTML page must render (200), not 500."""
        resp = client_no_db.get("/asset-tree/")
        assert resp.status_code == 200
        assert "Asset Tree" in resp.text

    def test_index_page_shows_warning_banner(self, client_no_db):
        """The page must include the DB-not-configured banner."""
        resp = client_no_db.get("/asset-tree/")
        assert resp.status_code == 200
        assert "DB not configured" in resp.text
        assert "ASSET_TREE_DB_URL" in resp.text

    def test_index_page_renders_no_trees_when_empty(self, tmp_path, monkeypatch):
        """When the JSON state dir is empty, the page still renders (banner only)."""
        # Override the default fixture: use a clean tmp state dir with no snapshots
        empty_state = tmp_path / "empty_state" / "asset_trees"
        empty_state.mkdir(parents=True)
        monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(empty_state.parent))
        from opensquilla.asset_tree.db import backend as _be_mod
        from opensquilla.asset_tree.web import store as _store_mod
        from opensquilla.asset_tree.db.pool import AssetTreeConfigError
        from opensquilla.asset_tree.web.store import TreeStore
        from opensquilla.asset_tree.web.routes import create_asset_tree_routes
        from starlette.applications import Starlette
        from starlette.routing import Mount
        from starlette.testclient import TestClient
        _be_mod.set_default_backend(None)
        monkeypatch.setattr(
            _store_mod, "_backend",
            lambda: (_ for _ in ()).throw(AssetTreeConfigError("unset")),
        )
        store = TreeStore()
        app = Starlette(routes=[Mount("/asset-tree", routes=create_asset_tree_routes(store))])
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.get("/asset-tree/")
        assert resp.status_code == 200
        assert "DB not configured" in resp.text

    def test_list_trees_returns_json_fallback(self, client_no_db):
        """GET /api/trees must return the JSON-fallback tree list."""
        resp = client_no_db.get("/asset-tree/api/trees")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["trees"]) == 1
        assert body["trees"][0]["root_domain"] == "fallback.com"
        assert body["trees"][0]["node_count"] == 2  # root + sub_domain

    def test_get_tree_returns_json_fallback(self, client_no_db):
        """GET /api/trees/{id} must reconstruct from JSON."""
        resp = client_no_db.get("/asset-tree/api/trees/tree-fallback")
        assert resp.status_code == 200
        body = resp.json()
        assert body["root_domain"] == "fallback.com"
        assert "tree" in body

    def test_get_tree_404_for_unknown(self, client_no_db):
        resp = client_no_db.get("/asset-tree/api/trees/nonexistent")
        assert resp.status_code == 404

    def test_create_tree_returns_503(self, client_no_db):
        """POST /api/trees must return 503 db_unavailable in fallback mode."""
        resp = client_no_db.post(
            "/asset-tree/api/trees",
            json={"root_domain": "blocked.com"},
        )
        assert resp.status_code == 503
        body = resp.json()
        assert body["code"] == "db_unavailable"
        assert "ASSET_TREE_DB_URL" in body["error"]

    def test_add_node_returns_503(self, client_no_db):
        resp = client_no_db.post(
            "/asset-tree/api/trees/tree-fallback/nodes",
            json={"asset_type": "sub_domain", "value": "x.fallback.com"},
        )
        assert resp.status_code == 503
        assert resp.json()["code"] == "db_unavailable"

    def test_update_node_returns_503(self, client_no_db):
        # Look up a real node id from the JSON-fallback tree, then
        # try to update it. The route should still 503 because
        # store.update_node is a write op.
        meta = client_no_db.get("/asset-tree/api/trees/tree-fallback").json()
        # tree.nodes is a list (see _tree_to_dict) — pick the first
        # non-root node.
        nodes = meta.get("tree", {}).get("nodes", [])
        real_node_id = None
        for n in nodes:
            if n.get("asset_type") != "root_domain":
                real_node_id = n.get("id")
                break
        assert real_node_id is not None, "fixture must have a non-root node"
        resp = client_no_db.put(
            f"/asset-tree/api/trees/tree-fallback/nodes/{real_node_id}",
            json={"state": "verified"},
        )
        assert resp.status_code == 503
        assert resp.json()["code"] == "db_unavailable"

    def test_delete_tree_returns_503(self, client_no_db):
        resp = client_no_db.delete("/asset-tree/api/trees/tree-fallback")
        assert resp.status_code == 503
        assert resp.json()["code"] == "db_unavailable"

    def test_get_stats_still_works_via_json(self, client_no_db):
        """Stats endpoint is a read — should work in JSON-fallback mode."""
        resp = client_no_db.get("/asset-tree/api/trees/tree-fallback/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_nodes"] == 2
