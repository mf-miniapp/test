"""Attack Paths dashboard web module — routes + store + template smoke.

Tests cover:

  - Dashboard page renders with stub backend (no DB) and shows the
    "DB unavailable" warning.
  - Path detail page 404s on unknown path.
  - KPI summary bucket counts by status.
  - ``path_detail_bundle`` aggregates vuln->node feeds.
  - API: ``/api/trees`` returns JSON.
  - API: ``/api/run`` rejects missing ``tree_id``.
  - API: ``/api/run`` short-circuits with the helper's BuildAndRunError
    code 2 (tree not found) for a fake id.
  - Hand-off URL shape (chat?prefill=...) is in the rendered script.
"""
from __future__ import annotations

import pytest
from starlette.routing import Mount
from starlette.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    from opensquilla.asset_tree.db import backend as _be_mod
    from tests._stubs.in_memory_backend import InMemoryStubBackend
    from opensquilla.attack_paths.web import create_attack_path_routes

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    app = Mount("/attack-paths", routes=create_attack_path_routes())
    return TestClient(app, raise_server_exceptions=False)


# ── Page routes ──────────────────────────────────────────


def test_dashboard_renders_with_no_trees(client):
    """With a stub backend that has no trees, the dashboard renders the
    empty-state copy and the toolbar (no warning, because stub backend
    is in fact available)."""
    r = client.get("/attack-paths/")
    assert r.status_code == 200
    assert "Attack Paths" in r.text
    assert "选择一个 Tree 开始" in r.text
    # The "Run all pending" button must be disabled when no tree selected
    assert 'id="btn-run-all"' in r.text
    assert "disabled" in r.text


def test_path_detail_404_for_unknown_path(client):
    r = client.get("/attack-paths/does-not-exist")
    assert r.status_code == 404
    assert "not found" in r.json()["error"].lower()


# ── API routes ────────────────────────────────────────────


def test_api_paths_requires_tree_id(client):
    r = client.get("/attack-paths/api/paths")
    assert r.status_code == 400
    assert "tree_id" in r.json()["error"]


def test_api_paths_summary_requires_tree_id(client):
    r = client.get("/attack-paths/api/paths/summary")
    assert r.status_code == 400


def test_api_run_rejects_missing_tree_id(client):
    r = client.post("/attack-paths/api/run", json={})
    assert r.status_code == 400
    assert "tree_id" in r.json()["error"]


def test_api_run_rejects_invalid_json(client):
    r = client.post(
        "/attack-paths/api/run",
        content="not-json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400


def test_api_run_unknown_tree_returns_503(client):
    """build_and_run_attack_paths raises BuildAndRunError(code=2) for
    unknown trees; the API layer maps that to 503."""
    r = client.post("/attack-paths/api/run", json={"tree_id": "tree-ghost"})
    assert r.status_code == 503
    assert "not found" in r.json()["error"]


# ── Store unit tests ──────────────────────────────────────


def test_path_summary_buckets(monkeypatch):
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.attack_paths.web.store import AttackPathStore
    from tests._stubs.in_memory_backend import InMemoryStubBackend

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)

    async def _setup():
        await be.upsert_tree("t1", root_domain="x.com", root_node_id="n-root")
        # Three paths with mixed statuses + leaf types
        for i, (status, leaf) in enumerate([
            ("pending", "sub_domain"),
            ("pending", "url"),
            ("completed", "sub_domain"),
            ("failed", "port"),
        ]):
            await be.upsert_attack_path(
                path_id=f"a{i:04x}{i:04x}{i:04x}",
                tree_id="t1",
                path_hash=f"hash{i}",
                status=status,
                scope_string="x.com",
                edge_chain_json={"edges": []},
                leaf_node_id=f"leaf-{i}",
                leaf_type=leaf,
                leaf_value=f"v-{i}",
            )
            if status == "completed":
                await be.update_attack_path_status(
                    path_id=f"a{i:04x}{i:04x}{i:04x}",
                    status="completed", vuln_count=2,
                    mark_started=True, mark_completed=True,
                )
    import asyncio
    asyncio.run(_setup())

    store = AttackPathStore()
    summary = asyncio.run(store.path_summary("t1"))
    assert summary["path_total"] == 4
    assert summary["by_status"]["pending"] == 2
    assert summary["by_status"]["completed"] == 1
    assert summary["by_status"]["failed"] == 1
    assert summary["by_status"].get("in_progress", 0) == 0
    assert summary["by_leaf_type"]["sub_domain"] == 2
    assert summary["by_leaf_type"]["url"] == 1
    assert summary["by_leaf_type"]["port"] == 1
    assert summary["vuln_total"] == 2  # only completed contributed


def test_path_detail_bundle_aggregates_node_feeds(monkeypatch):
    """The detail bundle should bucket vulns by leaf_node_id so the
    tree-feed section shows 1 entry per affected node."""
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.attack_paths.web.store import AttackPathStore
    from tests._stubs.in_memory_backend import InMemoryStubBackend

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)

    async def _setup():
        await be.upsert_tree("t1", root_domain="x.com", root_node_id="n-root")
        await be.upsert_attack_path(
            path_id="abc123abc123", tree_id="t1", path_hash="h",
            status="completed", scope_string="x.com",
            edge_chain_json={"edges": []},
            leaf_node_id="leaf-A", leaf_type="url", leaf_value="u",
        )
        await be.update_attack_path_status(
            path_id="abc123abc123", status="completed", vuln_count=2,
            mark_started=True, mark_completed=True,
        )
        # Two vulns on the same node, one on a different node
        for vid, leaf in [("v1", "leaf-A"), ("v2", "leaf-A"), ("v3", "leaf-B")]:
            await be.add_vulnerability(
                vuln_id=vid, tree_id="t1",
                attack_path_id="abc123abc123",
                leaf_node_id=leaf, cwe=None, cve=None,
                severity="high", title=vid, description=None,
                evidence=None, request=None, response=None, payload=None,
                discovered_by_wave=None, discovered_by_specialist=None,
            )
            await be.add_path_vuln(attack_path_id="abc123abc123", vulnerability_id=vid)
            await be.add_node_vuln(tree_id="t1", node_id=leaf, vulnerability_id=vid)
    import asyncio
    asyncio.run(_setup())

    store = AttackPathStore()
    bundle = asyncio.run(store.path_detail_bundle("abc123abc123"))
    assert bundle is not None
    assert len(bundle["vulnerabilities"]) == 3
    feeds = {f["node_id"]: f["vuln_ids"] for f in bundle["node_feeds"]}
    assert sorted(feeds["leaf-A"]) == ["v1", "v2"]
    assert feeds["leaf-B"] == ["v3"]


def test_dashboard_with_populated_data_shows_kpis(monkeypatch):
    """End-to-end: stub backend with 1 tree + 5 paths in mixed states;
    dashboard page must render KPIs reflecting the bucket counts."""
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.attack_paths.web import create_attack_path_routes
    from tests._stubs.in_memory_backend import InMemoryStubBackend
    from starlette.routing import Mount
    from starlette.testclient import TestClient

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)

    import asyncio
    async def _setup():
        await be.upsert_tree("t-pop", root_domain="x.com", root_node_id="n-root")
        for i, st in enumerate(["pending", "pending", "completed", "failed", "abandoned"]):
            pid = f"a{i:04x}{i:04x}{i:04x}"
            await be.upsert_attack_path(
                path_id=pid, tree_id="t-pop",
                path_hash=f"h{i}", status=st, scope_string="x.com",
                edge_chain_json={"edges": []},
                leaf_node_id=f"l-{i}", leaf_type="url", leaf_value=f"u{i}",
            )
    asyncio.run(_setup())

    app = Mount("/attack-paths", routes=create_attack_path_routes())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/attack-paths/?tree_id=t-pop")
    assert r.status_code == 200
    body = r.text
    # KPIs
    assert "Total Paths" in body
    # Status chips with counts
    assert "pending" in body
    assert "completed" in body
    # Each path row should be a <tr> in the table
    assert body.count("data-path-id=") == 5
    # The detail link is /attack-paths/{path_id}
    assert "/attack-paths/a000000000000" in body


def test_dashboard_status_filter_narrows_table(monkeypatch):
    """``?status=completed`` should hide non-completed rows."""
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.attack_paths.web import create_attack_path_routes
    from tests._stubs.in_memory_backend import InMemoryStubBackend
    from starlette.routing import Mount
    from starlette.testclient import TestClient

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    import asyncio
    async def _setup():
        await be.upsert_tree("t-pop2", root_domain="x.com", root_node_id="n-root")
        for i, st in enumerate(["pending", "completed", "completed", "failed"]):
            pid = f"b{i:04x}{i:04x}{i:04x}"
            await be.upsert_attack_path(
                path_id=pid, tree_id="t-pop2", path_hash=f"h{i}",
                status=st, scope_string="x.com",
                edge_chain_json={"edges": []},
                leaf_node_id=f"l-{i}", leaf_type="url", leaf_value=f"u{i}",
            )
    asyncio.run(_setup())

    app = Mount("/attack-paths", routes=create_attack_path_routes())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/attack-paths/?tree_id=t-pop2&status=completed")
    assert r.status_code == 200
    body = r.text
    assert body.count("data-path-id=") == 2


def test_dashboard_run_button_uses_chat_handoff(monkeypatch):
    """The ▶ Run button must NOT call /api/run directly; instead it
    should hand off to the chat surface via a /control/chat?prefill=
    URL.  Asserting on the rendered template text is a coarse but
    sufficient check that the right text + onclick binding is in place.
    """
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.attack_paths.web import create_attack_path_routes
    from tests._stubs.in_memory_backend import InMemoryStubBackend
    from starlette.routing import Mount
    from starlette.testclient import TestClient

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    import asyncio
    async def _setup():
        await be.upsert_tree("t-chat", root_domain="x.com", root_node_id="n-root")
        await be.upsert_attack_path(
            path_id="abc123abc123", tree_id="t-chat", path_hash="h",
            status="pending", scope_string="x.com",
            edge_chain_json={"edges": []},
            leaf_node_id="l-0", leaf_type="url", leaf_value="u0",
        )
    asyncio.run(_setup())

    app = Mount("/attack-paths", routes=create_attack_path_routes())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/attack-paths/?tree_id=t-chat")
    assert r.status_code == 200
    body = r.text
    # The button label changed from "▶ Run" to "▶ Run in chat" to make
    # the new hand-off behavior obvious to the user.
    assert "Run in chat" in body
    # The hand-off hint banner explains the redirect to /control/chat
    assert "/control/chat" in body
    assert "prefill" in body  # hint mentions the URL mechanism
    # Inline _runInChat helper is present
    assert "_runInChat" in body
    # The URL builder uses URLSearchParams (to also pass ?tree= as
    # a redundant fallback).  Just check both query keys are wired.
    assert "prefill=" in body
    assert "tree=" in body
    assert "/control/chat?" in body


def test_dashboard_hand_off_url_includes_prefill():
    """The hand-off URL must include the slash command so chat's
    prefill consumer can auto-send it.  We assert the script body
    contains the prefill URL builder with the slash command shape."""
    from opensquilla.asset_tree.db import backend as _be_mod
    from opensquilla.attack_paths.web import create_attack_path_routes
    from tests._stubs.in_memory_backend import InMemoryStubBackend
    from starlette.routing import Mount
    from starlette.testclient import TestClient

    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    import asyncio
    async def _setup():
        await be.upsert_tree("t-pf", root_domain="x.com", root_node_id="n-root")
    asyncio.run(_setup())
    app = Mount("/attack-paths", routes=create_attack_path_routes())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/attack-paths/?tree_id=t-pf")
    body = r.text
    # The URL builder opens /control/chat with both ?prefill= and
    # ?tree= so the chat view can dispatch even if the slash catalog
    # hasn't finished loading.
    assert "/control/chat?" in body
    assert "prefill=" in body
    assert "tree=" in body
    # And it builds the slash command with the tree id
    assert "URLSearchParams" in body
    assert "'/attack-paths run ' + treeId" in body
