"""Vulnerabilities web 路由单测 (v6, 2026-06-19)。

覆盖:
  - GET / 列表 (空)
  - GET /?tree_id=... 过滤
  - GET /<vuln_id> 详情 (含边链)
  - GET /attack-path/<path_id>
  - GET /api/vulnerabilities
  - GET /api/vulnerabilities/<vuln_id>
  - GET /api/attack-paths/<path_id>
  - 模板渲染无 jinja 错误
"""
from __future__ import annotations

import asyncio
import time
import pytest

from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Mount

from opensquilla.vulnerabilities.web.routes import create_vulnerability_routes
from opensquilla.vulnerabilities.web.store import VulnStore
from opensquilla.asset_tree.web import store as _asset_tree_store
from tests._stubs.in_memory_backend import InMemoryStubBackend


# ── Fixtures ─────────────────────────────────────────────


@pytest.fixture()
def backend(monkeypatch):
    from opensquilla.asset_tree.db import backend as _db
    be = InMemoryStubBackend()
    _db.set_default_backend(be)
    monkeypatch.setattr(_asset_tree_store, "_backend", lambda: be)
    return be


@pytest.fixture()
def store(backend):
    return VulnStore()


@pytest.fixture()
def client(store):
    routes = create_vulnerability_routes(store)
    app = Starlette(routes=[Mount("/vulnerabilities", routes=routes)])
    return TestClient(app, raise_server_exceptions=False)


# ── Helpers ──────────────────────────────────────────────


async def _seed(backend):
    """写入 attack_path + 2 个 vuln 关联, 让 web 测试有数据看。"""
    # 1) attack_path
    await backend.upsert_attack_path(
        path_id="a" * 12,
        tree_id="tree-test",
        path_hash="h" * 40,
        status="completed",
        scope_string="root_domain=x → parameter=q",
        edge_chain_json={"edges": [
            {"edge_index": 0, "from_node_id": "r" * 12, "to_node_id": "s" * 12,
             "from_type": "root_domain", "to_type": "sub_domain",
             "from_value": "x", "to_value": "a.x",
             "edge_state": "discovered"},
            {"edge_index": 1, "from_node_id": "s" * 12, "to_node_id": "p" * 12,
             "from_type": "sub_domain", "to_type": "parameter",
             "from_value": "a.x", "to_value": "q",
             "edge_state": "exploited"},
        ]},
        leaf_node_id="p" * 12,
        leaf_type="parameter",
        leaf_value="q",
    )
    # 2) 2 个 vuln
    await backend.add_vulnerability(
        vuln_id="v" * 12,
        tree_id="tree-test", attack_path_id="a" * 12, leaf_node_id="p" * 12,
        cwe="CWE-89", cve="CVE-2024-9999", severity="critical",
        title="SQL Injection in q",
        description="Classic SQLi via parameter q",
        evidence={"wave": "W4", "tool": "sqlmap"},
        request="GET /?q=x' OR 1=1-- -",
        response="200 OK; rows leaked: 1234",
        payload="x' OR 1=1-- -",
        discovered_by_wave="W4", discovered_by_specialist="penetration",
    )
    await backend.add_vulnerability(
        vuln_id="w" * 12,
        tree_id="tree-test", attack_path_id="a" * 12, leaf_node_id="p" * 12,
        cwe=None, cve=None, severity="medium",
        title="Reflected XSS in q",
        description="q reflects without escape",
        evidence=None, request=None, response=None, payload=None,
        discovered_by_wave="W4", discovered_by_specialist="penetration",
    )
    # 3) 反哺到 leaf node
    await backend.add_node_vuln(
        tree_id="tree-test", node_id="p" * 12, vulnerability_id="v" * 12,
    )
    await backend.add_node_vuln(
        tree_id="tree-test", node_id="p" * 12, vulnerability_id="w" * 12,
    )


# ── Page tests ───────────────────────────────────────────


class TestListPage:
    def test_empty(self, client):
        resp = client.get("/vulnerabilities/")
        assert resp.status_code == 200
        assert "Vulnerabilities" in resp.text

    def test_with_data(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get("/vulnerabilities/?tree_id=tree-test")
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text
        assert "Reflected XSS" in resp.text
        # severity 颜色块
        assert "critical" in resp.text
        assert "medium" in resp.text

    def test_filter_by_severity(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get("/vulnerabilities/?tree_id=tree-test&severity=critical")
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text
        # 过滤后, medium vuln 不应出现
        assert "Reflected XSS" not in resp.text

    def test_filter_by_tree_id(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get("/vulnerabilities/?tree_id=tree-test")
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text

    def test_filter_by_node_id(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get("/vulnerabilities/?tree_id=tree-test&node_id=" + "p" * 12)
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text


class TestDetailPage:
    def test_404(self, client):
        resp = client.get("/vulnerabilities/000000000000")
        assert resp.status_code == 404

    def test_with_data(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get(f"/vulnerabilities/{'v' * 12}")
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text
        # 详情页应该渲染资产树边链
        assert "root_domain=x" in resp.text
        assert "parameter=q" in resp.text
        # request/response
        assert "GET /?q=x" in resp.text

    def test_with_evidence(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get(f"/vulnerabilities/{'v' * 12}")
        assert "sqlmap" in resp.text  # evidence_json 里的 tool


class TestAttackPathPage:
    def test_404(self, client):
        resp = client.get("/vulnerabilities/attack-path/000000000000")
        assert resp.status_code == 404

    def test_with_data(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get(f"/vulnerabilities/attack-path/{'a' * 12}")
        assert resp.status_code == 200
        assert "completed" in resp.text  # status badge
        assert "root_domain=x" in resp.text


# ── JSON API ─────────────────────────────────────────────


class TestJSONAPI:
    def test_list_api(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get("/vulnerabilities/api/vulnerabilities?tree_id=tree-test")
        assert resp.status_code == 200
        data = resp.json()
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 2

    def test_detail_api(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get(f"/vulnerabilities/api/vulnerabilities/{'v' * 12}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "SQL Injection in q"
        assert data["severity"] == "critical"
        assert data["cve"] == "CVE-2024-9999"

    def test_attack_path_api(self, client, backend):
        asyncio.run(_seed(backend))
        resp = client.get(f"/vulnerabilities/api/attack-paths/{'a' * 12}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["path_id"] == "a" * 12
        assert data["status"] == "completed"
