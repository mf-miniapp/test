"""Vulnerability Web routes — 列表 + 详情 (Starlette).

Page:
    GET  /                              → 漏洞列表 (可按 tree_id / node_id / severity 过滤)
    GET  /{vuln_id}                     → 漏洞详情 (含资产树全链路)
    GET  /attack-path/{path_id}         → 单条 attack-path 详情 (含 edge 链 + 关联漏洞)

API:
    GET  /api/vulnerabilities           → 列表 JSON
    GET  /api/vulnerabilities/{vuln_id} → 详情 JSON
    GET  /api/attack-paths/{path_id}    → attack-path JSON
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jinja2
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from opensquilla.vulnerabilities.web.store import VulnStore


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=True,
)


def _render(name: str, context: dict[str, Any]) -> HTMLResponse:
    tmpl = _jinja_env.get_template(name)
    return HTMLResponse(tmpl.render(**context))


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _vuln_to_dict(v: dict[str, Any]) -> dict[str, Any]:
    """Format a vuln row for JSON API responses."""
    return {
        "id": v.get("id"),
        "tree_id": v.get("tree_id"),
        "attack_path_id": v.get("attack_path_id"),
        "leaf_node_id": v.get("leaf_node_id"),
        "cwe": v.get("cwe"),
        "cve": v.get("cve"),
        "severity": v.get("severity"),
        "title": v.get("title"),
        "description": v.get("description"),
        "evidence": v.get("evidence_json"),
        "request": v.get("request"),
        "response": v.get("response"),
        "payload": v.get("payload"),
        "discovered_by_wave": v.get("discovered_by_wave"),
        "discovered_by_specialist": v.get("discovered_by_specialist"),
        "created_at": v.get("created_at"),
    }


def create_vulnerability_routes(store: VulnStore | None = None) -> list[Route]:
    if store is None:
        store = VulnStore()

    # ── Page routes ────────────────────────────────────────

    async def page_list(request: Request) -> Response:
        """漏洞列表页 — 支持 query params: tree_id, node_id, severity."""
        tree_id = request.query_params.get("tree_id")
        node_id = request.query_params.get("node_id")
        severity = request.query_params.get("severity")
        try:
            vulns = await store.list_vulnerabilities(
                tree_id=tree_id, node_id=node_id, severity=severity,
            )
        except Exception as exc:
            return _json_error(str(exc), status=503)
        return _render("vulnerabilities.html", {
            "vulnerabilities": [_vuln_to_dict(v) for v in vulns],
            "filter": {
                "tree_id": tree_id,
                "node_id": node_id,
                "severity": severity,
            },
            "db_status": store.db_status_payload(),
            "version": "0.1.0",
        })

    async def page_detail(request: Request) -> Response:
        """漏洞详情页 — 含资产树全链路 + 关联 attack_path."""
        vuln_id = request.path_params["vuln_id"]
        vuln = await store.get_vulnerability(vuln_id)
        if vuln is None:
            return _json_error(f"Vulnerability '{vuln_id}' not found", status=404)
        # 关联 attack_path
        ap: dict[str, Any] | None = None
        edges: list[dict[str, Any]] = []
        if vuln.get("attack_path_id"):
            ap = await store.get_attack_path(vuln["attack_path_id"])
            if ap:
                ecj = ap.get("edge_chain_json")
                if isinstance(ecj, str):
                    try:
                        ecj = json.loads(ecj)
                    except json.JSONDecodeError:
                        ecj = {}
                if isinstance(ecj, dict):
                    edges = ecj.get("edges", [])
        return _render("vulnerability_detail.html", {
            "vulnerability": _vuln_to_dict(vuln),
            "attack_path": ap,
            "edges": edges,
            "db_status": store.db_status_payload(),
        })

    async def page_attack_path(request: Request) -> Response:
        path_id = request.path_params["path_id"]
        ap = await store.get_attack_path(path_id)
        if ap is None:
            return _json_error(f"AttackPath '{path_id}' not found", status=404)
        ecj = ap.get("edge_chain_json")
        if isinstance(ecj, str):
            try:
                ecj = json.loads(ecj)
            except json.JSONDecodeError:
                ecj = {}
        edges = (ecj or {}).get("edges", [])
        return _render("attack_path_detail.html", {
            "attack_path": ap,
            "edges": edges,
            "db_status": store.db_status_payload(),
        })

    # ── JSON API routes ───────────────────────────────────

    async def api_list(request: Request) -> Response:
        tree_id = request.query_params.get("tree_id")
        node_id = request.query_params.get("node_id")
        severity = request.query_params.get("severity")
        try:
            vulns = await store.list_vulnerabilities(
                tree_id=tree_id, node_id=node_id, severity=severity,
            )
        except Exception as exc:
            return _json_error(str(exc), status=503)
        return JSONResponse(
            {"vulnerabilities": [_vuln_to_dict(v) for v in vulns]},
        )

    async def api_detail(request: Request) -> Response:
        vuln_id = request.path_params["vuln_id"]
        v = await store.get_vulnerability(vuln_id)
        if v is None:
            return _json_error(f"Vulnerability '{vuln_id}' not found", status=404)
        return JSONResponse(_vuln_to_dict(v))

    async def api_attack_path(request: Request) -> Response:
        path_id = request.path_params["path_id"]
        ap = await store.get_attack_path(path_id)
        if ap is None:
            return _json_error(f"AttackPath '{path_id}' not found", status=404)
        return JSONResponse(ap)

    return [
        # Page routes
        Route("/", page_list, methods=["GET"]),
        Route("/{vuln_id}", page_detail, methods=["GET"]),
        Route("/attack-path/{path_id}", page_attack_path, methods=["GET"]),
        # API routes
        Route("/api/vulnerabilities", api_list, methods=["GET"]),
        Route("/api/vulnerabilities/{vuln_id}", api_detail, methods=["GET"]),
        Route("/api/attack-paths/{path_id}", api_attack_path, methods=["GET"]),
    ]
