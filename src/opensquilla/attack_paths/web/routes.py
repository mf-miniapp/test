"""Attack Paths Web routes — dashboard + path detail (Starlette).

Pages
=====

- ``GET  /``                       — Dashboard (path list + KPIs)
- ``GET  /{path_id}``              — Path detail (edges + vulns + 反哺)

JSON API
========

- ``GET  /api/trees``                       — list trees (for dropdown)
- ``GET  /api/paths``                       — list paths (?tree_id=)
- ``GET  /api/paths/summary``               — KPI aggregates (?tree_id=)
- ``GET  /api/paths/{path_id}``             — full detail bundle
- ``POST /api/run``                         — run attack-paths orchestrator
                                              body: {tree_id | path_ids[], ...}
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import jinja2
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from opensquilla.attack_paths.web.store import AttackPathStore


logger = logging.getLogger(__name__)


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=True,
)


def _json_error(message: str, *, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _render(template_name: str, ctx: dict[str, Any]) -> HTMLResponse:
    template = _jinja_env.get_template(template_name)
    return HTMLResponse(template.render(**ctx))


def create_attack_path_routes(
    store: AttackPathStore | None = None,
) -> list[Route]:
    if store is None:
        store = AttackPathStore()

    # ── Page routes ───────────────────────────────────────

    async def page_dashboard(request: Request) -> Response:
        tree_id = request.query_params.get("tree_id")
        status_filter = request.query_params.get("status")
        trees = await store.list_trees_with_path_counts()
        # Auto-pick the first tree if none selected (so the dashboard
        # is useful the moment you land on it).
        if not tree_id and trees:
            tree_id = trees[0]["tree_id"]
        paths: list[dict[str, Any]] = []
        summary: dict[str, Any] | None = None
        if tree_id:
            paths = await store.list_paths(tree_id, status=status_filter)
            summary = await store.path_summary(tree_id)
        # Available status values for the filter chip row
        status_options = ["pending", "in_progress", "completed", "failed", "abandoned"]
        return _render("dashboard.html", {
            "trees": trees,
            "selected_tree_id": tree_id,
            "status_filter": status_filter,
            "status_options": status_options,
            "paths": [_path_to_dict(p) for p in paths],
            "summary": summary,
            "db_status": store.db_status_payload(),
            "version": "0.1.0",
        })

    async def page_detail(request: Request) -> Response:
        path_id = request.path_params["path_id"]
        bundle = await store.path_detail_bundle(path_id)
        if bundle is None:
            return _json_error(f"AttackPath '{path_id}' not found", status=404)
        return _render("path_detail.html", {
            "path": _path_to_dict(bundle["path"]),
            "edges": bundle["edges"],
            "vulnerabilities": bundle["vulnerabilities"],
            "node_feeds": bundle["node_feeds"],
            "db_status": store.db_status_payload(),
            "version": "0.1.0",
        })

    # ── JSON API routes ──────────────────────────────────

    async def api_trees(request: Request) -> Response:
        trees = await store.list_trees_with_path_counts()
        return JSONResponse({"trees": trees})

    async def api_paths_list(request: Request) -> Response:
        tree_id = request.query_params.get("tree_id")
        if not tree_id:
            return _json_error("tree_id query param is required", status=400)
        status = request.query_params.get("status")
        paths = await store.list_paths(tree_id, status=status)
        return JSONResponse({
            "tree_id": tree_id,
            "paths": [_path_to_dict(p) for p in paths],
        })

    async def api_paths_summary(request: Request) -> Response:
        tree_id = request.query_params.get("tree_id")
        if not tree_id:
            return _json_error("tree_id query param is required", status=400)
        return JSONResponse(await store.path_summary(tree_id))

    async def api_path_detail(request: Request) -> Response:
        path_id = request.path_params["path_id"]
        bundle = await store.path_detail_bundle(path_id)
        if bundle is None:
            return _json_error(f"AttackPath '{path_id}' not found", status=404)
        return JSONResponse({
            "path": _path_to_dict(bundle["path"]),
            "vulnerabilities": bundle["vulnerabilities"],
            "node_feeds": bundle["node_feeds"],
            "edges": bundle["edges"],
        })

    async def api_run(request: Request) -> Response:
        """Run the orchestrator on a tree (HTTP convenience entry point).

        Note: as of 2026-06-19 the dashboard and path-detail surfaces no
        longer call this endpoint directly — they hand off to the chat
        view (via ``/control/chat?prefill=...``) so the user sees
        streaming progress and can interrupt mid-run.  This endpoint is
        kept for external callers (curl, scripts, other surfaces).

        Body JSON::

            {
              "tree_id":   "tree-...",         # required
              "path_ids":  ["...", "..."],     # optional subset (currently
                                               # orchestrator runs ALL pending;
                                               # this is a soft filter for UI)
              "dry_run":   false,
              "max_depth": 7,
              "include_states": ["unseen", "discovered", "triaged"],
              "auto_approve": true
            }

        Returns the standard :class:`RunAttackPathsResult` shape so the
        UI can update its KPIs and per-row counters without an extra
        round-trip.
        """
        try:
            body = await request.json()
        except Exception:
            return _json_error("body must be valid JSON", status=400)
        if not isinstance(body, dict):
            return _json_error("body must be a JSON object", status=400)
        tree_id = body.get("tree_id")
        if not isinstance(tree_id, str) or not tree_id.strip():
            return _json_error("tree_id is required", status=400)

        from opensquilla.orchestrator.run_attack_paths import (
            BuildAndRunError,
            BuildAndRunOptions,
            build_and_run_attack_paths,
        )

        states = body.get("include_states") or [
            "unseen", "discovered", "triaged",
        ]
        if isinstance(states, str):
            states = [s.strip() for s in states.split(",") if s.strip()]
        states = tuple(states)

        try:
            result = await build_and_run_attack_paths(BuildAndRunOptions(
                tree_id=tree_id.strip(),
                dry_run=bool(body.get("dry_run", False)),
                max_depth=int(body.get("max_depth", 7)),
                include_states=states,
                model=body.get("model"),
                provider=body.get("provider"),
                base_url=body.get("base_url"),
                api_key=body.get("api_key"),
                vuln_extractor=str(body.get("vuln_extractor", "default")),
                auto_approve=bool(body.get("auto_approve", True)),
            ))
        except BuildAndRunError as exc:
            msg = str(exc)
            return _json_error(f"attack-paths run failed: {msg}", status=503)
        except Exception as exc:  # noqa: BLE001
            logger.exception("api_run failed")
            return _json_error(f"unexpected error: {exc!r}", status=500)
        return JSONResponse({
            "tree_id": result.tree_id,
            "path_count": result.path_count,
            "written": result.written,
            "completed": result.completed,
            "failed": result.failed,
            "skipped": result.skipped,
            "vuln_total": result.vuln_total,
            "errors": list(result.errors or []),
        })

    return [
        # Page routes
        Route("/", page_dashboard, methods=["GET"]),
        Route("/{path_id}", page_detail, methods=["GET"]),
        # API routes
        Route("/api/trees", api_trees, methods=["GET"]),
        Route("/api/paths", api_paths_list, methods=["GET"]),
        Route("/api/paths/summary", api_paths_summary, methods=["GET"]),
        Route("/api/paths/{path_id}", api_path_detail, methods=["GET"]),
        Route("/api/run", api_run, methods=["POST"]),
    ]


# ── Serialization helper ──────────────────────────────────


def _path_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Project a vuln_attack_paths row to a JSON-safe dict.

    Strips the raw ``edge_chain_json`` blob and replaces it with a
    compact summary (edge count + leaf type) so the dashboard table
    doesn't bloat with the full chain.  The detail endpoint returns
    the full chain.
    """
    out = dict(row)
    ecj = out.get("edge_chain_json")
    if isinstance(ecj, str):
        try:
            ecj = json.loads(ecj)
        except json.JSONDecodeError:
            ecj = None
    if isinstance(ecj, dict):
        edges = ecj.get("edges", [])
        out["edge_count"] = len(edges) if isinstance(edges, list) else 0
        out["leaf_value"] = out.get("leaf_value") or (
            edges[-1].get("to_value") if edges else None
        )
    else:
        out["edge_count"] = 0
    return out
