"""Asset Tree Web routes — REST API + HTML page for tree management.

API Endpoints (JSON):
    GET  /api/trees                          → list all trees
    POST /api/trees                          → create a new tree
    GET  /api/trees/{tree_id}                → get tree metadata + structure
    DELETE /api/trees/{tree_id}              → delete a tree
    POST /api/trees/{tree_id}/nodes          → add a node
    PUT  /api/trees/{tree_id}/nodes/{node_id} → update node state/metadata
    DELETE /api/trees/{tree_id}/nodes/{node_id} → remove a node
    GET  /api/trees/{tree_id}/stats          → get tree statistics
    GET  /api/trees/{tree_id}/nodes          → list nodes (optionally filtered by type)

Page:
    GET  / → HTML tree viewer / manager
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

import jinja2
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from opensquilla.asset_tree.models import (
    AssetNode,
    AssetState,
    AssetType,
    validate_parent_child,
)
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.asset_tree.web.store import DBUnavailableError, TreeStore
from opensquilla.asset_tree.db import get_default_backend as _get_backend

# ── Template loader ──────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=True,
)


def _render_template(name: str, context: dict[str, Any]) -> HTMLResponse:
    tmpl = _jinja_env.get_template(name)
    return HTMLResponse(tmpl.render(**context))


# ── JSON helpers ─────────────────────────────────────────────────

def _json_state_dir_for_route() -> Path:
    """Resolve the JSON snapshot dir (same as ``store._json_state_dir``)."""
    from opensquilla.asset_tree.web.store import _json_state_dir
    return _json_state_dir()


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _db_unavailable(request: Request) -> JSONResponse:
    """Return 503 ``db_unavailable`` with operator hint.

    Triggered when a write op fires while the store is in JSON-fallback
    mode (DB not configured), or when a read fails for the same reason.
    """
    return JSONResponse(
        {
            "error": (
                "AssetTree database is not configured. "
                "Set ASSET_TREE_DB_URL to a 'mysql+aiomysql://...' string."
            ),
            "code": "db_unavailable",
        },
        status_code=503,
    )


def _parse_body(request: Request, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse request body from JSON or form data."""
    if data is not None:
        return data
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        return json.loads(request._body)  # type: ignore[attr-defined]
    return {}


def _node_to_dict(node: AssetNode) -> dict[str, Any]:
    """Serialize an AssetNode for JSON API responses."""
    return {
        "id": node.id,
        "asset_type": node.asset_type.value,
        "value": node.value,
        "state": node.state.value,
        "parent_id": node.parent_id,
        "children_ids": node.children_ids,
        "source_wave": node.source_wave,
        "metadata": node.metadata,
        "first_seen": node.first_seen.isoformat() if node.first_seen else None,
        "last_seen": node.last_seen.isoformat() if node.last_seen else None,
    }


def _tree_to_dict(tree: AssetTree) -> dict[str, Any]:
    """Serialize the full tree for the frontend — flat nodes list with children_ids."""
    raw = tree.to_dict()
    nodes = list(raw["nodes"].values())
    # Add children_ids to each node for frontend rendering
    for node in nodes:
        nid = node["id"]
        children = raw["edges"].get(nid, [])
        node["children_ids"] = children
        node["state"] = node.get("state", "unseen")
        node["metadata"] = node.get("metadata", {})
        node["source_wave"] = node.get("source_wave", None)
    return {
        "root_domain": tree.root_domain,
        "root_id": tree.root_id,
        "nodes": nodes,
        "stats": tree.stats(),
    }


# ── Route handlers ──────────────────────────────────────────────


def create_asset_tree_routes(store: TreeStore | None = None) -> list[Route]:
    """Create all asset tree routes.

    Args:
        store: TreeStore instance. Creates a new one if None.
    """
    if store is None:
        store = TreeStore()

    async def api_list_trees(request: Request) -> Response:
        """GET /api/trees — list all trees."""
        trees = await store.list_trees()
        return JSONResponse({"trees": trees})

    async def api_create_tree(request: Request) -> Response:
        """POST /api/trees — create a new tree."""
        body = await _read_body(request)
        root_domain = body.get("root_domain", "").strip()
        if not root_domain:
            return _json_error("root_domain is required")
        tree_id = body.get("tree_id")
        description = body.get("description", "")
        try:
            meta = await store.create_tree(root_domain, tree_id=tree_id, description=description)
        except DBUnavailableError:
            return _db_unavailable(request)
        except ValueError as e:
            return _json_error(str(e), status=409)
        return JSONResponse(meta, status_code=201)

    async def api_get_tree(request: Request) -> Response:
        """GET /api/trees/{tree_id} — get tree metadata + structure."""
        tree_id = request.path_params["tree_id"]
        try:
            meta = await store.get_tree_meta(tree_id)
            tree = await store.get_tree(tree_id)
            data = {**meta, "tree": _tree_to_dict(tree)}
            return JSONResponse(data)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

    async def api_delete_tree(request: Request) -> Response:
        """DELETE /api/trees/{tree_id} — delete a tree."""
        tree_id = request.path_params["tree_id"]
        try:
            await store.delete_tree(tree_id)
            return JSONResponse({"deleted": tree_id})
        except DBUnavailableError:
            return _db_unavailable(request)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

    async def api_tree_stats(request: Request) -> Response:
        """GET /api/trees/{tree_id}/stats — get tree statistics."""
        tree_id = request.path_params["tree_id"]
        try:
            tree = await store.get_tree(tree_id)
            stats = tree.stats()
            return JSONResponse(stats)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

    async def api_tree_snapshots(request: Request) -> Response:
        """GET /api/trees/{tree_id}/snapshots — list historical snapshots.

        Batch 5 time-dimension support: each find-run that calls
        ``asset_tree_complete`` leaves a time-stamped copy at
        ``<tree_id>--<iso_ts>.json``. The cumulative
        ``<tree_id>.json`` is also returned as a baseline so the
        operator always has at least one entry to diff against.

        Query params:
          limit: cap the number of returned snapshots (newest first).
        """
        tree_id = request.path_params["tree_id"]
        limit = int(request.query_params.get("limit", "50"))
        if not _json_state_dir_for_route().exists():  # type: ignore[attr-defined]
            return JSONResponse({
                "tree_id": tree_id,
                "snapshot_count": 0,
                "snapshots": [],
            })
        snaps = store.list_snapshots_for_tree(tree_id, limit=limit)  # type: ignore[attr-defined]
        return JSONResponse({
            "tree_id": tree_id.split("--", 1)[0] if "--" in tree_id else tree_id,
            "snapshot_count": len(snaps),
            "snapshots": snaps,
        })

    async def api_tree_diff(request: Request) -> Response:
        """GET /api/trees/{tree_id}/diff — diff against the previous snapshot.

        Batch 5 time-dimension wiring. Picks the two most recent
        snapshot files for ``tree_id`` and runs the same diff
        algorithm as ``recon_diff_snapshots`` (LLM tool). On the
        very first compare, returns a ``first_snapshot`` diff
        where every node is "added" relative to an empty baseline.

        Query params:
          sensitivity_field: which metadata field to compare
            against the risk ladder (default "risk", matches the
            COOKIE/HEADER convention from cookie-header specialist).
        """
        tree_id = request.path_params["tree_id"]
        sensitivity_field = request.query_params.get("sensitivity_field", "risk")
        result = store.diff_against_previous_snapshot(  # type: ignore[attr-defined]
            tree_id, sensitivity_field=sensitivity_field,
        )
        result["tree_id"] = tree_id.split("--", 1)[0] if "--" in tree_id else tree_id
        return JSONResponse(result)

    async def api_list_nodes(request: Request) -> Response:
        """GET /api/trees/{tree_id}/nodes — list nodes, optionally filtered by type."""
        tree_id = request.path_params["tree_id"]
        try:
            tree = await store.get_tree(tree_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

        type_filter = request.query_params.get("type")
        if type_filter:
            try:
                at = AssetType(type_filter)
                nodes = [tree._nodes[nid] for nid in tree._by_type.get(at, [])]
            except ValueError:
                return _json_error(f"Invalid asset type: {type_filter}")
        else:
            nodes = list(tree._nodes.values())

        return JSONResponse({
            "nodes": [_node_to_dict(n) for n in nodes],
            "total": len(nodes),
        })

    async def api_add_node(request: Request) -> Response:
        """POST /api/trees/{tree_id}/nodes — add a node."""
        tree_id = request.path_params["tree_id"]
        try:
            tree = await store.get_tree(tree_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

        body = await _read_body(request)
        asset_type_str = body.get("asset_type", "")
        value = body.get("value", "").strip()
        if not asset_type_str or not value:
            return _json_error("asset_type and value are required")

        try:
            asset_type = AssetType(asset_type_str)
        except ValueError:
            return _json_error(f"Invalid asset_type: {asset_type_str}")

        parent_id = body.get("parent_id") or tree.root_id  # default to root
        source_wave = body.get("source_wave")
        metadata = body.get("metadata", {})

        try:
            result = await store.add_node(
                tree_id=tree_id,
                asset_type=asset_type_str,
                value=value,
                parent_id=parent_id,
                state="discovered",
                source_wave=source_wave,
                metadata=metadata if isinstance(metadata, dict) else {},
            )
            await store.touch(tree_id)
            return JSONResponse(
                {
                    "id": result["id"],
                    "asset_type": asset_type_str,
                    "value": value,
                    "state": result["state"],
                    "parent_id": parent_id,
                    "material_path": result["material_path"],
                    "path_depth": result["material_path"].count("/") - 1,
                    "metadata": metadata if isinstance(metadata, dict) else {},
                    "source_wave": source_wave,
                    "children_ids": [],
                },
                status_code=201,
            )
        except DBUnavailableError:
            return _db_unavailable(request)
        except Exception as e:
            return _json_error(str(e), status=400)

    async def api_update_node(request: Request) -> Response:
        """PUT /api/trees/{tree_id}/nodes/{node_id} — update node state or metadata."""
        tree_id = request.path_params["tree_id"]
        node_id = request.path_params["node_id"]
        try:
            tree = await store.get_tree(tree_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

        node = tree.get_node(node_id)
        if node is None:
            return _json_error(f"Node '{node_id}' not found", status=404)

        body = await _read_body(request)

        # Update state (db path) + optional metadata merge
        new_state = body.get("state")
        new_meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else None
        if new_state is None and new_meta is None:
            return _json_error("No fields to update")
        try:
            await store.update_node(
                tree_id=tree_id,
                node_id=node_id,
                state=new_state,
                metadata=new_meta,
            )
        except DBUnavailableError:
            return _db_unavailable(request)
        except ValueError as e:
            return _json_error(str(e), status=400)
        await store.touch(tree_id)
        # Re-fetch via store
        try:
            tree = await store.get_tree(tree_id)
            node = tree.get_node(node_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)
        return JSONResponse(_node_to_dict(node))

    async def api_tree_vulnerabilities_summary(request: Request) -> Response:
        """v6 (2026-06-19) — 资产树 web UI 用, 拿本树漏洞摘要。

        返回 ``{"vulnerabilities": [...]}`` 列表, 严重度降序,
        默认 limit=20 (UI 一次性展示够用)。
        """
        tree_id = request.path_params["tree_id"]
        try:
            tree = await store.get_tree(tree_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)
        try:
            be = _get_backend()
            vulns = await be.list_vulnerabilities(
                tree_id=tree_id, limit=20,
            )
        except Exception as e:
            return JSONResponse(
                {"vulnerabilities": [], "warning": str(e)},
            )
        # 序列化
        out = []
        for v in vulns:
            out.append({
                "id": v.get("id"),
                "severity": v.get("severity"),
                "title": v.get("title"),
                "cve": v.get("cve"),
                "cwe": v.get("cwe"),
                "leaf_node_id": v.get("leaf_node_id"),
                "discovered_by_wave": v.get("discovered_by_wave"),
                "discovered_by_specialist": v.get("discovered_by_specialist"),
            })
        return JSONResponse({"vulnerabilities": out})

    async def api_node_vulnerabilities(request: Request) -> Response:
        """v6 (2026-06-19) — 列出挂在某 node 上的 vulnerability id 列表。

        资产树 web UI 用这个 API 决定叶子节点是否变红 + 可点击跳转。
        返回 ``{"node_id": ..., "vulnerability_ids": [...]}``。
        """
        tree_id = request.path_params["tree_id"]
        node_id = request.path_params["node_id"]
        try:
            tree = await store.get_tree(tree_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)
        if tree.get_node(node_id) is None:
            return _json_error(f"Node '{node_id}' not found", status=404)
        # 调 backend.list_node_vulnerability_ids (vuln 4 表)
        try:
            be = _get_backend()
            vuln_ids = await be.list_node_vulnerability_ids(tree_id, node_id)
        except Exception as e:
            # backend 不可用 = 没有漏洞 (兼容 JSON 降级模式)
            return JSONResponse({
                "node_id": node_id, "vulnerability_ids": [], "warning": str(e),
            })
        return JSONResponse({"node_id": node_id, "vulnerability_ids": vuln_ids})

    async def api_delete_node(request: Request) -> Response:
        """DELETE /api/trees/{tree_id}/nodes/{node_id} — remove a node."""
        tree_id = request.path_params["tree_id"]
        node_id = request.path_params["node_id"]
        try:
            tree = await store.get_tree(tree_id)
        except KeyError:
            return _json_error(f"Tree '{tree_id}' not found", status=404)

        node = tree.get_node(node_id)
        if node is None:
            return _json_error(f"Node '{node_id}' not found", status=404)

        # Don't allow deleting root
        if node_id == tree.root_id:
            return _json_error("Cannot delete root node", status=400)

        tree.remove_subtree(node_id)
        try:
            await store.touch(tree_id)
        except DBUnavailableError:
            return _db_unavailable(request)
        return JSONResponse({"deleted": node_id})

    # ── Page route ──────────────────────────────────────────────

    async def page_index(request: Request) -> Response:
        """GET / — HTML tree viewer."""
        trees = await store.list_trees()
        db_status = store.db_status_payload()
        return _render_template("asset_tree.html", {
            "trees": trees,
            "db_status": db_status,
            "version": "0.3.1",
        })

    # ── Assemble routes ─────────────────────────────────────────

    return [
        # API routes
        Route("/api/trees", api_list_trees, methods=["GET"]),
        Route("/api/trees", api_create_tree, methods=["POST"]),
        Route("/api/trees/{tree_id}", api_get_tree, methods=["GET"]),
        Route("/api/trees/{tree_id}", api_delete_tree, methods=["DELETE"]),
        Route("/api/trees/{tree_id}/stats", api_tree_stats, methods=["GET"]),
        Route("/api/trees/{tree_id}/snapshots", api_tree_snapshots, methods=["GET"]),
        Route("/api/trees/{tree_id}/diff", api_tree_diff, methods=["GET"]),
        Route("/api/trees/{tree_id}/nodes", api_list_nodes, methods=["GET"]),
        Route("/api/trees/{tree_id}/nodes", api_add_node, methods=["POST"]),
        Route("/api/trees/{tree_id}/nodes/{node_id}", api_update_node, methods=["PUT"]),
        Route("/api/trees/{tree_id}/nodes/{node_id}", api_delete_node, methods=["DELETE"]),
        # v6 (2026-06-19) — 节点关联漏洞查询
        Route("/api/trees/{tree_id}/nodes/{node_id}/vulnerabilities", api_node_vulnerabilities, methods=["GET"]),
        # v6 (2026-06-19) — 资产页下方漏洞摘要
        Route("/api/trees/{tree_id}/vulnerabilities-summary", api_tree_vulnerabilities_summary, methods=["GET"]),
        # Page route (must be last to avoid shadowing)
        Route("/", page_index, methods=["GET"]),
    ]


async def _read_body(request: Request) -> dict[str, Any]:
    """Read and parse request body."""
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        try:
            body_bytes = await request.body()
            return json.loads(body_bytes) if body_bytes else {}
        except json.JSONDecodeError:
            return {}
    return {}
