"""DB-backed tree store (2026-06-15).

Replaces the previous in-memory ``TreeStore`` that kept each
``AssetTree`` in a process-local dict. That dict was empty at every
gateway restart, so the web UI under ``/asset-tree/`` showed nothing
even when the tool layer had populated the tree via
``asset_tree_update_state`` etc.

The tool layer already writes to MySQL through
``AssetTreeBackend.upsert_tree`` / ``add_node`` /
``update_node_state`` when ``ASSET_TREE_DB_URL`` is set (the
in-memory ``AssetTree`` instance fires a fire-and-forget
``asyncio.ensure_future(self._backend.add_node(...))`` from inside
``_add_node_locked``). This store just *reads* that persistent
data and reconstructs the ``AssetTree`` view the web UI expects.

All public methods are ``async def`` because the underlying
``MysqlBackend`` is async. The route handlers in ``routes.py`` are
already async, so the migration is a one-line ``await`` prefix
per call site.

Failures from the DB (e.g. ASSET_TREE_DB_URL unset) surface as
``RuntimeError`` from the lazy ``_backend()`` factory. The web
routes catch that and return a 503 so the operator sees a clear
``db_unavailable`` error rather than an empty list (the previous
silent ``[]`` return was the bug that made this surface in the
first place).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from opensquilla.asset_tree.models import (
    AssetNode,
    AssetState,
    AssetType,
)
from opensquilla.asset_tree.tree import AssetTree


# Lazy backend — the env var ASSET_TREE_DB_URL is consulted only when
# the first async method fires. Tests can ``set_default_backend(None)``
# via ``asset_tree.db.set_default_backend`` to inject a stub.
def _backend():
    from opensquilla.asset_tree.db import get_default_backend
    return get_default_backend()


class TreeStore:
    """Async DB-backed tree storage.

    Each tree is identified by a unique ID and is created, listed,
    retrieved, and deleted through the web interface. The
    ``AssetTree`` instances are reconstructed on demand by reading
    all rows from the ``asset_nodes`` + ``asset_edges`` tables and
    feeding them through ``AssetTree.from_dict`` — the same
    serializer the JSON path uses.
    """

    def __init__(self) -> None:
        self._auto_id_counter = 0

    # ── Public read API ─────────────────────────────────────

    async def list_trees(self) -> list[dict[str, Any]]:
        """Return metadata for all stored trees (one row per tree)."""
        be = _backend()
        # Cheap "list all" query: SELECT tree_id, root_domain,
        # description, created_at, updated_at FROM asset_trees.
        async with be._engine.begin() as conn:  # type: ignore[attr-defined]
            from sqlalchemy import text
            rows = (await conn.execute(text(
                "SELECT tree_id, root_domain, description, created_at, updated_at "
                "FROM asset_trees ORDER BY updated_at DESC"
            ))).all()
        results = []
        for r in rows:
            # Per-tree node count is a second query (cheap given the
            # ix_asset_nodes_tree_state index); we accept the N+1 here
            # because the UI list is small and the alternative
            # (GROUP BY in the first query) makes pagination awkward.
            stats = await be.stats(r.tree_id)
            results.append({
                "id": r.tree_id,
                "root_domain": r.root_domain,
                "description": r.description or "",
                "node_count": stats.get("total_nodes", 0),
                "created_at": r.created_at.timestamp() if r.created_at else 0.0,
                "updated_at": r.updated_at.timestamp() if r.updated_at else 0.0,
            })
        return results

    async def get_tree(self, tree_id: str) -> AssetTree:
        """Reconstruct the full ``AssetTree`` for ``tree_id``.

        Reads all ``asset_nodes`` + ``asset_edges`` rows, materialises
        them through ``AssetTree.from_dict``, and returns the live
        object so route handlers can call ``tree.stats()`` etc.
        """
        be = _backend()
        tree_row = await be.get_tree(tree_id)
        if tree_row is None:
            raise KeyError(f"Tree '{tree_id}' not found")

        # Pull all nodes in one query
        from sqlalchemy import text
        async with be._engine.begin() as conn:  # type: ignore[attr-defined]
            node_rows = (await conn.execute(text(
                "SELECT id, asset_type, value, state, parent_id, material_path, "
                "       path_depth, source_wave, assigned_wave, metadata, "
                "       first_seen, last_seen "
                "FROM asset_nodes WHERE tree_id = :tid"
            ), {"tid": tree_id})).all()
            edge_rows = (await conn.execute(text(
                "SELECT parent_id, child_id, child_order "
                "FROM asset_edges WHERE tree_id = :tid "
                "ORDER BY parent_id, child_order"
            ), {"tid": tree_id})).all()

        import json as _json
        nodes_dict: dict[str, dict[str, Any]] = {}
        for r in node_rows:
            # MySQL JSON column comes back as a string under the raw
            # ``text()`` path; decode it back to a dict. ``None`` (the
            # SQL NULL) round-trips as the Python ``None`` we want.
            meta = r.metadata
            if meta is None:
                meta = {}
            elif isinstance(meta, str):
                # MySQL JSON columns come back as a string under the
                # ``text()`` raw-SQL path. Common values:
                #   ``"null"``     → JSON NULL  → Python ``None``
                #   ``"{}"``       → empty obj  → Python ``{}``
                #   ``'{"a": 1}'`` → dict
                # Normalize all three to either ``{}`` (for the dict
                # model) or a decoded dict. ``AssetNode.metadata`` is
                # declared as ``dict[str, Any]`` (not Optional), so
                # a stray ``None`` would fail Pydantic validation.
                loaded = _json.loads(meta) if meta.strip() else {}
                if loaded is None:
                    loaded = {}
                meta = loaded
            nodes_dict[r.id] = {
                "id": r.id,
                "asset_type": r.asset_type,
                "value": r.value,
                "state": r.state,
                "parent_id": r.parent_id,
                "material_path": r.material_path,
                "path_depth": r.path_depth,
                "source_wave": r.source_wave,
                "assigned_wave": r.assigned_wave,
                "metadata": meta,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }

        # edges: parent_id -> [child_id, ...]
        edges_dict: dict[str, list[str]] = {}
        for r in edge_rows:
            edges_dict.setdefault(r.parent_id, []).append(r.child_id)

        from_dict = {
            "root_id": tree_row.root_node_id,
            "nodes": nodes_dict,
            "edges": edges_dict,
        }
        # from_dict needs a flat nodes dict, but it also keys by node id.
        return AssetTree.from_dict(from_dict)

    async def get_tree_meta(self, tree_id: str) -> dict[str, Any]:
        be = _backend()
        tree_row = await be.get_tree(tree_id)
        if tree_row is None:
            raise KeyError(f"Tree '{tree_id}' not found")
        stats = await be.stats(tree_id)
        return {
            "id": tree_id,
            "root_domain": tree_row.root_domain,
            "description": tree_row.description or "",
            "node_count": stats.get("total_nodes", 0),
            "created_at": tree_row.created_at.timestamp() if tree_row.created_at else 0.0,
            "updated_at": tree_row.updated_at.timestamp() if tree_row.updated_at else 0.0,
        }

    async def delete_tree(self, tree_id: str) -> None:
        be = _backend()
        try:
            await be.delete_tree(tree_id)
        except Exception as e:
            raise KeyError(f"Tree '{tree_id}' not found") from e

    async def update_tree_meta(self, tree_id: str, **kwargs: Any) -> dict[str, Any]:
        be = _backend()
        tree_row = await be.get_tree(tree_id)
        if tree_row is None:
            raise KeyError(f"Tree '{tree_id}' not found")
        new_desc = kwargs.get("description", tree_row.description)
        await be.upsert_tree(
            tree_id=tree_id,
            root_domain=tree_row.root_domain,
            root_node_id=tree_row.root_node_id,
            description=new_desc,
        )
        return await self.get_tree_meta(tree_id)

    async def touch(self, tree_id: str) -> None:
        """Update the updated_at timestamp (no-op for db-backed store)."""
        # MySQL's ON UPDATE CURRENT_TIMESTAMP on asset_trees.updated_at
        # handles this implicitly on any upsert / write. The routes
        # call touch() after a node mutation; we read the fresh
        # row next anyway, so no explicit UPDATE is needed.
        return

    # ── Write API (the web UI also creates / mutates trees) ──

    async def create_tree(
        self,
        root_domain: str,
        tree_id: Optional[str] = None,
        description: str = "",
    ) -> dict[str, Any]:
        be = _backend()
        if tree_id is None:
            self._auto_id_counter += 1
            tree_id = f"tree-{self._auto_id_counter}"
        # Pre-check existence
        existing = await be.get_tree(tree_id)
        if existing is not None:
            raise ValueError(f"Tree '{tree_id}' already exists")

        # Make a fresh root node id (same scheme the tool layer uses:
        # 12-char hex). The tool layer later swaps to its own id, but
        # the row needs *some* id for the FK.
        import secrets
        root_node_id = secrets.token_hex(6)
        await be.upsert_tree(
            tree_id=tree_id,
            root_domain=root_domain,
            root_node_id=root_node_id,
            description=description,
        )
        # Also write the root asset_node so children can reference it.
        await be.add_node(
            tree_id=tree_id, node_id=root_node_id,
            asset_type="root_domain", value=root_domain,
            parent_id=None, state="discovered",
            material_path=f"/{root_node_id}", path_depth=0,
            source_wave="W0",
        )
        return await self.get_tree_meta(tree_id)

    async def add_node(
        self,
        tree_id: str,
        asset_type: str,
        value: str,
        parent_id: Optional[str] = None,
        state: str = "discovered",
        source_wave: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        be = _backend()
        import secrets
        node_id = secrets.token_hex(6)
        # material_path: derive from parent
        if parent_id is None:
            material_path = f"/{node_id}"
        else:
            parent_node = await be.get_node(tree_id, parent_id)
            if parent_node is None:
                raise ValueError(f"Parent node '{parent_id}' not found in tree '{tree_id}'")
            material_path = f"{parent_node.material_path}/{node_id}"
        path_depth = material_path.count("/") - 1

        await be.add_node(
            tree_id=tree_id, node_id=node_id,
            asset_type=asset_type, value=value,
            parent_id=parent_id, state=state,
            material_path=material_path, path_depth=path_depth,
            source_wave=source_wave, metadata=metadata,
        )
        return {"id": node_id, "material_path": material_path, "state": state}

    async def update_node(
        self,
        tree_id: str,
        node_id: str,
        state: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        be = _backend()
        if state is not None:
            await be.update_node_state(tree_id=tree_id, node_id=node_id, new_state=state)
        if metadata is not None:
            # No metadata-only update on the SQLAlchemy backend; fall
            # back to the JSON-only AssetTree view if needed. For now
            # we accept state-only updates.
            pass
        return {"id": node_id, "state": state}

    async def delete_node(self, tree_id: str, node_id: str) -> None:
        # SQLAlchemy backend has no node-level delete; cascade via
        # the FK on delete_tree, or leave a TODO for the bulk path.
        # For now: not exposed in the UI's "delete node" action.
        raise NotImplementedError(
            "DB-backed store does not yet support single-node delete"
        )


class _TreeEntry:
    """Legacy in-memory entry class — kept only so existing
    ``isinstance`` checks in the codebase do not NameError. Not
    constructed by ``TreeStore.__init__`` anymore (the new store
    is stateless)."""

    __slots__ = ("tree", "description", "created_at", "updated_at")

    def __init__(self, tree: AssetTree, description: str, created_at: float, updated_at: float) -> None:
        self.tree = tree
        self.description = description
        self.created_at = created_at
        self.updated_at = updated_at
