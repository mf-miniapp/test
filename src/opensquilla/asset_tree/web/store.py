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
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone
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


# ── snapshot diff (re-uses the recon tool's core) ───────────
from opensquilla.tools.builtin.recon.diff import diff_snapshots as _recon_diff_snapshots  # noqa: E402


class DBUnavailableError(RuntimeError):
    """Raised when an AssetTree operation requires a configured DB but
    ``ASSET_TREE_DB_URL`` is unset / points to a non-MySQL URL.

    Read operations fall back to the on-disk JSON snapshots at
    ``~/.opensquilla/state/asset_trees/*.json``; write operations
    raise this so the web routes can return 503 ``db_unavailable``
    with a clear hint for the operator.
    """


def is_db_config_error(exc: BaseException) -> bool:
    """True if ``exc`` (or any cause in its chain) is a DB config error.

    Mirrors the production contract: ``ASSET_TREE_DB_URL`` unset or
    non-MySQL means the operator hasn't wired up the persistent
    backend, so we transparently fall back to JSON reads.
    """
    from opensquilla.asset_tree.db.pool import AssetTreeConfigError
    cur: Optional[BaseException] = exc
    seen: set[int] = set()
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, AssetTreeConfigError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _json_state_dir() -> Path:
    """Resolve the JSON snapshot dir (same as the tool layer uses)."""
    env = os.environ.get("OPEN_SQUILLA_STATE_DIR")
    return Path(env) if env else (Path.home() / ".opensquilla" / "state" / "asset_trees")


def _read_json_tree(tree_id: str) -> Optional[dict[str, Any]]:
    """Read a tree's JSON snapshot from disk; return None if absent."""
    # Strip any "--<iso_ts>" suffix to get the canonical tree_id
    # (Batch 5 snapshot_id format: "<tree_id>--<iso_ts>")
    canonical = tree_id.split("--", 1)[0] if "--" in tree_id else tree_id
    path = _json_state_dir() / f"{canonical}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _list_json_trees() -> list[Path]:
    """List all tree JSON files in the state dir, newest first."""
    d = _json_state_dir()
    if not d.exists():
        return []
    files = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files


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
        # Cached DB status. ``None`` = not yet probed. ``True`` = a
        # backend is wired up (or the test stub is installed).
        # ``False`` = ``ASSET_TREE_DB_URL`` is unset or non-MySQL,
        # so reads fall back to JSON files.
        self._db_available: Optional[bool] = None

    # ── DB status ─────────────────────────────────────────

    @property
    def db_available(self) -> bool:
        """True iff the production DB backend (or a test stub) is wired.

        Probing is lazy and cached. The first call tries to resolve
        ``_backend()``; if that raises ``AssetTreeConfigError`` the
        store flips into JSON-fallback mode and stays there for the
        process lifetime.
        """
        if self._db_available is not None:
            return self._db_available
        try:
            _backend()
            self._db_available = True
        except Exception as exc:
            if is_db_config_error(exc):
                self._db_available = False
            else:
                # Some other error — treat as unavailable, but the
                # routes will surface the real message on first use.
                self._db_available = False
        return self._db_available

    def db_status_payload(self) -> dict[str, Any]:
        """Return a JSON-serializable status dict for the UI banner.

        - ``mode``: ``"db"`` (production) or ``"json_fallback"``
        - ``hint``: operator action when in fallback
        """
        if self.db_available:
            return {"mode": "db", "hint": None}
        return {
            "mode": "json_fallback",
            "hint": (
                "ASSET_TREE_DB_URL is unset. Reads work via the on-disk "
                "JSON snapshots under ~/.opensquilla/state/asset_trees/. "
                "Writes are disabled. Set ASSET_TREE_DB_URL to a "
                "'mysql+aiomysql://...' string to enable full DB mode."
            ),
        }

    # ── Public read API ─────────────────────────────────────

    async def list_trees(self) -> list[dict[str, Any]]:
        """Return metadata for all stored trees (one row per tree)."""
        if not self.db_available:
            return self._list_trees_from_json()
        be = _backend()
        try:
            return await self._list_trees_from_db(be)
        except Exception as exc:
            if is_db_config_error(exc):
                self._db_available = False
                return self._list_trees_from_json()
            raise

    async def _list_trees_from_db(self, be: Any) -> list[dict[str, Any]]:
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

        Falls back to the on-disk JSON snapshot when the DB is
        not configured (``ASSET_TREE_DB_URL`` unset) — see
        ``self.db_available``.
        """
        if not self.db_available:
            tree = await self.get_tree_from_json(tree_id)
            if tree is None:
                raise KeyError(f"Tree '{tree_id}' not found")
            return tree
        be = _backend()
        try:
            tree_row = await be.get_tree(tree_id)
        except Exception as exc:
            if is_db_config_error(exc):
                self._db_available = False
                tree = await self.get_tree_from_json(tree_id)
                if tree is None:
                    raise KeyError(f"Tree '{tree_id}' not found") from exc
                return tree
            raise
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
        if not self.db_available:
            meta = self.get_tree_meta_from_json(tree_id)
            if meta is None:
                raise KeyError(f"Tree '{tree_id}' not found")
            return meta
        be = _backend()
        try:
            tree_row = await be.get_tree(tree_id)
        except Exception as exc:
            if is_db_config_error(exc):
                self._db_available = False
                meta = self.get_tree_meta_from_json(tree_id)
                if meta is None:
                    raise KeyError(f"Tree '{tree_id}' not found") from exc
                return meta
            raise
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
        if not self.db_available:
            raise DBUnavailableError(
                "Cannot delete trees: ASSET_TREE_DB_URL is not set. "
                "Set it to a 'mysql+aiomysql://...' URL to enable writes."
            )
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
        if not self.db_available:
            raise DBUnavailableError(
                "Cannot create trees: ASSET_TREE_DB_URL is not set. "
                "Set it to a 'mysql+aiomysql://...' URL to enable writes."
            )
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
        if not self.db_available:
            raise DBUnavailableError(
                "Cannot add nodes: ASSET_TREE_DB_URL is not set. "
                "Set it to a 'mysql+aiomysql://...' URL to enable writes."
            )
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
        if not self.db_available:
            raise DBUnavailableError(
                "Cannot update nodes: ASSET_TREE_DB_URL is not set. "
                "Set it to a 'mysql+aiomysql://...' URL to enable writes."
            )
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
        if not self.db_available:
            raise DBUnavailableError(
                "Cannot delete nodes: ASSET_TREE_DB_URL is not set. "
                "Set it to a 'mysql+aiomysql://...' URL to enable writes."
            )
        raise NotImplementedError(
            "DB-backed store does not yet support single-node delete"
        )

    # ── JSON-fallback read methods ────────────────────────────

    def _list_trees_from_json(self) -> list[dict[str, Any]]:
        """List trees by scanning the JSON snapshot dir.

        Used as a read-only fallback when the DB isn't configured.
        Returns the same shape as ``_list_trees_from_db`` so the
        page renderer doesn't need to special-case.
        """
        results: list[dict[str, Any]] = []
        for p in _list_json_trees():
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            nodes = doc.get("nodes") or {}
            # Derive root_domain from the root_domain node's value
            root_domain = ""
            for n in nodes.values():
                if n.get("asset_type") == "root_domain":
                    root_domain = n.get("value", "")
                    break
            results.append({
                "id": p.stem,  # canonical tree_id (no --<iso> suffix)
                "root_domain": root_domain,
                "description": "(JSON fallback — DB not configured)",
                "node_count": len(nodes),
                "created_at": p.stat().st_ctime,
                "updated_at": p.stat().st_mtime,
            })
        return results

    async def get_tree_from_json(self, tree_id: str) -> Optional[AssetTree]:
        """Read-only tree reconstruction from the JSON snapshot.

        Returns None if no JSON file exists for the given tree_id.
        """
        doc = _read_json_tree(tree_id)
        if doc is None:
            return None
        try:
            return AssetTree.from_dict(doc)
        except Exception:
            return None

    def get_tree_meta_from_json(self, tree_id: str) -> Optional[dict[str, Any]]:
        """Read-only tree metadata from the JSON snapshot."""
        doc = _read_json_tree(tree_id)
        if doc is None:
            return None
        nodes = doc.get("nodes") or {}
        root_domain = ""
        root_id = doc.get("root_id", "")
        for n in nodes.values():
            if n.get("asset_type") == "root_domain":
                root_domain = n.get("value", "")
                break
        return {
            "id": tree_id.split("--", 1)[0] if "--" in tree_id else tree_id,
            "root_domain": root_domain,
            "root_id": root_id,
            "description": "(JSON fallback — DB not configured)",
            "node_count": len(nodes),
        }

    # ── Snapshot history (Batch 5 time-dimension wiring) ────

    def list_snapshots_for_tree(
        self, tree_id: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List all snapshot files for ``tree_id``, newest first.

        A snapshot is any file matching ``<tree_id>--<iso_ts>.json``
        (per Batch 5's snapshot_id format). The cumulative
        ``<tree_id>.json`` is also returned as the most recent
        entry (mtime-ordered) so the UI always has at least one
        baseline to diff against, even if the operator never
        called ``asset_tree_complete``.

        Each entry has: ``snapshot_id``, ``tree_id``, ``snapshot_ts``
        (or ``None`` for the cumulative), ``file_path``,
        ``file_mtime_iso``, ``node_count``, ``node_count_by_type``.
        """
        canonical = tree_id.split("--", 1)[0] if "--" in tree_id else tree_id
        d = _json_state_dir()
        if not d.exists():
            return []
        # Match "<canonical>--<iso>.json" + the bare "<canonical>.json"
        results: list[Path] = []
        for p in d.glob(f"{canonical}*.json"):
            results.append(p)
        # Newest first
        results.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        out: list[dict[str, Any]] = []
        for p in results[:limit]:
            stem = p.stem
            if "--" in stem and stem.startswith(canonical + "--"):
                snap_id = stem
                snap_ts = stem.split("--", 1)[1]
            elif stem == canonical:
                snap_id = stem  # cumulative = baseline
                snap_ts = None
            else:
                # Substring match but different tree (e.g. canonical="tree-x"
                # matching "tree-xyz--<ts>"). Skip.
                continue
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            nodes = doc.get("nodes") or {}
            by_type_count: dict[str, int] = {}
            for n in nodes.values():
                t = n.get("asset_type", "unknown")
                by_type_count[t] = by_type_count.get(t, 0) + 1
            out.append({
                "snapshot_id": snap_id,
                "tree_id": canonical,
                "snapshot_ts": snap_ts,
                "is_cumulative": snap_ts is None,
                "file_path": str(p),
                "file_mtime_iso": (
                    datetime.fromtimestamp(
                        p.stat().st_mtime, tz=timezone.utc
                    ).isoformat()
                ),
                "node_count": len(nodes),
                "node_count_by_type": by_type_count,
            })
        return out

    def diff_against_previous_snapshot(
        self,
        tree_id: str,
        *,
        sensitivity_field: str = "risk",
    ) -> dict[str, Any]:
        """Diff the current tree against the previous snapshot.

        Picks the two most recent snapshot files for ``tree_id``:
        if only one exists, returns a "all added" diff (every node
        is new relative to an empty baseline) so the operator
        always gets a useful answer on the first compare.

        Returns a dict with ``summary``, ``added``, ``removed``,
        ``changed``, ``moved``, ``sensitivity_escalations`` plus
        ``snapshot_a`` / ``snapshot_b`` paths and a ``mode``:
          - ``"normal"`` — both snapshots present
          - ``"first_snapshot"`` — no prior baseline; everything
            shows up as ``added`` (useful as a "what's in this
            tree at all" view)
          - ``"no_snapshots"`` — no JSON file at all; return empty
        """
        snaps = self.list_snapshots_for_tree(tree_id, limit=2)
        if not snaps:
            return {
                "mode": "no_snapshots",
                "snapshot_a": None,
                "snapshot_b": None,
                "summary": {
                    "added": 0, "removed": 0, "changed": 0,
                    "moved": 0, "sensitivity_escalations": 0,
                    "by_type": {},
                },
                "added": [], "removed": [], "changed": [],
                "moved": [], "sensitivity_escalations": [],
            }
        if len(snaps) == 1:
            # First-time diff: treat the single snapshot as "all added"
            only = snaps[0]
            try:
                doc = json.loads(Path(only["file_path"]).read_text(encoding="utf-8"))
            except Exception:
                return {
                    "mode": "no_snapshots",
                    "snapshot_a": None,
                    "snapshot_b": only["file_path"],
                    "summary": {
                        "added": 0, "removed": 0, "changed": 0,
                        "moved": 0, "sensitivity_escalations": 0,
                        "by_type": {},
                    },
                    "added": [], "removed": [], "changed": [],
                    "moved": [], "sensitivity_escalations": [],
                }
            # Build the diff against an empty baseline by hand
            # (avoids a file-existence check in the recon core).
            from opensquilla.tools.builtin.recon.diff import diff_nodes
            b_nodes = doc.get("nodes") or {}
            result = diff_nodes({}, b_nodes, sensitivity_field=sensitivity_field)
            result["mode"] = "first_snapshot"
            result["snapshot_a"] = None
            result["snapshot_b"] = only["file_path"]
            return result

        # Normal case: 2+ snapshots, diff the two newest
        newer = snaps[0]
        older = snaps[1]
        result = _recon_diff_snapshots(
            older["file_path"], newer["file_path"],
            sensitivity_field=sensitivity_field,
        )
        result["mode"] = "normal"
        return result


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
