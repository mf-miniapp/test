"""Stub AssetTreeBackend for tests that don't want a real MySQL.

TreeStore calls into the default backend via the lazy ``_backend()`` factory.
The test fixture replaces ``opensquilla.asset_tree.db.get_default_backend``
with this stub, so the in-memory contract the old in-memory TreeStore had
is preserved for routes + UI tests.

This is intentionally NOT a real AssetTreeBackend ABC subclass — it provides
only the surface area ``web/store.py`` actually touches:

    - ``_engine`` (async context manager returning a connection with ``execute``)
    - ``stats(tree_id) -> dict``
    - ``get_tree(tree_id) -> TreeRow | None``
    - ``get_node(tree_id, node_id) -> NodeRow | None``
    - ``upsert_tree(...)``
    - ``add_node(...)``
    - ``update_node_state(...)``
    - ``delete_tree(tree_id)``

Storage is a nested dict: ``_trees[tree_id]`` -> ``TreeEntry`` (mirrors the
old in-memory shape). All methods are no-ops on the storage layer except
``add_node`` / ``update_node_state`` / ``upsert_tree`` / ``delete_tree``
which mutate it.
"""
from __future__ import annotations

import asyncio
import time
import secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager

def _utc_from_ts(ts: float):
    return datetime.fromtimestamp(ts, tz=timezone.utc)

from typing import Any, Optional


class _StubRow:
    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        try:
            return self._data[name]
        except KeyError as e:
            raise AttributeError(name) from e


class _StubTreeRow:
    __slots__ = ("tree_id", "root_domain", "root_node_id", "description", "created_at", "updated_at")

    def __init__(self, tree_id: str, root_domain: str, root_node_id: str,
                 description: str = "",
                 created_at=None, updated_at=None) -> None:
        self.created_at = created_at
        self.updated_at = updated_at
        self.tree_id = tree_id
        self.root_domain = root_domain
        self.root_node_id = root_node_id
        self.description = description
        self.created_at = created_at
        self.updated_at = updated_at


class _StubNodeRow:
    __slots__ = ("id", "asset_type", "value", "state", "parent_id", "material_path", "path_depth", "metadata")

    def __init__(self, **kwargs: Any) -> None:
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))


class InMemoryStubBackend:
    """Drop-in backend that satisfies the surface area web/store.py uses.

    It is NOT a real ``AssetTreeBackend`` subclass on purpose — keeping
    the surface narrow means tests don't have to implement 20 abstract
    methods, and the in-memory shape stays close to the original
    pre-MySQL design.
    """

    def __init__(self) -> None:
        self._trees: dict[str, dict[str, Any]] = {}
        self._nodes: dict[tuple[str, str], dict[str, Any]] = {}
        self._edges: dict[tuple[str, str], list[str]] = {}

    # ── SQL surface (raw text() path used by list_trees / get_tree) ──

    @property
    def _engine(self):
        return self

    @asynccontextmanager
    async def begin(self):
        yield _StubConn(self)

    # ── Asset tree CRUD ───────────────────────────────────────────

    async def get_tree(self, tree_id: str) -> Optional[_StubTreeRow]:
        t = self._trees.get(tree_id)
        if t is None:
            return None
        return _StubTreeRow(
            tree_id=tree_id,
            root_domain=t["root_domain"],
            root_node_id=t["root_node_id"],
            description=t.get("description", ""),
            created_at=t.get("created_at", 0.0),
            updated_at=t.get("updated_at", 0.0),
        )

    async def upsert_tree(
        self,
        tree_id: str,
        root_domain: str,
        root_node_id: str,
        description: str = "",
        **_: Any,
    ) -> None:
        now = time.time()
        if tree_id not in self._trees:
            self._trees[tree_id] = {
                "root_domain": root_domain,
                "root_node_id": root_node_id,
                "description": description,
                "created_at": _utc_from_ts(now),
                "updated_at": _utc_from_ts(now),
            }
        else:
            t = self._trees[tree_id]
            t["root_domain"] = root_domain
            t["root_node_id"] = root_node_id
            t["description"] = description
            t["updated_at"] = _utc_from_ts(now)

    async def delete_tree(self, tree_id: str) -> None:
        if tree_id not in self._trees:
            raise KeyError(f"Tree '{tree_id}' not found")
        self._trees.pop(tree_id, None)
        for k in [k for k in self._nodes if k[0] == tree_id]:
            self._nodes.pop(k, None)
        for k in [k for k in self._edges if k[0] == tree_id]:
            self._edges.pop(k, None)

    async def stats(self, tree_id: str) -> dict[str, Any]:
        nodes = [n for (tid, _), n in self._nodes.items() if tid == tree_id]
        return {
            "total_nodes": len(nodes),
            "depth": max((n.get("path_depth", 0) for n in nodes), default=0),
        }

    # ── Node CRUD ─────────────────────────────────────────────────

    async def get_node(self, tree_id: str, node_id: str) -> Optional[_StubNodeRow]:
        n = self._nodes.get((tree_id, node_id))
        return _StubNodeRow(**n) if n else None

    async def add_node(
        self,
        tree_id: str,
        node_id: str,
        asset_type: str,
        value: str,
        parent_id: Optional[str] = None,
        state: str = "discovered",
        material_path: Optional[str] = None,
        path_depth: int = 0,
        source_wave: Optional[str] = None,
        assigned_wave: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        **_: Any,
    ) -> None:
        self._nodes[(tree_id, node_id)] = {
            "id": node_id,
            "asset_type": asset_type,
            "value": value,
            "state": state,
            "parent_id": parent_id,
            "material_path": material_path or f"/{node_id}",
            "path_depth": path_depth,
            "metadata": metadata or {},
        }
        if parent_id:
            self._edges.setdefault((tree_id, parent_id), []).append(node_id)

    async def update_node_state(self, tree_id: str, node_id: str, new_state: str) -> None:
        # Mirror AssetState enum so routes that try an invalid state
        # get a ValueError (which the route catches → 400).
        valid = {"unseen", "discovered", "triaged", "exploited", "abandoned"}
        if new_state not in valid:
            raise ValueError(
                f"Invalid asset state {new_state!r}; must be one of {sorted(valid)}"
            )
        n = self._nodes.get((tree_id, node_id))
        if n is not None:
            n["state"] = new_state
        else:
            raise KeyError(f"Node '{node_id}' not found in tree '{tree_id}'")


class _StubConn:
    """Minimal connection that returns rows from a callback."""

    def __init__(self, backend: InMemoryStubBackend) -> None:
        self._backend = backend

    async def execute(self, stmt, params=None):
        # Parse the SQL — we only support the two queries TreeStore issues.
        text = str(stmt).lower()
        params = params or {}

        if "from asset_trees" in text and "from asset_nodes" not in text:
            # list_trees: SELECT tree_id, root_domain, description, created_at, updated_at
            #             FROM asset_trees ORDER BY updated_at DESC
            rows = []
            for tree_id, t in self._backend._trees.items():
                rows.append(_StubRow({
                    "tree_id": tree_id,
                    "root_domain": t["root_domain"],
                    "description": t.get("description", ""),
                    "created_at": t.get("created_at", 0.0),
                    "updated_at": t.get("updated_at", 0.0),
                }))
            rows.sort(key=lambda r: r._data["updated_at"], reverse=True)
            return _StubResult(rows)

        if "from asset_nodes" in text and "from asset_edges" not in text:
            # get_tree nodes: SELECT id, asset_type, value, state, parent_id, material_path,
            #                 path_depth, source_wave, assigned_wave, metadata,
            #                 first_seen, last_seen FROM asset_nodes WHERE tree_id = :tid
            tid = params.get("tid") or params.get("tree_id")
            rows = []
            for (tree_id, node_id), n in self._backend._nodes.items():
                if tree_id == tid:
                    rows.append(_StubRow({
                        "id": n["id"],
                        "asset_type": n["asset_type"],
                        "value": n["value"],
                        "state": n["state"],
                        "parent_id": n["parent_id"],
                        "material_path": n["material_path"],
                        "path_depth": n["path_depth"],
                        "source_wave": n.get("source_wave"),
                        "assigned_wave": n.get("assigned_wave"),
                        "metadata": n.get("metadata", {}),
                        "first_seen": None,
                        "last_seen": None,
                    }))
            return _StubResult(rows)

        if "from asset_edges" in text:
            # get_tree edges: SELECT parent_id, child_id, child_order
            #                 FROM asset_edges WHERE tree_id = :tid
            #                 ORDER BY parent_id, child_order
            tid = params.get("tid") or params.get("tree_id")
            rows = []
            for (tree_id, parent_id), children in self._backend._edges.items():
                if tree_id == tid:
                    for order, child_id in enumerate(children):
                        rows.append(_StubRow({
                            "parent_id": parent_id,
                            "child_id": child_id,
                            "child_order": order,
                        }))
            return _StubResult(rows)

        # Unknown query — return empty.
        return _StubResult([])


class _StubResult:
    def __init__(self, rows: list[_StubRow]) -> None:
        self._rows = rows

    def all(self) -> list[_StubRow]:
        return list(self._rows)


def install_stub_backend(monkeypatch) -> InMemoryStubBackend:
    """Replace the lazy backend factory with a fresh in-memory stub."""
    from opensquilla.asset_tree import db as _db
    from opensquilla.asset_tree.web import store as _store
    backend = InMemoryStubBackend()
    _db.set_default_backend(backend)  # type: ignore[arg-type]
    monkeypatch.setattr(_store, "_backend", lambda: backend)
    return backend
