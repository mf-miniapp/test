"""AssetTree backend abstraction — MySQL only.

A backend encapsulates all DB operations against the relational schema
defined in ``schema.py``. The ``AssetTree`` in-memory class is a session
cache; persistence goes through ``MysqlBackend`` (the only supported
backend, ``mysql+aiomysql://`` URL).
"""

from __future__ import annotations

import json
import logging
import threading
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from sqlalchemy import select, text
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from opensquilla.asset_tree.db.pool import (
    build_engine_from_url,
    build_session_factory,
    default_db_url,
)
from opensquilla.asset_tree.db.schema import (
    asset_edges,
    asset_evidence_refs,
    asset_nodes,
    asset_state_transitions,
    asset_trees,
)


logger = logging.getLogger(__name__)


# ── Public dataclass-like row types ───────────────────────────────


class TreeRow:
    """One row from ``asset_trees``."""

    __slots__ = ("tree_id", "root_domain", "description", "root_node_id",
                 "created_at", "updated_at")

    def __init__(self, **kwargs: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot))


class NodeRow:
    """One row from ``asset_nodes``."""

    __slots__ = (
        "id", "tree_id", "asset_type", "value", "state",
        "parent_id", "material_path", "path_depth",
        "source_wave", "assigned_wave", "metadata",
        "first_seen", "last_seen",
    )

    def __init__(self, **kwargs: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot))


# ── Backend ABC ────────────────────────────────────────────────


class AssetTreeBackend(ABC):
    """Abstract async backend interface.

    All methods are coroutines. Implementations MUST be safe to share
    across concurrent callers — connection pooling handles isolation.
    """

    @abstractmethod
    async def init_schema(self) -> None:
        """Create all tables + indexes if missing. Idempotent."""

    @abstractmethod
    async def drop_schema(self) -> None:
        """Drop everything. Test-only."""

    @abstractmethod
    async def upsert_tree(
        self,
        tree_id: str,
        root_domain: str,
        root_node_id: str,
        description: str | None = None,
    ) -> None:
        """Create or update a tree record."""

    @abstractmethod
    async def get_tree(self, tree_id: str) -> TreeRow | None:
        """Fetch a tree row, or None if missing."""

    @abstractmethod
    async def delete_tree(self, tree_id: str) -> None:
        """Cascade-delete a tree and all its nodes."""

    @abstractmethod
    async def add_node(
        self,
        *,
        node_id: str,
        tree_id: str,
        asset_type: str,
        value: str,
        state: str,
        parent_id: str | None,
        material_path: str,
        path_depth: int,
        source_wave: str | None = None,
        assigned_wave: str | None = None,
        metadata: dict[str, Any] | None = None,
        last_seen: Any | None = None,
    ) -> bool:
        """Insert a node. Returns True if inserted, False if it already
        existed (UNIQUE dedup constraint hit).

        ``parent_id``: ``None`` means "no parent" (root layer). The
        backend translates this to the empty-string sentinel internally
        so the UNIQUE dedup constraint can be enforced (NULL values in
        a UNIQUE constraint are never equal in MySQL).
        """

    @abstractmethod
    async def update_node_state(
        self,
        *,
        node_id: str,
        tree_id: str,
        new_state: str,
    ) -> bool:
        """Update state. Returns True on success, False if node not found."""

    @abstractmethod
    async def add_nodes_bulk(
        self,
        tree_id: str,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> tuple[list[bool], list[bool]]:
        """Bulk insert nodes + edges in a single transaction.

        Each entry in ``nodes`` and ``edges`` matches the kwargs of
        ``add_node`` / edge insert respectively (excluding the
        transaction-bridging tree_id, which is supplied here).

        Returns ``(node_results, edge_results)`` — booleans indicating
        whether each row was newly inserted (True) or deduped (False).
        All-or-nothing on transaction failure: if any node INSERT
        raises, the whole batch is rolled back.
        """

    @abstractmethod
    async def add_state_transition(
        self,
        *,
        tree_id: str,
        node_id: str,
        from_state: str,
        to_state: str,
    ) -> None:
        """Record a state transition in the audit log."""

    @abstractmethod
    async def get_node(self, tree_id: str, node_id: str) -> NodeRow | None:
        """Fetch a single node."""

    @abstractmethod
    async def find_node_root_layer(
        self,
        tree_id: str,
        asset_type: str,
        value: str,
    ) -> NodeRow | None:
        """Find a root-layer (parent_id IS NULL) node by (type, value)."""

    @abstractmethod
    async def find_nodes_by_value(
        self, tree_id: str, value: str
    ) -> list[NodeRow]:
        """Find all nodes with the given value (cross-parent safe)."""

    @abstractmethod
    async def get_children(self, tree_id: str, parent_id: str) -> list[NodeRow]:
        """Direct children of a parent, ordered by child_order."""

    @abstractmethod
    async def get_parent(
        self, tree_id: str, node_id: str
    ) -> NodeRow | None:
        """Fetch the parent node."""

    @abstractmethod
    async def get_path_to_root(
        self, tree_id: str, node_id: str
    ) -> list[NodeRow]:
        """Walk material_path to root, return [root, ..., node]."""

    @abstractmethod
    async def get_all_descendants(
        self, tree_id: str, node_id: str
    ) -> list[NodeRow]:
        """All nodes whose material_path starts with the parent's path."""

    @abstractmethod
    async def find_unseen(
        self, tree_id: str, asset_type: str | None = None
    ) -> list[NodeRow]:
        """List UNSEEN nodes (optionally filtered by asset_type)."""

    @abstractmethod
    async def stats(self, tree_id: str) -> dict[str, Any]:
        """Return summary stats for a tree."""

    @abstractmethod
    async def find_shared_ips(self, tree_id: str) -> dict[str, list[str]]:
        """{ip_value: [parent_id, ...]} — IPs shared by ≥2 sub_domains."""

    @abstractmethod
    async def close(self) -> None:
        """Release the connection pool."""


# ── SQLAlchemy async backend (shared impl) ─────────────────────


class _SqlAlchemyBackend(AssetTreeBackend):
    """Common SQLAlchemy 2.0 async implementation. MySQL only."""

    _INSERT_DIALECT_ATTR: str = ""  # set by subclasses

    def __init__(self, engine: AsyncEngine, session_factory: async_sessionmaker[Any]) -> None:
        self._engine = engine
        self._session_factory = session_factory
        self._lock = threading.Lock()

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        async with self._session_factory() as session:
            yield session

    # ── Schema management ─────────────────────────────────────

    async def init_schema(self) -> None:
        """Create all tables + indexes (dialect-aware via SQLAlchemy).

        We use ``MetaData.create_all`` instead of raw DDL because raw
        MySQL ``ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`` syntax is
        After creation we additionally run
        ``ALTER TABLE ... ENGINE=InnoDB`` to ensure the production
        storage engine is set even when SQLAlchemy's CREATE TABLE
        omitted it (it sometimes does for indexes-only diffs).
        """
        from opensquilla.asset_tree.db.schema import (
            all_metadata,
            asset_edges,
            asset_evidence_refs,
            asset_nodes,
            asset_state_transitions,
            asset_trees,
        )

        metadata = all_metadata()
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

        # MySQL post-creation: enforce InnoDB + utf8mb4 explicitly so a
        # CREATE TABLE emitted by SQLAlchemy that didn't specify the
        # engine still ends up with the right storage engine / charset.
        if self._INSERT_DIALECT_ATTR == "mysql":
            async with self._engine.begin() as conn:
                for tbl in (asset_trees, asset_nodes, asset_edges,
                            asset_state_transitions, asset_evidence_refs):
                    await conn.execute(text(
                        f"ALTER TABLE {tbl.name} "
                        "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 "
                        "COLLATE=utf8mb4_unicode_ci"
                    ))

    async def drop_schema(self) -> None:
        from opensquilla.asset_tree.db.schema import (
            asset_edges,
            asset_evidence_refs,
            asset_nodes,
            asset_state_transitions,
            asset_trees,
            all_metadata,
        )

        # Drop in FK-safe order via raw SQL (cleaner than metadata.drop_all
        # which may not respect CASCADE in all dialects).
        async with self._engine.begin() as conn:
            for tbl in (asset_evidence_refs, asset_state_transitions,
                       asset_edges, asset_nodes, asset_trees):
                await conn.execute(text(f"DROP TABLE IF EXISTS {tbl.name}"))

    # ── Trees ──────────────────────────────────────────────────

    async def upsert_tree(
        self,
        tree_id: str,
        root_domain: str,
        root_node_id: str,
        description: str | None = None,
    ) -> None:
        async with self._session() as session:
            async with session.begin():
                row = {
                    "tree_id": tree_id,
                    "root_domain": root_domain,
                    "root_node_id": root_node_id,
                    "description": description,
                }
                insert_stmt = self._insert_dialect(asset_trees).values(row)
                upsert = insert_stmt.on_duplicate_key_update(
                    root_domain=insert_stmt.inserted.root_domain,
                    root_node_id=insert_stmt.inserted.root_node_id,
                    description=insert_stmt.inserted.description,
                ) if self._INSERT_DIALECT_ATTR == "mysql" else \
                    insert_stmt.on_conflict_do_update(
                        index_elements=["tree_id"],
                        set_={
                            "root_domain": row["root_domain"],
                            "root_node_id": row["root_node_id"],
                            "description": row["description"],
                        },
                    )
                await session.execute(upsert)

    async def get_tree(self, tree_id: str) -> TreeRow | None:
        async with self._session() as session:
            row = (await session.execute(
                select(asset_trees).where(asset_trees.c.tree_id == tree_id)
            )).first()
            if row is None:
                return None
            return TreeRow(**dict(row._mapping))

    async def delete_tree(self, tree_id: str) -> None:
        async with self._session() as session:
            async with session.begin():
                await session.execute(
                    asset_trees.delete().where(asset_trees.c.tree_id == tree_id)
                )

    # ── Nodes ──────────────────────────────────────────────────

    async def add_node(
        self,
        *,
        node_id: str,
        tree_id: str,
        asset_type: str,
        value: str,
        state: str,
        parent_id: str | None,
        material_path: str,
        path_depth: int,
        source_wave: str | None = None,
        assigned_wave: str | None = None,
        metadata: dict[str, Any] | None = None,
        last_seen: Any | None = None,
    ) -> bool:
        """Insert node. Returns True on insert, False on dedup hit.

        Translates ``parent_id=None`` to ``""`` (NOT NULL sentinel) so
        the UNIQUE dedup constraint can enforce uniqueness at the DB
        layer — MySQL treats NULLs as distinct in UNIQUE indexes, which
        would silently allow duplicate root nodes.
        """
        parent_sentinel = parent_id if parent_id is not None else ""

        async with self._session() as session:
            try:
                async with session.begin():
                    row = {
                        "id": node_id,
                        "tree_id": tree_id,
                        "asset_type": asset_type,
                        "value": value,
                        "state": state,
                        "parent_id": parent_sentinel,
                        "material_path": material_path,
                        "path_depth": path_depth,
                        "source_wave": source_wave,
                        "assigned_wave": assigned_wave,
                        "metadata": metadata,
                    }
                    # Insert the node FIRST, then the edge. FK check
                    # fires per-statement, so the edge's reference to
                    # the child row must be satisfiable when the edge
                    # is inserted.
                    insert_node = self._insert_dialect(asset_nodes).values(row)
                    await session.execute(insert_node)
                    if parent_id is not None:
                        edges_row = {
                            "tree_id": tree_id,
                            "parent_id": parent_id,
                            "child_id": node_id,
                            "child_order": await self._next_child_order(
                                session, tree_id, parent_id
                            ),
                        }
                        insert_edges = self._insert_dialect(asset_edges).values(
                            edges_row
                        )
                        await session.execute(insert_edges)
                return True
            except IntegrityError as exc:
                # UNIQUE dedup constraint — node already exists.
                # MySQL ("Duplicate entry") embeds identifying info in
                # the exception; we accept any IntegrityError from a node
                # insert path as a dedup hit.
                err_str = str(exc).upper() + " " + str(exc.orig).upper()
                if "UNIQUE" in err_str:
                    return False
                raise

    async def add_nodes_bulk(
        self,
        tree_id: str,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> tuple[list[bool], list[bool]]:
        """Bulk insert nodes + edges in one transaction.

        Sort nodes by path_depth ascending (parents before children),
        pre-check existing rows for dedup detection, then insert
        node-by-node (so we can record per-row dedup status). Edge
        INSERTs come after all node INSERTs complete — this satisfies
        the edge FKs to both parent and child.
        """
        sorted_nodes = sorted(nodes, key=lambda n: n.get("path_depth", 0))
        node_results: list[bool] = []

        async with self._session() as session:
            try:
                async with session.begin():
                    existing_keys: set[tuple[str, str, str]] = set()
                    if sorted_nodes:
                        from sqlalchemy import or_, and_
                        conds = []
                        for n in sorted_nodes:
                            parent = n.get("parent_id")
                            sentinel = parent if parent is not None else ""
                            conds.append(and_(
                                asset_nodes.c.tree_id == tree_id,
                                asset_nodes.c.asset_type == n["asset_type"],
                                asset_nodes.c.parent_id == sentinel,
                                asset_nodes.c.value == n["value"],
                            ))
                        if conds:
                            r = await session.execute(
                                select(
                                    asset_nodes.c.asset_type,
                                    asset_nodes.c.parent_id,
                                    asset_nodes.c.value,
                                ).where(or_(*conds))
                            )
                            for row in r:
                                existing_keys.add((row[0], row[1], row[2]))

                    for n in sorted_nodes:
                        parent = n.get("parent_id")
                        sentinel = parent if parent is not None else ""
                        key = (n["asset_type"], sentinel, n["value"])
                        if key in existing_keys:
                            node_results.append(False)
                            continue
                        row = {
                            "id": n["node_id"],
                            "tree_id": tree_id,
                            "asset_type": n["asset_type"],
                            "value": n["value"],
                            "state": n.get("state", "unseen"),
                            "parent_id": sentinel,
                            "material_path": n["material_path"],
                            "path_depth": n.get("path_depth", sentinel.count("/")),
                            "source_wave": n.get("source_wave"),
                            "assigned_wave": n.get("assigned_wave"),
                            "metadata": n.get("metadata"),
                        }
                        stmt = self._insert_dialect(asset_nodes).values(row)
                        await session.execute(stmt)
                        node_results.append(True)

                    edge_results: list[bool] = []
                    for e in edges:
                        stmt = self._insert_dialect(asset_edges).values(
                            tree_id=tree_id,
                            parent_id=e["parent_id"],
                            child_id=e["child_id"],
                            child_order=e.get("child_order", 0),
                        )
                        await session.execute(stmt)
                        edge_results.append(True)
            except IntegrityError as exc:
                err_str = str(exc).upper() + " " + str(exc.orig).upper()
                if "UNIQUE" in err_str:
                    if node_results:
                        node_results[-1] = False
                else:
                    raise

        return node_results, []

    async def _next_child_order(
        self, session: AsyncSession, tree_id: str, parent_id: str
    ) -> int:
        """Compute the next child_order (max+1, or 0 for first child)."""
        result = await session.execute(
            select(asset_edges.c.child_order)
            .where(asset_edges.c.tree_id == tree_id,
                   asset_edges.c.parent_id == parent_id)
            .order_by(asset_edges.c.child_order.desc())
            .limit(1)
        )
        row = result.first()
        return (row[0] + 1) if row else 0

    async def update_node_state(
        self,
        *,
        node_id: str,
        tree_id: str,
        new_state: str,
    ) -> bool:
        async with self._session() as session:
            async with session.begin():
                result = await session.execute(
                    asset_nodes.update()
                    .where(asset_nodes.c.tree_id == tree_id,
                           asset_nodes.c.id == node_id)
                    .values(state=new_state)
                )
                return result.rowcount > 0

    async def add_state_transition(
        self,
        *,
        tree_id: str,
        node_id: str,
        from_state: str,
        to_state: str,
    ) -> None:
        async with self._session() as session:
            async with session.begin():
                await session.execute(
                    asset_state_transitions.insert().values(
                        tree_id=tree_id,
                        node_id=node_id,
                        from_state=from_state,
                        to_state=to_state,
                    )
                )

    async def get_node(self, tree_id: str, node_id: str) -> NodeRow | None:
        async with self._session() as session:
            row = (await session.execute(
                select(asset_nodes).where(
                    asset_nodes.c.tree_id == tree_id,
                    asset_nodes.c.id == node_id,
                )
            )).first()
            if row is None:
                return None
            return self._row_to_node(row._mapping)

    async def find_node_root_layer(
        self,
        tree_id: str,
        asset_type: str,
        value: str,
    ) -> NodeRow | None:
        async with self._session() as session:
            row = (await session.execute(
                select(asset_nodes).where(
                    asset_nodes.c.tree_id == tree_id,
                    asset_nodes.c.asset_type == asset_type,
                    asset_nodes.c.parent_id == "",  # root-layer sentinel
                    asset_nodes.c.value == value,
                ).limit(1)
            )).first()
            if row is None:
                return None
            return self._row_to_node(row._mapping)

    async def find_nodes_by_value(
        self, tree_id: str, value: str
    ) -> list[NodeRow]:
        async with self._session() as session:
            result = await session.execute(
                select(asset_nodes).where(
                    asset_nodes.c.tree_id == tree_id,
                    asset_nodes.c.value == value,
                )
            )
            return [self._row_to_node(r._mapping) for r in result]

    async def get_children(self, tree_id: str, parent_id: str) -> list[NodeRow]:
        async with self._session() as session:
            # JOIN edges + nodes ordered by child_order
            result = await session.execute(
                select(asset_nodes, asset_edges.c.child_order)
                .select_from(asset_edges)
                .join(asset_nodes,
                      (asset_nodes.c.tree_id == asset_edges.c.tree_id) &
                      (asset_nodes.c.id == asset_edges.c.child_id))
                .where(asset_edges.c.tree_id == tree_id,
                       asset_edges.c.parent_id == parent_id)
                .order_by(asset_edges.c.child_order)
            )
            return [self._row_to_node(r._mapping) for r in result]

    async def get_parent(
        self, tree_id: str, node_id: str
    ) -> NodeRow | None:
        async with self._session() as session:
            # Use the edges table reverse lookup
            row = (await session.execute(
                select(asset_nodes)
                .select_from(asset_edges)
                .join(asset_nodes,
                      (asset_nodes.c.tree_id == asset_edges.c.tree_id) &
                      (asset_nodes.c.id == asset_edges.c.parent_id))
                .where(asset_edges.c.tree_id == tree_id,
                       asset_edges.c.child_id == node_id)
                .limit(1)
            )).first()
            if row is None:
                return None
            return self._row_to_node(row._mapping)

    async def get_path_to_root(
        self, tree_id: str, node_id: str
    ) -> list[NodeRow]:
        async with self._session() as session:
            node = await self.get_node(tree_id, node_id)
            if node is None or not node.material_path:
                return []
            ids = node.material_path.split("/")
            if not ids:
                return []
            result = await session.execute(
                select(asset_nodes)
                .where(asset_nodes.c.tree_id == tree_id,
                       asset_nodes.c.id.in_(ids))
                .order_by(asset_nodes.c.path_depth)
            )
            return [self._row_to_node(r._mapping) for r in result]

    async def get_all_descendants(
        self, tree_id: str, node_id: str
    ) -> list[NodeRow]:
        async with self._session() as session:
            node = await self.get_node(tree_id, node_id)
            if node is None:
                return []
            prefix = node.material_path + "/"
            result = await session.execute(
                select(asset_nodes)
                .where(asset_nodes.c.tree_id == tree_id,
                       asset_nodes.c.material_path.like(prefix + "%"))
                .order_by(asset_nodes.c.path_depth)
            )
            return [self._row_to_node(r._mapping) for r in result]

    async def find_unseen(
        self, tree_id: str, asset_type: str | None = None
    ) -> list[NodeRow]:
        async with self._session() as session:
            stmt = select(asset_nodes).where(
                asset_nodes.c.tree_id == tree_id,
                asset_nodes.c.state == "unseen",
            )
            if asset_type is not None:
                stmt = stmt.where(asset_nodes.c.asset_type == asset_type)
            stmt = stmt.order_by(asset_nodes.c.path_depth, asset_nodes.c.id)
            result = await session.execute(stmt)
            return [self._row_to_node(r._mapping) for r in result]

    async def stats(self, tree_id: str) -> dict[str, Any]:
        async with self._session() as session:
            total = (await session.execute(
                select(asset_nodes.c.id)
                .where(asset_nodes.c.tree_id == tree_id)
            )).all()
            total_count = len(total)

            by_type_rows = (await session.execute(
                select(asset_nodes.c.asset_type)
                .where(asset_nodes.c.tree_id == tree_id)
            )).all()
            by_type: dict[str, int] = {}
            for (t,) in by_type_rows:
                by_type[t] = by_type.get(t, 0) + 1

            by_state_rows = (await session.execute(
                select(asset_nodes.c.state)
                .where(asset_nodes.c.tree_id == tree_id)
            )).all()
            by_state: dict[str, int] = {}
            for (s,) in by_state_rows:
                by_state[s] = by_state.get(s, 0) + 1

            depth_row = (await session.execute(
                select(asset_nodes.c.path_depth)
                .where(asset_nodes.c.tree_id == tree_id)
                .order_by(asset_nodes.c.path_depth.desc())
                .limit(1)
            )).first()
            max_depth = depth_row[0] if depth_row else 0

            shared_ips = await self.find_shared_ips(tree_id)

            tree = await self.get_tree(tree_id)
            root_domain = tree.root_domain if tree else None

            return {
                "total_nodes": total_count,
                "by_type": by_type,
                "by_state": by_state,
                "depth": max_depth,
                "shared_ips": len(shared_ips),
                "root_domain": root_domain,
            }

    async def find_shared_ips(self, tree_id: str) -> dict[str, list[str]]:
        async with self._session() as session:
            result = await session.execute(
                select(
                    asset_nodes.c.value,
                    asset_nodes.c.parent_id,
                )
                .where(
                    asset_nodes.c.tree_id == tree_id,
                    asset_nodes.c.asset_type == "ip",
                    asset_nodes.c.parent_id != "",  # exclude root layer
                )
            )
            ip_to_parents: dict[str, list[str]] = {}
            for value, parent_id in result:
                ip_to_parents.setdefault(value, []).append(parent_id)
            return {ip: ps for ip, ps in ip_to_parents.items() if len(ps) > 1}

    # ── Helpers ────────────────────────────────────────────────

    def _insert_dialect(self, table: Any) -> Any:
        """Return dialect-specific INSERT builder. MySQL only."""
        return mysql_insert(table)

    def _row_to_node(self, mapping: Any) -> NodeRow:
        """Convert a SQLAlchemy row mapping to a NodeRow.

        - ``metadata`` comes back as a JSON string on MySQL — parse it back.
        - ``parent_id``: the empty-string sentinel (NOT NULL storage)
          is translated back to ``None`` for the caller-facing API.
        """
        d = dict(mapping)
        meta = d.get("metadata")
        if isinstance(meta, str):
            try:
                d["metadata"] = json.loads(meta)
            except json.JSONDecodeError:
                d["metadata"] = None
        if d.get("parent_id") == "":
            d["parent_id"] = None
        return NodeRow(**d)

    async def close(self) -> None:
        await self._engine.dispose()


# ── Concrete backends ──────────────────────────────────────────


class MysqlBackend(_SqlAlchemyBackend):
    """MySQL backend — production.

    Requires ``aiomysql`` driver (``pip install aiomysql``). Default URL:
    ``mysql+aiomysql://opensquilla:secret@localhost:3306/opensquilla``.

    Uses ``INSERT ... ON DUPLICATE KEY UPDATE`` for upsert, taking
    advantage of MySQL's native JSON type.
    """

    _INSERT_DIALECT_ATTR = "mysql"



# ── Default factory ────────────────────────────────────────────


_default_backend: AssetTreeBackend | None = None
_default_backend_lock = threading.Lock()


def get_default_backend() -> AssetTreeBackend:
    """Lazy-init the default backend from ASSET_TREE_DB_URL.

    First call: builds engine + session factory + backend instance,
    AND runs the idempotent schema migration so the tool path is
    immediately usable. Subsequent calls: returns the cached singleton.

    Tests should call ``set_default_backend(None)`` (or build their own
    backend) to avoid sharing state across test runs.

    Schema migration is run in a worker thread (via asyncio.run) to
    sidestep "asyncio.run() cannot be called from a running event loop"
    when the first caller is itself inside an async context.
    """
    global _default_backend
    with _default_backend_lock:
        if _default_backend is None:
            url = default_db_url()
            engine = build_engine_from_url(url)
            factory = build_session_factory(engine)
            # pool.default_db_url() already validates and rejects non-MySQL,
            # but we double-check here to make the intent explicit.
            if not url.startswith("mysql"):
                from opensquilla.asset_tree.db.pool import AssetTreeConfigError
                raise AssetTreeConfigError(
                    f"AssetTree only supports MySQL (got URL: {url!r})."
                )
            backend: AssetTreeBackend = MysqlBackend(engine, factory)
            # Auto-migrate on first init so callers don't have to.
            try:
                import asyncio as _asyncio
                _asyncio.run(backend.init_schema())
            except RuntimeError:
                # Already inside an event loop — call from a thread.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    ex.submit(_asyncio.run, backend.init_schema()).result()
            _default_backend = backend
            logger.info("asset_tree_backend_init url=%s type=%s", url, type(backend).__name__)
        return _default_backend


def set_default_backend(backend: AssetTreeBackend | None) -> None:
    """Replace the default backend (test setup / teardown)."""
    global _default_backend
    with _default_backend_lock:
        _default_backend = backend