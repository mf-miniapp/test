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
        self,
        tree_id: str,
        asset_type: str | None = None,
        *,
        max_depth: int | None = None,
    ) -> list[NodeRow]:
        """List UNSEEN nodes (optionally filtered by asset_type / depth).

        v5 (2026-06-18): ``max_depth`` filters by ``path_depth`` column.
        Default ``None`` = no depth filter (return all UNSEEN). When set,
        only nodes with ``path_depth <= max_depth`` are returned. Use
        ``max_depth=MAX_TREE_DEPTH`` (= 8) to keep the orchestrator
        from issuing waves against nodes that would push the tree past
        the business hard limit.
        """

    @abstractmethod
    async def stats(self, tree_id: str) -> dict[str, Any]:
        """Return summary stats for a tree."""

    @abstractmethod
    async def find_shared_ips(self, tree_id: str) -> dict[str, list[str]]:
        """{ip_value: [parent_id, ...]} — IPs shared by ≥2 sub_domains."""

    # ── v6 (2026-06-19) 漏洞与攻击路径 ABC 接口 ─────────────────────
    #
    # 4 张新表 (vuln_attack_paths / vulnerabilities / vuln_path_vulns /
    # vuln_node_vulns) 与 asset_tree 共享 connection pool; 这些方法
    # 构成 attack-path 编排链路的持久化基础。

    @abstractmethod
    async def upsert_attack_path(
        self,
        *,
        path_id: str,
        tree_id: str,
        path_hash: str,
        status: str,
        scope_string: str,
        edge_chain_json: dict[str, Any],
        leaf_node_id: str,
        leaf_type: str,
        leaf_value: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Create or no-op update on a vuln_attack_paths row.

        ``path_hash`` is the SHA1 hex of the edge chain — the UNIQUE
        constraint enforces idempotency: re-running the same topology
        returns the same path_id (idempotent re-ingest).
        """

    @abstractmethod
    async def update_attack_path_status(
        self,
        *,
        path_id: str,
        status: str,
        vuln_count: int | None = None,
        error: str | None = None,
        mark_started: bool = False,
        mark_completed: bool = False,
    ) -> None:
        """Update attack path status / counters / error.

        Exactly one of mark_started / mark_completed should be True
        when transitioning to in_progress / completed. If both False,
        only the status + counters are updated (used for failed
        transitions).
        """

    @abstractmethod
    async def get_attack_path(
        self, path_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single attack path row by id, or None."""

    @abstractmethod
    async def list_attack_paths(
        self, tree_id: str, status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List attack paths in a tree, optionally filtered by status."""

    @abstractmethod
    async def add_vulnerability(
        self,
        *,
        vuln_id: str,
        tree_id: str,
        attack_path_id: str | None,
        leaf_node_id: str,
        cwe: str | None,
        cve: str | None,
        severity: str,
        title: str,
        description: str | None,
        evidence: dict[str, Any] | None,
        request: str | None,
        response: str | None,
        payload: str | None,
        discovered_by_wave: str | None,
        discovered_by_specialist: str | None,
    ) -> None:
        """Insert one vulnerability row."""

    @abstractmethod
    async def add_path_vuln(
        self, *, attack_path_id: str, vulnerability_id: str,
    ) -> None:
        """Link a vulnerability to an attack path (M:N)."""

    @abstractmethod
    async def add_node_vuln(
        self, *, tree_id: str, node_id: str, vulnerability_id: str,
    ) -> None:
        """Link a vulnerability to a node (反哺资产树)."""

    @abstractmethod
    async def list_vulnerabilities(
        self,
        tree_id: str,
        *,
        attack_path_id: str | None = None,
        leaf_node_id: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """List vulnerabilities for a tree with optional filters."""

    @abstractmethod
    async def get_vulnerability(
        self, vuln_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single vulnerability row, or None."""

    @abstractmethod
    async def list_node_vulnerability_ids(
        self, tree_id: str, node_id: str,
    ) -> list[str]:
        """Return vulnerability ids associated with a node (反哺查询用)."""

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
            vuln_attack_paths,
            vuln_node_vulns,
            vuln_path_vulns,
            vulnerabilities,
        )

        metadata = all_metadata()
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

        # MySQL post-creation: enforce InnoDB + utf8mb4 explicitly so a
        # CREATE TABLE emitted by SQLAlchemy that didn't specify the
        # engine still ends up with the right storage engine / charset.
        # v6 (2026-06-19) 加 vuln_* 4 张表。
        if self._INSERT_DIALECT_ATTR == "mysql":
            async with self._engine.begin() as conn:
                for tbl in (asset_trees, asset_nodes, asset_edges,
                            asset_state_transitions, asset_evidence_refs,
                            vuln_attack_paths, vulnerabilities,
                            vuln_path_vulns, vuln_node_vulns):
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
        # Defensive precheck: ``asset_state_transitions`` has a FK to
        # ``asset_nodes`` (ON DELETE CASCADE). When an upstream
        # ``asset_tree_add_nodes`` bulk insert fails partway through,
        # the in-memory tree still calls ``update_state`` for nodes
        # that were never committed to MySQL, and the resulting FK
        # violation (errno 1452) floods the asyncio error log with
        # unretrievable tasks. Skip the audit insert if the parent
        # node row is missing — the state change is a no-op in that
        # case (no node → no node to update), and the next successful
        # ``add_nodes`` will record the proper transition.
        async with self._session() as session:
            async with session.begin():
                node_exists = (
                    await session.execute(
                        select(asset_nodes.c.id)
                        .where(
                            asset_nodes.c.tree_id == tree_id,
                            asset_nodes.c.id == node_id,
                        )
                        .limit(1)
                    )
                ).first()
                if node_exists is None:
                    logger.warning(
                        "asset_state_transition_skipped_missing_node "
                        "tree_id=%s node_id=%s from=%s to=%s",
                        tree_id, node_id, from_state, to_state,
                    )
                    return
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
        self,
        tree_id: str,
        asset_type: str | None = None,
        *,
        max_depth: int | None = None,
    ) -> list[NodeRow]:
        async with self._session() as session:
            stmt = select(asset_nodes).where(
                asset_nodes.c.tree_id == tree_id,
                asset_nodes.c.state == "unseen",
            )
            if asset_type is not None:
                stmt = stmt.where(asset_nodes.c.asset_type == asset_type)
            if max_depth is not None:
                stmt = stmt.where(asset_nodes.c.path_depth <= max_depth)
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

    # ── v6 (2026-06-19) 漏洞与攻击路径 SQLAlchemy 实现 ─────────────

    async def upsert_attack_path(
        self,
        *,
        path_id: str,
        tree_id: str,
        path_hash: str,
        status: str,
        scope_string: str,
        edge_chain_json: dict[str, Any],
        leaf_node_id: str,
        leaf_type: str,
        leaf_value: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Insert vuln_attack_paths, no-op on (tree_id, path_hash) conflict."""
        from sqlalchemy.dialects.mysql import insert as _mysql_insert
        from opensquilla.asset_tree.db.schema import vuln_attack_paths as _tap
        stmt = _mysql_insert(_tap).values(
            path_id=path_id,
            tree_id=tree_id,
            path_hash=path_hash,
            status=status,
            scope_string=scope_string,
            edge_chain_json=edge_chain_json,
            leaf_node_id=leaf_node_id,
            leaf_type=leaf_type,
            leaf_value=leaf_value,
            metadata=metadata,
        )
        # Idempotent: if the same (tree_id, path_hash) exists, keep
        # the existing row (path_id, status, leaf_*, etc.) untouched.
        stmt = stmt.on_duplicate_key_update(
            path_id=_tap.c.path_id,  # no-op
        )
        async with self._session() as session:
            await session.execute(stmt)
            await session.commit()

    async def update_attack_path_status(
        self,
        *,
        path_id: str,
        status: str,
        vuln_count: int | None = None,
        error: str | None = None,
        mark_started: bool = False,
        mark_completed: bool = False,
    ) -> None:
        from opensquilla.asset_tree.db.schema import vuln_attack_paths as _tap
        values: dict[str, Any] = {"status": status}
        if mark_started:
            values["started_at"] = datetime.now(timezone.utc)
        if mark_completed:
            values["completed_at"] = datetime.now(timezone.utc)
        if vuln_count is not None:
            values["vuln_count"] = vuln_count
        if error is not None:
            values["error"] = error
        async with self._session() as session:
            await session.execute(
                _tap.update().where(_tap.c.path_id == path_id).values(**values)
            )
            await session.commit()

    async def get_attack_path(
        self, path_id: str,
    ) -> dict[str, Any] | None:
        from opensquilla.asset_tree.db.schema import vuln_attack_paths as _tap
        async with self._session() as session:
            result = await session.execute(
                select(_tap).where(_tap.c.path_id == path_id)
            )
            row = result.first()
            if row is None:
                return None
            d = dict(row._mapping)
            for json_col in ("edge_chain_json", "metadata"):
                v = d.get(json_col)
                if isinstance(v, str):
                    try:
                        d[json_col] = json.loads(v)
                    except json.JSONDecodeError:
                        d[json_col] = None
            return d

    async def list_attack_paths(
        self, tree_id: str, status: str | None = None,
    ) -> list[dict[str, Any]]:
        from opensquilla.asset_tree.db.schema import vuln_attack_paths as _tap
        async with self._session() as session:
            stmt = select(_tap).where(_tap.c.tree_id == tree_id)
            if status is not None:
                stmt = stmt.where(_tap.c.status == status)
            stmt = stmt.order_by(_tap.c.created_at.desc())
            result = await session.execute(stmt)
            out: list[dict[str, Any]] = []
            for row in result:
                d = dict(row._mapping)
                for json_col in ("edge_chain_json", "metadata"):
                    v = d.get(json_col)
                    if isinstance(v, str):
                        try:
                            d[json_col] = json.loads(v)
                        except json.JSONDecodeError:
                            d[json_col] = None
                out.append(d)
            return out

    async def add_vulnerability(
        self,
        *,
        vuln_id: str,
        tree_id: str,
        attack_path_id: str | None,
        leaf_node_id: str,
        cwe: str | None,
        cve: str | None,
        severity: str,
        title: str,
        description: str | None,
        evidence: dict[str, Any] | None,
        request: str | None,
        response: str | None,
        payload: str | None,
        discovered_by_wave: str | None,
        discovered_by_specialist: str | None,
    ) -> None:
        from opensquilla.asset_tree.db.schema import vulnerabilities as _v
        async with self._session() as session:
            await session.execute(_v.insert().values(
                id=vuln_id, tree_id=tree_id,
                attack_path_id=attack_path_id, leaf_node_id=leaf_node_id,
                cwe=cwe, cve=cve, severity=severity, title=title,
                description=description, evidence_json=evidence,
                request=request, response=response, payload=payload,
                discovered_by_wave=discovered_by_wave,
                discovered_by_specialist=discovered_by_specialist,
            ))
            await session.commit()

    async def add_path_vuln(
        self, *, attack_path_id: str, vulnerability_id: str,
    ) -> None:
        from sqlalchemy.dialects.mysql import insert as _mysql_insert
        from opensquilla.asset_tree.db.schema import vuln_path_vulns as _vpv
        stmt = _mysql_insert(_vpv).values(
            attack_path_id=attack_path_id, vulnerability_id=vulnerability_id,
        )
        # Idempotent on duplicate (attack_path_id, vulnerability_id).
        stmt = stmt.on_duplicate_key_update(
            attack_path_id=_vpv.c.attack_path_id,
        )
        async with self._session() as session:
            await session.execute(stmt)
            await session.commit()

    async def add_node_vuln(
        self, *, tree_id: str, node_id: str, vulnerability_id: str,
    ) -> None:
        from sqlalchemy.dialects.mysql import insert as _mysql_insert
        from opensquilla.asset_tree.db.schema import vuln_node_vulns as _vnv
        stmt = _mysql_insert(_vnv).values(
            tree_id=tree_id, node_id=node_id, vulnerability_id=vulnerability_id,
        )
        stmt = stmt.on_duplicate_key_update(
            node_id=_vnv.c.node_id,
        )
        async with self._session() as session:
            await session.execute(stmt)
            await session.commit()

    async def list_vulnerabilities(
        self,
        tree_id: str,
        *,
        attack_path_id: str | None = None,
        leaf_node_id: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        from opensquilla.asset_tree.db.schema import vulnerabilities as _v
        async with self._session() as session:
            stmt = select(_v).where(_v.c.tree_id == tree_id)
            if attack_path_id is not None:
                stmt = stmt.where(_v.c.attack_path_id == attack_path_id)
            if leaf_node_id is not None:
                stmt = stmt.where(_v.c.leaf_node_id == leaf_node_id)
            if severity is not None:
                stmt = stmt.where(_v.c.severity == severity)
            # severity desc by enum rank (critical=1 ... info=5)
            _RANK = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
            stmt = stmt.order_by(_v.c.created_at.desc()).limit(limit)
            result = await session.execute(stmt)
            out: list[dict[str, Any]] = []
            for row in result:
                d = dict(row._mapping)
                ev = d.get("evidence_json")
                if isinstance(ev, str):
                    try:
                        d["evidence_json"] = json.loads(ev)
                    except json.JSONDecodeError:
                        d["evidence_json"] = None
                out.append(d)
            out.sort(key=lambda r: (_RANK.get(r.get("severity", "info"), 9),
                                    r.get("created_at") or ""))
            return out

    async def get_vulnerability(
        self, vuln_id: str,
    ) -> dict[str, Any] | None:
        from opensquilla.asset_tree.db.schema import vulnerabilities as _v
        async with self._session() as session:
            result = await session.execute(
                select(_v).where(_v.c.id == vuln_id)
            )
            row = result.first()
            if row is None:
                return None
            d = dict(row._mapping)
            ev = d.get("evidence_json")
            if isinstance(ev, str):
                try:
                    d["evidence_json"] = json.loads(ev)
                except json.JSONDecodeError:
                    d["evidence_json"] = None
            return d

    async def list_node_vulnerability_ids(
        self, tree_id: str, node_id: str,
    ) -> list[str]:
        from opensquilla.asset_tree.db.schema import vuln_node_vulns as _vnv
        async with self._session() as session:
            result = await session.execute(
                select(_vnv.c.vulnerability_id)
                .where(_vnv.c.tree_id == tree_id, _vnv.c.node_id == node_id)
            )
            return [r[0] for r in result]

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
            # The migration is best-effort: a failure here surfaces
            # later when the first write hits a missing table, so we
            # log and continue rather than wedging the backend into a
            # half-initialised state.
            try:
                import asyncio as _asyncio
                import concurrent.futures
                # Detect the running loop BEFORE creating the coroutine.
                # ``asyncio.run(coro)`` would otherwise create ``coro``
                # eagerly and then reject it from inside a running loop,
                # leaking the coroutine for GC to flag with
                # ``RuntimeWarning: coroutine ... was never awaited``.
                try:
                    _asyncio.get_running_loop()
                    in_running_loop = True
                except RuntimeError:
                    in_running_loop = False
                if in_running_loop:
                    # Fallback: already inside an event loop. Run the
                    # migration in a fresh thread so ``asyncio.run`` has
                    # its own loop. ``.result()`` blocks until the
                    # migration completes (and the coroutine inside the
                    # worker thread is awaited, not GC'd).
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=1
                    ) as ex:
                        ex.submit(
                            _asyncio.run, backend.init_schema()
                        ).result()
                else:
                    # Preferred path: no running loop → asyncio.run works.
                    _asyncio.run(backend.init_schema())
            except Exception as exc:  # noqa: BLE001 - best-effort migration
                logger.warning(
                    "asset_tree_backend_init_schema_failed error=%s",
                    exc,
                )
            _default_backend = backend
            logger.info("asset_tree_backend_init url=%s type=%s", url, type(backend).__name__)
        return _default_backend


def set_default_backend(backend: AssetTreeBackend | None) -> None:
    """Replace the default backend (test setup / teardown)."""
    global _default_backend
    with _default_backend_lock:
        _default_backend = backend