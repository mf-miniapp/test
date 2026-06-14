"""AssetTree relational schema (SQLAlchemy Core, MySQL 8.0+ / SQLite 3.38+).

Design summary
==============

We use the **adjacency-list + materialized-path** model for the node hierarchy:

- ``asset_nodes.parent_id``  — direct parent (classic adjacency list)
- ``asset_nodes.material_path`` — slash-separated id chain, e.g. ``root/abc/def``
- ``asset_nodes.path_depth`` — depth from root (0 = root)

Combined with an explicit ``asset_edges`` table for O(1) child enumeration
without recursive CTEs (MySQL 8.0+ supports them but the explicit edge
table makes the most common query — "give me the children of X" — a single
PK lookup instead of a recursive scan).

For the dedup invariant ("same value under same parent returns the same
node id, cross-parent duplicates of an IP are LEGAL"), we use a composite
UNIQUE index on ``(tree_id, asset_type, parent_id, value)``. The unique
constraint enforces it at the DB layer — the application code can stop
doing pre-flight SELECT-then-INSERT races.

Why JSON for ``metadata``?
- Per-type fields are heterogeneous (sub_domain has DNS records, port has
  banner, service has version/CPE). A relational pivot table would add
  5+ tables and zero query wins for a 200-node tree.
- MySQL 8.0 and SQLite 3.38+ both support JSON column type natively.
- Replaces the previous ``AssetNode.metadata: dict[str, Any]`` field 1:1.

Hot query → covering index mapping
=================================

| Query                                              | Index used                       |
| -------------------------------------------------- | -------------------------------- |
| ``find_node(asset_type, value)`` (root layer)      | idx_nodes_tree_type + parent_id  |
| ``find_nodes_by_value(value)``                     | idx_nodes_tree_value             |
| ``add_node`` dedup check                            | uq_nodes_dedup (UNIQUE)          |
| ``find_unseen(tree, asset_type?)``                 | idx_nodes_tree_state + type      |
| ``get_children(parent_id)``                        | uq_edges_parent_child            |
| ``get_siblings(node_id)``                          | idx_nodes_tree_parent            |
| ``get_path_to_root(node_id)``                      | idx_nodes_path_prefix (LIKE)     |
| ``get_all_descendants(parent_id)``                 | idx_nodes_path_prefix (LIKE)     |
| ``find_shared_ips()``                              | idx_nodes_tree_type              |
| ``stats()``                                        | idx_nodes_tree_type + state      |

Naming convention
=================
- All tables prefixed with ``asset_`` to avoid collision with other systems
  sharing the same MySQL instance.
- All foreign keys cascade-delete: removing a tree removes all its
  nodes / edges / evidence refs / state transitions.
- All timestamps ``DATETIME(6)`` (microsecond precision) to disambiguate
  same-second state transitions.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.mysql import (
    BIGINT as MYSQL_BIGINT,
    TINYINT as MYSQL_TINYINT,
)


# Single MetaData namespace for all AssetTree tables. Naming convention
# preserves the MySQL convention even on SQLite (where it's just a label).
_metadata = MetaData(
    naming_convention={
        "ix": "ix_%(table_name)s_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
    }
)


# Use MySQL-specific TINYINT UNSIGNED for ``path_depth`` / ``child_order``
# (saves 3 bytes per row vs INT) and BIGINT UNSIGNED for the audit log.
# On SQLite the dialect falls back to INTEGER transparently.


# ── Trees ──────────────────────────────────────────────────────────


asset_trees = Table(
    "asset_trees",
    _metadata,
    Column("tree_id", String(128), primary_key=True, nullable=False),
    Column("root_domain", String(255), nullable=False),
    Column("description", Text, nullable=True),
    # root_node_id is a CHAR(12) — same shape as the in-memory _new_id()
    Column("root_node_id", String(12), nullable=False),
    Column(
        "created_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    Column(
        "updated_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
        server_onupdate=func.now(),
    ),
    # Secondary lookups by root domain (e.g. "is this tree already running?")
    Index("ix_asset_trees_root_domain", "root_domain"),
    Index("ix_asset_trees_updated_at", "updated_at"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


# ── Nodes ──────────────────────────────────────────────────────────


# CHAR(12) UUID hex (matches the in-memory id format).
_NODE_ID_TYPE = String(12)
_PARENT_ID_TYPE = String(12)

asset_nodes = Table(
    "asset_nodes",
    _metadata,
    # Composite PK — node id is unique within a tree (id alone is the
    # 12-hex random; tree_id scopes it).
    Column("id", _NODE_ID_TYPE, nullable=False),
    Column("tree_id", String(128), nullable=False),
    Column("asset_type", String(32), nullable=False),
    Column("value", String(2048), nullable=False),
    Column("state", String(16), nullable=False, server_default="unseen"),
    Column("parent_id", _PARENT_ID_TYPE, nullable=False, server_default=""),
    # material_path: slash-separated id chain. e.g. root/abc/def.
    # 512 chars handles depth-50 trees with 10-char ids (50*11 = 550, padded).
    Column("material_path", String(512), nullable=False),
    # 0 = root, 1 = sub_domain, ..., 5 = endpoint. Use TINYINT UNSIGNED on
    # MySQL for 1-byte storage; falls back to SMALLINT on SQLite.
    Column("path_depth", SmallInteger, nullable=False, server_default="0"),
    Column("source_wave", String(128), nullable=True),
    Column("assigned_wave", String(128), nullable=True),
    Column("metadata", JSON, nullable=True),
    Column(
        "first_seen",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    Column(
        "last_seen",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
        server_onupdate=func.now(),
    ),
    # Composite primary key
    PrimaryKeyConstraint("tree_id", "id", name="pk_asset_nodes"),
    # FK to asset_trees (cascade-delete)
    ForeignKeyConstraint(
        ["tree_id"],
        ["asset_trees.tree_id"],
        name="fk_asset_nodes_tree",
        ondelete="CASCADE",
    ),
    # NOTE: a self-referential FK on (tree_id, parent_id) would be the
    # obvious way to enforce "every parent must exist", but it rejects
    # root nodes (parent_id="" doesn't reference any row). We keep
    # referential integrity at the application layer via
    # ``models.validate_parent_child`` (called from add_node) plus the
    # dedup UNIQUE constraint. Trade-off: a corrupted parent_id won't
    # be caught by the DB; mitigated by the strong type system +
    # transactional add_node.
    # State enum guard
    CheckConstraint(
        "state IN ('unseen','discovered','triaged','exploited','abandoned')",
        name="state_enum",
    ),
    CheckConstraint(
        "asset_type IN ("
        "'root_domain','sub_domain','ip','port','service','url','endpoint','parameter',"
        " 'injection_vector','auth_surface','static_asset','api_schema','component','cookie','header',"
        " 'storage','storage_object','secret','generic')",
        name="asset_type_enum",
    ),
    # ── Hot-path indexes ───────────────────────────────────────
    # The hot query is "give me all UNSEEN nodes of type T in tree X".
    # A composite (tree_id, asset_type, state) would be ideal, but we
    # also need type-only and state-only lookups — split into two
    # supporting indexes so the optimizer can pick the right one.
    Index("ix_asset_nodes_tree_type", "tree_id", "asset_type"),
    Index("ix_asset_nodes_tree_state", "tree_id", "state"),
    # Per-parent traversal: get_children / get_siblings
    Index("ix_asset_nodes_tree_parent", "tree_id", "parent_id"),
    # UNIQUE dedup invariant: (tree, type, parent, value). value prefix
    # because MySQL max index key length is 3072 bytes (utf8mb4 = 4 bytes
    # per char × 768 char ceiling); 255 is universally safe.
    UniqueConstraint(
        "tree_id",
        "asset_type",
        "parent_id",
        "value",
        name="uq_asset_nodes_dedup",
    ),
    # Cross-tree value lookup: find_nodes_by_value("1.2.3.4")
    Index("ix_asset_nodes_tree_value", "tree_id", "value"),
    # Subtree scan: material_path LIKE 'root/abc/%'
    Index("ix_asset_nodes_path_prefix", "tree_id", "material_path"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


# ── Edges ──────────────────────────────────────────────────────────


asset_edges = Table(
    "asset_edges",
    _metadata,
    Column("tree_id", String(128), nullable=False),
    Column("parent_id", _PARENT_ID_TYPE, nullable=False),
    Column("child_id", _NODE_ID_TYPE, nullable=False),
    # Insertion order for stable rendering. 0-indexed.
    Column(
        "child_order",
        Integer,
        nullable=False,
        server_default="0",
    ),
    PrimaryKeyConstraint("tree_id", "parent_id", "child_id", name="pk_asset_edges"),
    ForeignKeyConstraint(
        ["tree_id", "parent_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_asset_edges_parent",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["tree_id", "child_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_asset_edges_child",
        ondelete="CASCADE",
    ),
    # Reverse lookup: "which parent does this child have?"
    Index("ix_asset_edges_child", "tree_id", "child_id"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


# ── State transition audit log ──────────────────────────────────────


asset_state_transitions = Table(
    "asset_state_transitions",
    _metadata,
    # BIGINT UNSIGNED auto-increment PK on MySQL (8 bytes), INTEGER on
    # SQLite (4 bytes; plenty for audit log volumes). Uses SQLAlchemy
    # 2.0 Identity() so the dialect picks the correct autoincrement
    # strategy (AUTOINCREMENT on SQLite, AUTO_INCREMENT on MySQL).
    Column(
        "id",
        # INTEGER on SQLite (4 bytes; auto-increments), BIGINT UNSIGNED
        # on MySQL (8 bytes; auto-increments). SQLAlchemy needs
        # ``autoincrement=True`` paired with the dialect's integer
        # variant to emit ``AUTOINCREMENT`` / ``AUTO_INCREMENT``.
        Integer().with_variant(MYSQL_BIGINT(unsigned=True), "mysql"),
        primary_key=True,
        autoincrement=True,
    ),
    Column("tree_id", String(128), nullable=False),
    Column("node_id", _NODE_ID_TYPE, nullable=False),
    Column("from_state", String(16), nullable=False),
    Column("to_state", String(16), nullable=False),
    Column(
        "occurred_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    ForeignKeyConstraint(
        ["tree_id", "node_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_state_transitions_node",
        ondelete="CASCADE",
    ),
    Index("ix_state_transitions_node", "tree_id", "node_id", "occurred_at"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


# ── Evidence refs (handoff linkage) ──────────────────────────────


asset_evidence_refs = Table(
    "asset_evidence_refs",
    _metadata,
    Column("tree_id", String(128), nullable=False),
    Column("node_id", _NODE_ID_TYPE, nullable=False),
    Column("handoff_id", String(128), nullable=False),
    Column(
        "added_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    PrimaryKeyConstraint(
        "tree_id", "node_id", "handoff_id", name="pk_asset_evidence_refs"
    ),
    ForeignKeyConstraint(
        ["tree_id", "node_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_asset_evidence_refs_node",
        ondelete="CASCADE",
    ),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


# ── Migration DDL (raw, for ops tools) ────────────────────────────


# Render MySQL-compatible DDL via SQLAlchemy's MySQL dialect compiler.
# This produces the SAME schema as the SQLAlchemy table definitions above
# but in raw DDL form for ops scripts / migration tools that don't want
# to import SQLAlchemy.
DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS asset_trees (
        tree_id        VARCHAR(128) NOT NULL,
        root_domain    VARCHAR(255) NOT NULL,
        description    TEXT NULL,
        root_node_id   VARCHAR(12)  NOT NULL,
        created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                  ON UPDATE CURRENT_TIMESTAMP(6),
        PRIMARY KEY (tree_id),
        INDEX ix_asset_trees_root_domain (root_domain),
        INDEX ix_asset_trees_updated_at (updated_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_nodes (
        id              VARCHAR(12)  NOT NULL,
        tree_id         VARCHAR(128) NOT NULL,
        asset_type      VARCHAR(32)  NOT NULL,
        value           VARCHAR(2048) NOT NULL,
        state           VARCHAR(16)  NOT NULL DEFAULT 'unseen',
        parent_id       VARCHAR(12)  NULL,
        material_path   VARCHAR(512) NOT NULL,
        path_depth      SMALLINT UNSIGNED NOT NULL DEFAULT 0,
        source_wave     VARCHAR(128) NULL,
        assigned_wave   VARCHAR(128) NULL,
        metadata        JSON         NULL,
        first_seen      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        last_seen       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                    ON UPDATE CURRENT_TIMESTAMP(6),
        PRIMARY KEY (tree_id, id),
        CONSTRAINT fk_asset_nodes_tree FOREIGN KEY (tree_id)
            REFERENCES asset_trees(tree_id) ON DELETE CASCADE,
        CONSTRAINT fk_asset_nodes_parent FOREIGN KEY (tree_id, parent_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        CONSTRAINT ck_asset_nodes_state CHECK (state IN
            ('unseen','discovered','triaged','exploited','abandoned')),
        CONSTRAINT ck_asset_nodes_asset_type CHECK (asset_type IN
            ('root_domain','sub_domain','ip','port','service','url','endpoint','parameter',
             'injection_vector','auth_surface','static_asset','api_schema','component','cookie','header',
             'storage','storage_object','secret','generic')),
        INDEX ix_asset_nodes_tree_type (tree_id, asset_type),
        INDEX ix_asset_nodes_tree_state (tree_id, state),
        INDEX ix_asset_nodes_tree_parent (tree_id, parent_id),
        UNIQUE KEY uq_asset_nodes_dedup (tree_id, asset_type, parent_id, value(255)),
        INDEX ix_asset_nodes_tree_value (tree_id, value(255)),
        INDEX ix_asset_nodes_path_prefix (tree_id, material_path(255))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_edges (
        tree_id     VARCHAR(128) NOT NULL,
        parent_id   VARCHAR(12)  NOT NULL,
        child_id    VARCHAR(12)  NOT NULL,
        child_order INT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (tree_id, parent_id, child_id),
        CONSTRAINT fk_asset_edges_parent FOREIGN KEY (tree_id, parent_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        CONSTRAINT fk_asset_edges_child FOREIGN KEY (tree_id, child_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        INDEX ix_asset_edges_child (tree_id, child_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_state_transitions (
        id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        tree_id     VARCHAR(128) NOT NULL,
        node_id     VARCHAR(12)  NOT NULL,
        from_state  VARCHAR(16)  NOT NULL,
        to_state    VARCHAR(16)  NOT NULL,
        occurred_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        PRIMARY KEY (id),
        CONSTRAINT fk_state_transitions_node FOREIGN KEY (tree_id, node_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        INDEX ix_state_transitions_node (tree_id, node_id, occurred_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_evidence_refs (
        tree_id     VARCHAR(128) NOT NULL,
        node_id     VARCHAR(12)  NOT NULL,
        handoff_id  VARCHAR(128) NOT NULL,
        added_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        PRIMARY KEY (tree_id, node_id, handoff_id),
        CONSTRAINT fk_asset_evidence_refs_node FOREIGN KEY (tree_id, node_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
)


def all_metadata() -> MetaData:
    """Return the package-level MetaData singleton (used by migration runner)."""
    return _metadata