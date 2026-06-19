"""AssetTree relational schema (SQLAlchemy Core, MySQL 8.0+).

AssetTree is MySQL-only. The schema is defined once via SQLAlchemy Core
(the single source of truth used by the runtime) and mirrored as raw
MySQL DDL in ``DDL_STATEMENTS`` (for ops/migration tools).

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
- MySQL 8.0+ supports the native JSON column type with indexable paths.
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
  sharing the same MySQL instance. (AssetTree is MySQL-only.)
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


# Single MetaData namespace for all AssetTree tables.
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
    # path_depth: 0 = root, 1 = sub_domain, ..., 7 = injection_vector (L7).
    # v5 (2026-06-18) 业务硬上限 MAX_TREE_DEPTH=8; 入库时由 validate_depth
    # 拦截越界写入, 并由 ck_asset_nodes_depth_max CHECK 约束做 DB 层兜底。
    # SMALLINT UNSIGNED 最多 65535, 远超 8 层需要。
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
    # per char × 768 char ceiling); 255 is universally safe. We use
    # ``Index(..., unique=True, mysql_length=...)`` instead of
    # ``UniqueConstraint`` because the latter does not honour the
    # ``mysql_length`` prefix and emits a full-length UNIQUE key, which
    # fails on MySQL 8 with ``Specified key was too long`` (1071).
    Index(
        "uq_asset_nodes_dedup",
        "tree_id",
        "asset_type",
        "parent_id",
        "value",
        unique=True,
        mysql_length={"value": 255},
    ),
    # Cross-tree value lookup: find_nodes_by_value("1.2.3.4"). value
    # prefix-255 for the same MySQL key-length reason as
    # ``uq_asset_nodes_dedup`` above.
    Index(
        "ix_asset_nodes_tree_value",
        "tree_id",
        "value",
        mysql_length={"value": 255},
    ),
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
    # BIGINT UNSIGNED auto-increment PK on MySQL (8 bytes; large range
    # for audit log volumes). SQLAlchemy emits AUTO_INCREMENT.
    Column(
        "id",
        # BIGINT UNSIGNED on MySQL (8 bytes; auto-increments).
        # ``autoincrement=True`` is required to emit AUTO_INCREMENT.
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
        CONSTRAINT ck_asset_nodes_depth_max CHECK (path_depth <= 8),
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
    """
    CREATE TABLE IF NOT EXISTS vuln_attack_paths (
        path_id         VARCHAR(12)  NOT NULL,
        tree_id         VARCHAR(128) NOT NULL,
        path_hash       CHAR(40)     NOT NULL,
        status          VARCHAR(16)  NOT NULL DEFAULT 'pending',
        scope_string    TEXT         NOT NULL,
        edge_chain_json JSON         NOT NULL,
        leaf_node_id    VARCHAR(12)  NOT NULL,
        leaf_type       VARCHAR(32)  NOT NULL,
        leaf_value      VARCHAR(2048) NOT NULL,
        vuln_count      INT UNSIGNED NOT NULL DEFAULT 0,
        metadata        JSON         NULL,
        error           TEXT         NULL,
        created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        started_at      DATETIME(6)  NULL,
        completed_at    DATETIME(6)  NULL,
        PRIMARY KEY (path_id),
        CONSTRAINT fk_vuln_attack_paths_tree FOREIGN KEY (tree_id)
            REFERENCES asset_trees(tree_id) ON DELETE CASCADE,
        CONSTRAINT fk_vuln_attack_paths_leaf FOREIGN KEY (tree_id, leaf_node_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        CONSTRAINT ck_vuln_attack_paths_status CHECK (status IN
            ('pending','in_progress','completed','failed','abandoned')),
        UNIQUE KEY uq_vuln_attack_paths_hash (path_hash),
        INDEX ix_vuln_attack_paths_tree_status (tree_id, status),
        INDEX ix_vuln_attack_paths_leaf (tree_id, leaf_node_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id            VARCHAR(12)  NOT NULL,
        tree_id       VARCHAR(128) NOT NULL,
        attack_path_id VARCHAR(12) NULL,
        leaf_node_id  VARCHAR(12)  NOT NULL,
        cwe           VARCHAR(64)  NULL,
        cve           VARCHAR(64)  NULL,
        severity      VARCHAR(16)  NOT NULL,
        title         VARCHAR(512) NOT NULL,
        description   TEXT         NULL,
        evidence_json JSON         NULL,
        request       TEXT         NULL,
        response      TEXT         NULL,
        payload       TEXT         NULL,
        discovered_by_wave       VARCHAR(64)  NULL,
        discovered_by_specialist VARCHAR(64)  NULL,
        created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        PRIMARY KEY (id),
        CONSTRAINT fk_vulnerabilities_tree FOREIGN KEY (tree_id)
            REFERENCES asset_trees(tree_id) ON DELETE CASCADE,
        CONSTRAINT fk_vulnerabilities_leaf FOREIGN KEY (tree_id, leaf_node_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        CONSTRAINT fk_vulnerabilities_path FOREIGN KEY (attack_path_id)
            REFERENCES vuln_attack_paths(path_id) ON DELETE SET NULL,
        CONSTRAINT ck_vulnerabilities_severity CHECK (severity IN
            ('critical','high','medium','low','info')),
        INDEX ix_vulnerabilities_tree (tree_id),
        INDEX ix_vulnerabilities_tree_path (tree_id, attack_path_id),
        INDEX ix_vulnerabilities_leaf (tree_id, leaf_node_id),
        INDEX ix_vulnerabilities_severity (tree_id, severity)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_path_vulns (
        attack_path_id    VARCHAR(12)  NOT NULL,
        vulnerability_id  VARCHAR(12)  NOT NULL,
        created_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        PRIMARY KEY (attack_path_id, vulnerability_id),
        CONSTRAINT fk_vuln_path_vulns_path FOREIGN KEY (attack_path_id)
            REFERENCES vuln_attack_paths(path_id) ON DELETE CASCADE,
        CONSTRAINT fk_vuln_path_vulns_vuln FOREIGN KEY (vulnerability_id)
            REFERENCES vulnerabilities(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_node_vulns (
        tree_id          VARCHAR(128) NOT NULL,
        node_id          VARCHAR(12)  NOT NULL,
        vulnerability_id VARCHAR(12)  NOT NULL,
        created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        PRIMARY KEY (tree_id, node_id, vulnerability_id),
        CONSTRAINT fk_vuln_node_vulns_node FOREIGN KEY (tree_id, node_id)
            REFERENCES asset_nodes(tree_id, id) ON DELETE CASCADE,
        CONSTRAINT fk_vuln_node_vulns_vuln FOREIGN KEY (vulnerability_id)
            REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        INDEX ix_vuln_node_vulns_vuln (vulnerability_id),
        INDEX ix_vuln_node_vulns_node (tree_id, node_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
)


# ── v6 漏洞与攻击路径 SQLAlchemy Table 对象 (2026-06-19) ──────────────
# 与上面 DDL_STATEMENTS 的 raw DDL 保持一致; metadata.create_all 会
# 拉这些 Table 一起创建。所有表 FOREIGN KEY 走 asset_trees /
# asset_nodes / vuln_attack_paths / vulnerabilities, 与 SQL DDL 同步。

vuln_attack_paths = Table(
    "vuln_attack_paths",
    _metadata,
    Column("path_id", _NODE_ID_TYPE, primary_key=True, nullable=False),
    Column("tree_id", String(128), nullable=False),
    Column("path_hash", String(40), nullable=False),
    Column("status", String(16), nullable=False, server_default="pending"),
    Column("scope_string", Text, nullable=False),
    Column("edge_chain_json", JSON, nullable=False),
    Column("leaf_node_id", _NODE_ID_TYPE, nullable=False),
    Column("leaf_type", String(32), nullable=False),
    Column("leaf_value", String(2048), nullable=False),
    Column(
        "vuln_count",
        Integer().with_variant(MYSQL_BIGINT(unsigned=True), "mysql"),
        nullable=False,
        server_default="0",
    ),
    Column("metadata", JSON, nullable=True),
    Column("error", Text, nullable=True),
    Column(
        "created_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    Column("started_at", DateTime(timezone=False), nullable=True),
    Column("completed_at", DateTime(timezone=False), nullable=True),
    ForeignKeyConstraint(
        ["tree_id"],
        ["asset_trees.tree_id"],
        name="fk_vuln_attack_paths_tree",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["tree_id", "leaf_node_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_vuln_attack_paths_leaf",
        ondelete="CASCADE",
    ),
    CheckConstraint(
        "status IN ('pending','in_progress','completed','failed','abandoned')",
        name="status_enum",
    ),
    UniqueConstraint("path_hash", name="uq_vuln_attack_paths_hash"),
    Index("ix_vuln_attack_paths_tree_status", "tree_id", "status"),
    Index("ix_vuln_attack_paths_leaf", "tree_id", "leaf_node_id"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


vulnerabilities = Table(
    "vulnerabilities",
    _metadata,
    Column("id", _NODE_ID_TYPE, primary_key=True, nullable=False),
    Column("tree_id", String(128), nullable=False),
    Column("attack_path_id", _NODE_ID_TYPE, nullable=True),
    Column("leaf_node_id", _NODE_ID_TYPE, nullable=False),
    Column("cwe", String(64), nullable=True),
    Column("cve", String(64), nullable=True),
    Column("severity", String(16), nullable=False),
    Column("title", String(512), nullable=False),
    Column("description", Text, nullable=True),
    Column("evidence_json", JSON, nullable=True),
    Column("request", Text, nullable=True),
    Column("response", Text, nullable=True),
    Column("payload", Text, nullable=True),
    Column("discovered_by_wave", String(64), nullable=True),
    Column("discovered_by_specialist", String(64), nullable=True),
    Column(
        "created_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    ForeignKeyConstraint(
        ["tree_id"],
        ["asset_trees.tree_id"],
        name="fk_vulnerabilities_tree",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["tree_id", "leaf_node_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_vulnerabilities_leaf",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["attack_path_id"],
        ["vuln_attack_paths.path_id"],
        name="fk_vulnerabilities_path",
        ondelete="SET NULL",
    ),
    CheckConstraint(
        "severity IN ('critical','high','medium','low','info')",
        name="severity_enum",
    ),
    Index("ix_vulnerabilities_tree", "tree_id"),
    Index("ix_vulnerabilities_tree_path", "tree_id", "attack_path_id"),
    Index("ix_vulnerabilities_leaf", "tree_id", "leaf_node_id"),
    Index("ix_vulnerabilities_severity", "tree_id", "severity"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


vuln_path_vulns = Table(
    "vuln_path_vulns",
    _metadata,
    Column("attack_path_id", _NODE_ID_TYPE, nullable=False),
    Column("vulnerability_id", _NODE_ID_TYPE, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    PrimaryKeyConstraint(
        "attack_path_id",
        "vulnerability_id",
        name="pk_vuln_path_vulns",
    ),
    ForeignKeyConstraint(
        ["attack_path_id"],
        ["vuln_attack_paths.path_id"],
        name="fk_vuln_path_vulns_path",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["vulnerability_id"],
        ["vulnerabilities.id"],
        name="fk_vuln_path_vulns_vuln",
        ondelete="CASCADE",
    ),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


vuln_node_vulns = Table(
    "vuln_node_vulns",
    _metadata,
    Column("tree_id", String(128), nullable=False),
    Column("node_id", _NODE_ID_TYPE, nullable=False),
    Column("vulnerability_id", _NODE_ID_TYPE, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
    ),
    PrimaryKeyConstraint(
        "tree_id",
        "node_id",
        "vulnerability_id",
        name="pk_vuln_node_vulns",
    ),
    ForeignKeyConstraint(
        ["tree_id", "node_id"],
        ["asset_nodes.tree_id", "asset_nodes.id"],
        name="fk_vuln_node_vulns_node",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["vulnerability_id"],
        ["vulnerabilities.id"],
        name="fk_vuln_node_vulns_vuln",
        ondelete="CASCADE",
    ),
    Index("ix_vuln_node_vulns_vuln", "vulnerability_id"),
    Index("ix_vuln_node_vulns_node", "tree_id", "node_id"),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


def all_metadata() -> MetaData:
    """Return the package-level MetaData singleton (used by migration runner)."""
    return _metadata