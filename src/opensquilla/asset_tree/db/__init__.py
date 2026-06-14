"""AssetTree MySQL persistence — package marker.

See sibling modules:
- ``schema.py``   : SQLAlchemy Core table definitions (single source of truth)
- ``pool.py``     : async engine factory + connection-pool config
- ``backend.py``  : ``AssetTreeBackend`` ABC + ``MysqlBackend`` + ``SqliteBackend``
- ``migrations.py``: idempotent table / index creation
- ``ddl.sql``     : raw MySQL DDL for ops / migration tool
"""

from opensquilla.asset_tree.db.backend import (
    AssetTreeBackend,
    MysqlBackend,
    SqliteBackend,
    get_default_backend,
)
from opensquilla.asset_tree.db.pool import (
    build_engine_from_url,
    build_session_factory,
    default_db_url,
)
from opensquilla.asset_tree.db.schema import (
    DDL_STATEMENTS,
    asset_edges,
    asset_evidence_refs,
    asset_nodes,
    asset_state_transitions,
    asset_trees,
)

__all__ = [
    "DDL_STATEMENTS",
    "AssetTreeBackend",
    "MysqlBackend",
    "SqliteBackend",
    "asset_edges",
    "asset_evidence_refs",
    "asset_nodes",
    "asset_state_transitions",
    "asset_trees",
    "build_engine_from_url",
    "build_session_factory",
    "default_db_url",
    "get_default_backend",
]