"""AssetTree MySQL persistence — package marker.

See sibling modules:
- ``schema.py``   : SQLAlchemy Core table definitions (single source of truth)
- ``pool.py``     : async engine factory + connection-pool config (MySQL only)
- ``backend.py``  : ``AssetTreeBackend`` ABC + ``MysqlBackend``
- ``migrations.py``: idempotent table / index creation
- ``ddl.sql``     : raw MySQL DDL for ops / migration tool
"""

from opensquilla.asset_tree.db.backend import (
    AssetTreeBackend,
    MysqlBackend,
    get_default_backend,
)
from opensquilla.asset_tree.db.pool import (
    AssetTreeConfigError,
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
    vuln_attack_paths,
    vuln_node_vulns,
    vuln_path_vulns,
    vulnerabilities,
)

__all__ = [
    "AssetTreeConfigError",
    "AssetTreeBackend",
    "DDL_STATEMENTS",
    "MysqlBackend",
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
