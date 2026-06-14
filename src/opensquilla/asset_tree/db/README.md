# AssetTree MySQL Persistence — Design Document

> **Phase 4 (2026-06-14)** — replaces the prior JSON-file persistence
> with enterprise-grade MySQL storage. SQLite is supported as a
> dialect-equivalent test backend; both share the same SQLAlchemy Core
> schema and migration runner.

---

## 1. Goals

- **MySQL as the source of truth** for all `AssetTree` state (replaces
  the prior JSON snapshot in `~/.opensquilla/state/asset_trees/`).
- **SQLite parity** for CI / dev runs (no MySQL server required).
- **Hot-query coverage** via 11+ indexes mapped to every read path.
- **Dedup invariant enforced at the DB layer** (UNIQUE on
  `(tree_id, asset_type, parent_id, value)`).
- **Concurrent-safe** via the existing `threading.RLock` on the
  in-memory `AssetTree` cache + MySQL InnoDB row-level locking for
  cross-process safety.

## 2. Driver choice

| Layer | Driver | Why |
|---|---|---|
| Query abstraction | SQLAlchemy 2.0 Core | Single schema → MySQL or SQLite dialect automatically |
| Production async | `aiomysql` (already in project deps via `pyproject.toml`) | Native asyncio, matches the rest of the codebase |
| Test async | `aiosqlite` (already installed) | No external server required |
| Async glue | `sqlalchemy.ext.asyncio.AsyncEngine` + `async_sessionmaker` | Standard SQLAlchemy 2.0 pattern |

`greenlet` is a runtime dep of SQLAlchemy async; it was added to
`pyproject.toml` during Phase 4.

## 3. Schema

5 tables, 11 indexes, 4 FK constraints (with cascade-delete), 2 CHECK
constraints (state and asset_type enums). See `schema.py` for the
SQLAlchemy Core definitions and `DDL_STATEMENTS` for the raw MySQL DDL.

### 3.1 Entity-relationship

```
┌──────────────┐
│ asset_trees  │  (1 row per tree)
│──────────────│
│ tree_id (PK) │
│ root_domain  │
│ root_node_id │
│ description  │
│ created_at   │
│ updated_at   │
└──────┬───────┘
       │ 1:N (CASCADE)
       ▼
┌──────────────────┐
│ asset_nodes      │  (1 row per node)
│──────────────────│
│ (tree_id, id) PK │  ← composite PK (id unique within tree)
│ asset_type       │
│ value            │
│ state            │
│ parent_id        │  ("" = root layer; NOT NULL sentinel)
│ material_path    │  ← slash-separated id chain (e.g. "root/abc/def")
│ path_depth       │
│ source_wave      │
│ assigned_wave    │
│ metadata (JSON)  │
│ first_seen       │
│ last_seen        │
└──┬────────────┬──┘
   │ N:1        │ 1:N
   │            ▼
   │  ┌────────────────┐
   │  │ asset_edges    │  (explicit adjacency for fast child enumeration)
   │  │────────────────│
   │  │ (tree_id,      │
   │  │  parent_id,    │  PK: composite on (tree_id, parent_id, child_id)
   │  │  child_id) PK  │
   │  │ child_order    │
   │  └────────────────┘
   ▼
┌──────────────────────────┐
│ asset_state_transitions  │  (audit log)
│──────────────────────────│
│ id (BIGINT PK)           │  auto-increment
│ (tree_id, node_id) FK    │
│ from_state               │
│ to_state                 │
│ occurred_at              │
└──────────────────────────┘

┌──────────────────────┐
│ asset_evidence_refs  │  (handoff linkage)
│──────────────────────│
│ (tree_id,            │
│  node_id,            │
│  handoff_id) PK      │
│ added_at             │
└──────────────────────┘
```

### 3.2 Index matrix (hot-query → covering index)

| # | Query | Index used | Notes |
|---|---|---|---|
| 1 | `add_node` dedup | `uq_asset_nodes_dedup` (UNIQUE on `(tree_id, asset_type, parent_id, value)`) | Root layer uses `""` sentinel so the UNIQUE applies (NULL is never equal in either MySQL or SQLite). |
| 2 | `find_node(asset_type, value)` (root layer) | `ix_asset_nodes_tree_value` + `parent_id == ""` filter | Hits the value index, then filters root-layer rows. |
| 3 | `find_nodes_by_value(value)` | `ix_asset_nodes_tree_value` | Cross-parent lookup. |
| 4 | `find_unseen(asset_type?)` | `ix_asset_nodes_tree_state` (+ `ix_asset_nodes_tree_type` when filter is set) | The hot "next wave" query. |
| 5 | `get_children(parent_id)` | PK on `asset_edges (tree_id, parent_id, child_id)` + JOIN to `asset_nodes` by PK | Single-tree traversal = PK lookup, no recursion. |
| 6 | `get_parent(node_id)` | `ix_asset_edges_child (tree_id, child_id)` (reverse lookup) | Avoids storing a redundant `child→parent` index. |
| 7 | `get_path_to_root(node_id)` | `ix_asset_nodes_path_prefix (tree_id, material_path)` | Materialized-path column = O(depth) instead of O(N) for ancestor walks. |
| 8 | `get_all_descendants(node_id)` | `ix_asset_nodes_path_prefix` with `LIKE 'parent_path/%'` | Materialized-path enables subtree scan as a single range query. |
| 9 | `find_shared_ips()` | `ix_asset_nodes_tree_type` (filter `asset_type='ip'`) + GROUP BY `value` HAVING `count>1` | Returns IPs whose `parent_id` differs across rows. |
| 10 | `stats()` | `ix_asset_nodes_tree_type` + `ix_asset_nodes_tree_state` (GROUP BY) | COUNT/GROUP BY operations benefit from the same indexes. |
| 11 | State-transition audit query | `ix_state_transitions_node (tree_id, node_id, occurred_at)` | Supports `WHERE node_id=? ORDER BY occurred_at DESC`. |

Plus tree-level indexes:
- `ix_asset_trees_root_domain` — "is there an existing tree for this domain?"
- `ix_asset_trees_updated_at` — "recently updated trees" (for cache eviction).

## 4. Dedup invariant — the `""` sentinel

`asset_nodes.parent_id` is `NOT NULL` with `server_default=""`. Callers
passing `None` get translated to `""` at the `backend.add_node` boundary
and back to `None` on read.

This works because **both MySQL and SQLite treat `NULL` as distinct in
UNIQUE constraints** — a `NULL parent_id` row would allow duplicate
root-layer nodes with the same `(tree_id, asset_type, value)` triple,
defeating the dedup invariant. The empty-string sentinel restores
correctness at the cost of one tiny indirection at the API boundary.

## 5. Concurrency

- **Within a process**: `AssetTree` holds `threading.RLock`; all mutating
  operations acquire it. `_persist_node` schedules the async backend
  call via `asyncio.ensure_future` (fire-and-forget) so the sync
  `add_node` API stays sync.
- **Across processes**: MySQL InnoDB row-level locks on the unique
  index handle concurrent INSERTs. `add_node` returns `False` on
  dedup-violation (`IntegrityError`), so two LLM-coordinator instances
  racing on the same tree converge to one winner.
- **Within async**: SQLAlchemy's `AsyncSession` serializes statements
  per session. Multi-statement operations use `async with
  session.begin():` so the row order is preserved.

## 6. Connection pool configuration

| Setting | MySQL | SQLite |
|---|---|---|
| `pool_size` | 10 | (NullPool — SQLite doesn't share connections across threads) |
| `max_overflow` | 5 | n/a |
| `pool_recycle` | 1800s (MySQL `wait_timeout`) | n/a |
| `pool_timeout` | 30s | n/a |
| `pool_pre_ping` | True (detect stale conns) | True |
| `PRAGMA foreign_keys` | n/a (InnoDB enforces FKs) | `ON` per connection (event listener) |

URL examples:
```
mysql+aiomysql://opensquilla:secret@db.host:3306/opensquilla
sqlite+aiosqlite:////var/lib/opensquilla/asset_tree.db
sqlite+aiosqlite:///:memory:        # ephemeral test backend
```

## 7. Migration runner

`python -m opensquilla.asset_tree.db.migrations --url <DB_URL> [--reset]`

`migrate(backend)` is idempotent: it runs `metadata.create_all(engine)`
which emits `CREATE TABLE IF NOT EXISTS` statements. After creation,
on MySQL we run `ALTER TABLE ... ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
to ensure the storage engine + charset are set even when SQLAlchemy's
CREATE TABLE omitted them (defense in depth).

The raw `DDL_STATEMENTS` tuple is the authoritative migration source
for ops teams that prefer hand-applied SQL over SQLAlchemy.

## 8. Integration with `AssetTree` (in-memory cache)

The `AssetTree` class keeps its 4 in-memory indexes (`_nodes`,
`_edges`, `_by_type`, `_value_index`) as a **session cache**. When
constructed with `backend=...`, every mutating call schedules a
fire-and-forget persistence task via `asyncio.ensure_future`. The
backend is the **durable source of truth**; the in-memory cache is for
fast read paths (children, descendants, sibling walks).

The `tools/builtin/asset_tree/tree.py` continues to maintain a JSON
snapshot as a read-through cache for sync test code paths. In
production, the backend's `add_node`/`update_node_state` are the
write path.

## 9. Test coverage

`tests/test_asset_tree_backend.py` (19 tests):
- Schema migration: tables created, indexes exist, idempotency.
- Tree CRUD: upsert, get, delete (cascade).
- Node CRUD: root insertion, dedup, cross-parent legality, state transitions.
- Traversal: children, parent, path-to-root, descendants, shared IPs.
- find_unseen with type filter, depth ordering.
- Stats summary.
- Concurrency: 100 concurrent inserts of the same (tree, type, value) → 1 winner.

The SQLite backend (`sqlite+aiosqlite:///`) covers all paths; the
MySQL backend shares the same `SqlAlchemyBackend` parent class so
dialect-level differences are exercised at integration time.

## 10. Migration path for existing data

For installations that already have JSON snapshots under
`~/.opensquilla/state/asset_trees/`, the `scripts/migrate_legacy_json.py`
script (Phase 5+, not in this PR) will:
1. Iterate JSON files.
2. Parse each `AssetTree.to_dict()`.
3. Insert tree + nodes + edges in dependency order (parent before child).
4. Skip files that fail dedup (treat as already-migrated).

For now, JSON files coexist — the tools write to both backends.