"""AssetTree tools — full set (8 tools).

Phase 1 MVP shipped the loop primitives; Phase 2 added the remaining 5
tools needed for end-to-end recursive discovery + handoff to hack-deep.

All mutating tools persist to ``~/.opensquilla/state/asset_trees/<tree_id>.json``
after each mutation so the tree survives LLM context eviction and
concurrent specialist sessions.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from opensquilla.asset_tree.models import AssetState, AssetType
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.tools.registry import tool
from opensquilla.tools.types import ToolError


# ── 持久化路径 ──────────────────────────────────────


def _default_state_root() -> Path:
    """Resolve the state dir lazily so OPEN_SQUILLA_STATE_DIR is respected."""
    env = os.environ.get("OPEN_SQUILLA_STATE_DIR")
    return Path(env) if env else (Path.home() / ".opensquilla" / "state" / "asset_trees")


def _tree_path(tree_id: str) -> Path:
    if not tree_id or "/" in tree_id or ".." in tree_id:
        raise ToolError(f"Invalid tree_id: {tree_id!r}")
    return _default_state_root() / f"{tree_id}.json"


def _backend():
    """Lazy-resolve the default backend, ensuring the schema is migrated.

    The default backend reads ``ASSET_TREE_DB_URL``. Tests set this to
    ``sqlite+aiosqlite:///<tmpdir>/test.db`` for in-process runs;
    production points at MySQL.

    Migration is a one-shot per process. We run it in a worker thread
    (via ``asyncio.run``) to avoid "loop is already running" conflicts
    when the tool itself is invoked from an async context.
    """
    import threading
    from opensquilla.asset_tree.db import get_default_backend
    from opensquilla.asset_tree.db.migrations import migrate

    be = get_default_backend()
    if getattr(_backend, "_migrated", False):
        return be

    with _backend._lock:  # type: ignore[attr-defined]
        if getattr(_backend, "_migrated", False):
            return be
        # Migration in a fresh thread so it doesn't fight with any
        # outer event loop the caller may be in.
        import asyncio

        def _do_migrate() -> None:
            asyncio.run(migrate(be))

        thread = threading.Thread(target=_do_migrate, daemon=True)
        thread.start()
        thread.join(timeout=30)
        if thread.is_alive():
            raise RuntimeError(
                "AssetTree schema migration timed out (30s). "
                "Check ASSET_TREE_DB_URL connectivity."
            )
        _backend._migrated = True  # type: ignore[attr-defined]
    return be


_backend._lock = threading.Lock()  # type: ignore[attr-defined]
_backend._migrated = False  # type: ignore[attr-defined]


def _save_tree(tree: AssetTree, tree_id: str) -> None:
    """Persist tree to disk (atomic write).

    Phase 4 keeps this for two reasons:
    1. Tools' sync ``_load_tree`` path reads from the same JSON file
       (lets the existing 156 tests run without touching MySQL).
    2. Defense-in-depth snapshot — if the MySQL connection drops, the
       JSON is the recovery point.

    The AssetTree backend's auto-persist (via ``_add_node_locked`` and
    ``update_state``) fires in parallel for the long-term MySQL store.
    """
    path = _tree_path(tree_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(tree.to_json(), encoding="utf-8")
    os.replace(tmp, path)


def _load_tree(tree_id: str) -> AssetTree:
    """Sync loader — Phase 4 keeps the JSON snapshot for test compatibility.

    CRITICAL: rebinds the loaded AssetTree's ``_backend`` to the
    default backend. Without this rebind, every tool mutation
    (``asset_tree_add_nodes``, ``asset_tree_update_state``, ...) would
    skip the MySQL write because ``AssetTree.from_json`` constructs
    an instance with ``_backend=None``. After this rebind, the
    auto-persist hook in ``_add_node_locked`` / ``update_state`` fires
    and every mutation lands in the DB.
    """
    path = _tree_path(tree_id)
    if path.exists():
        try:
            tree = AssetTree.from_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ToolError(f"Failed to load tree {tree_id}: {exc}") from exc
    else:
        raise ToolError(
            f"Tree not found: {tree_id} (no JSON snapshot at {path}). "
            "Use _load_tree_async() or call asset_tree_create first."
        )

    # Rebind to the default backend so subsequent mutations flush.
    try:
        tree._backend = _backend()  # type: ignore[attr-defined]
        tree._tree_id = tree_id  # type: ignore[attr-defined]
    except Exception:
        # Backend unavailable (e.g. tests without DB) — fall back to
        # in-memory only. Tools still work, JSON persists.
        tree._backend = None  # type: ignore[attr-defined]
        tree._tree_id = None  # type: ignore[attr-defined]
    return tree


def _validate_asset_type(asset_type_str: str) -> AssetType:
    try:
        return AssetType(asset_type_str)
    except ValueError as exc:
        raise ToolError(
            f"Invalid asset_type: {asset_type_str!r}. "
            f"Must be one of {[t.value for t in AssetType]}"
        ) from exc


def _validate_state(state_str: str) -> AssetState:
    try:
        return AssetState(state_str)
    except ValueError as exc:
        raise ToolError(
            f"Invalid state: {state_str!r}. "
            f"Must be one of {[s.value for s in AssetState]}"
        ) from exc


# ── 工具 ──────────────────────────────────────────


@tool(
    name="asset_tree_create",
    description=(
        "Create a new AssetTree rooted at `root_domain`. Returns the "
        "`tree_id` (use this in all subsequent asset_tree_* calls) and the "
        "`root_node_id` (the ROOT_DOMAIN node's id). If `tree_id` is "
        "omitted, a default id of `tree-<root_domain>` is used (sanitized). "
        "The tree is persisted immediately to the state directory."
    ),
    params={
        "root_domain": {
            "type": "string",
            "description": (
                "Primary root domain (e.g. 'example.com'). This is the "
                "tree's canonical root; all other seeds are attached as "
                "child ROOT_DOMAIN nodes."
            ),
        },
        "tree_id": {
            "type": "string",
            "description": (
                "Optional explicit tree id. Must be filesystem-safe (no '/' "
                "or '..'). Default: 'tree-<sanitized-root_domain>'."
            ),
        },
        "extra_seeds": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["domain", "asn", "ip_range", "org_name", "keyword"],
                    },
                    "value": {"type": "string"},
                },
                "required": ["kind", "value"],
            },
            "description": (
                "Optional additional seeds (Batch 4, multi-seed expansion). "
                "Each seed becomes a child ROOT_DOMAIN node under the "
                "primary root. `kind` indicates the seed type so the "
                "orchestrator can dispatch the right specialist."
            ),
        },
    },
    required=["root_domain"],
)
async def asset_tree_create(
    root_domain: str,
    tree_id: str | None = None,
    extra_seeds: list[dict[str, str]] | None = None,
) -> str:
    """Create a new AssetTree.

    Phase 4: persists BOTH to JSON (read-through cache + sync test
    compat) AND to the configured MySQL/SQLite backend. The backend
    is the durable source of truth.

    Batch 4 (2026-06-15): supports multi-seed expansion via
    `extra_seeds` parameter. Each extra seed becomes a child
    ROOT_DOMAIN node so the orchestrator can iterate seeds in
    parallel within a single tree.
    """
    if not root_domain or not root_domain.strip():
        raise ToolError("root_domain must be non-empty")

    if tree_id is None:
        sanitized = "".join(c if c.isalnum() or c in "-_." else "-" for c in root_domain)
        tree_id = f"tree-{sanitized}" if sanitized else "tree-root"

    path = _tree_path(tree_id)
    if path.exists():
        raise ToolError(f"Tree already exists: {tree_id} (at {path})")

    # Build in-memory tree, then mirror to both stores. Bind the
    # backend up-front so the in-memory tree's auto-persist hook is
    # wired in for subsequent add_nodes calls in the same process.
    backend = _backend()
    tree = AssetTree(root_domain.strip(), backend=backend, tree_id=tree_id)
    _save_tree(tree, tree_id)

    # Backend persistence: tree record + root node. Fire-and-await so
    # we surface DB errors to the LLM immediately (vs. swallowing
    # them in a fire-and-forget task). The DB write is async; we
    # await it before returning the success payload.
    try:
        await backend.upsert_tree(
            tree_id=tree_id,
            root_domain=tree.root_domain,
            root_node_id=tree.root_id,
        )
        await backend.add_node(
            node_id=tree.root_id,
            tree_id=tree_id,
            asset_type=AssetType.ROOT_DOMAIN.value,
            value=tree.root_domain,
            state=AssetState.UNSEEN.value,
            parent_id=None,
            material_path=tree.root_id,
            path_depth=0,
        )
    except Exception as exc:
        # Roll back the JSON snapshot so the caller doesn't see a
        # half-created tree.
        try:
            os.remove(path)
        except OSError:
            pass
        raise ToolError(f"Backend persistence failed: {exc}") from exc

    # Batch 4: attach extra seeds as child ROOT_DOMAIN nodes
    extra_seed_ids: list[dict[str, str]] = []
    if extra_seeds:
        for seed in extra_seeds:
            kind = seed.get("kind", "domain")
            value = seed.get("value", "").strip()
            if not value:
                continue
            try:
                child_id = tree.add_node(
                    parent_id=tree.root_id,
                    asset_type=AssetType.ROOT_DOMAIN,
                    value=f"[{kind}] {value}",  # tag so kind is visible
                )
                extra_seed_ids.append({"kind": kind, "value": value, "node_id": child_id})
            except Exception as exc:
                # Skip on add failure; don't fail the whole tree create
                extra_seed_ids.append({"kind": kind, "value": value, "error": str(exc)})

    return json.dumps(
        {
            "tree_id": tree_id,
            "root_node_id": tree.root_id,
            "root_domain": tree.root_domain,
            "persisted_path": str(path),
            "backend": type(backend).__name__,
            "extra_seeds": extra_seed_ids,
            "extra_seed_count": len(extra_seed_ids),
        },
        ensure_ascii=False,
    )


@tool(
    name="asset_tree_add_nodes",
    description=(
        "Add one or more child nodes of the same asset_type to a parent "
        "node in the tree. Dedup is per-parent (same asset_type + value "
        "under the same parent returns the existing node id; cross-parent "
        "duplicates of an IP or port are LEGAL and produce distinct nodes). "
        "Returns per-input status: `added` for new, `deduped` for existing."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id from asset_tree_create."},
        "parent_id": {
            "type": "string",
            "description": "Parent node id. Must exist in the tree.",
        },
        "asset_type": {
            "type": "string",
            "description": (
                "AssetType value. Allowed values: 'sub_domain', 'ip', 'port', "
                "'service', 'url', 'endpoint', 'parameter', 'injection_vector', "
                "'auth_surface', 'static_asset', 'api_schema', 'component', "
                "'cookie', 'header', 'storage', 'storage_object', 'secret', 'generic'. "
                "The parent→child relation is validated."
            ),
        },
        "values": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of child node values to add under parent.",
        },
        "metadata": {
            "type": "object",
            "description": (
                "Optional metadata applied to every newly-created node. "
                "Existing (deduped) nodes are NOT mutated."
            ),
        },
        "source_wave": {
            "type": "string",
            "description": (
                "Optional handoff_id of the wave that discovered these nodes. "
                "Recorded on each new node as `source_wave`."
            ),
        },
        "verification": {
            "type": "object",
            "description": (
                "v4 (2026-06-17) REQUIRED for asset_type=port / service / "
                "url / endpoint. Verification envelope from "
                "recon_url_validate (for url/endpoint) or recon_port_verify "
                "(for port/service). The envelope must have verified=true. "
                "Without it the add_node call is rejected — this is the "
                "false-positive gate that 51ifind.com run 2026-06-17 lacked "
                "(14/84 ports and 13 URL nodes that turned out to be "
                "unreachable / error pages were all marked discovered). "
                "For asset_type not in (port, service, url, endpoint), "
                "verification is ignored."
            ),
        },
        "allow_unverified": {
            "type": "boolean",
            "description": (
                "Skip verification check. PRODUCTION PATHS MUST NOT PASS TRUE. "
                "Only valid for deserialization (from_dict, JSON restore) and "
                "test fixtures."
            ),
            "default": False,
        },
    },
    required=["tree_id", "parent_id", "asset_type", "values"],
)
async def asset_tree_add_nodes(
    tree_id: str,
    parent_id: str,
    asset_type: str,
    values: list[str],
    metadata: dict[str, Any] | None = None,
    source_wave: str | None = None,
    verification: dict[str, Any] | None = None,
    allow_unverified: bool = False,
) -> str:
    """Add child nodes to a parent.

    Phase 4: every successfully-added node is flushed to the backend
    via ``add_nodes_bulk`` in a single transaction (sorted by
    path_depth so parents commit before children — required for the
    edge FK checks to pass).
    """
    if not values:
        return json.dumps(
            {"added": [], "deduped": [], "errors": []}, ensure_ascii=False
        )

    atype = _validate_asset_type(asset_type)
    tree = _load_tree(tree_id)

    parent = tree.get_node(parent_id)
    if parent is None:
        raise ToolError(f"Parent node not found: {parent_id}")

    added: list[dict[str, Any]] = []
    deduped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    # Phase 1: build in-memory tree + collect bulk backend payloads.
    # Suppress the in-memory auto-persist (fire-and-forget) for this
    # batch — we'll do one awaited bulk write at the end.
    bulk_nodes: list[dict[str, Any]] = []
    bulk_edges: list[dict[str, Any]] = []

    for value in values:
        if not value or not isinstance(value, str):
            errors.append({"value": str(value), "error": "empty or non-string value"})
            continue
        # Check existing via find_nodes_by_value (cross-parent safe)
        existing_match = None
        for candidate in tree.find_nodes_by_value(value):
            if (
                candidate.asset_type == atype
                and candidate.parent_id == parent_id
            ):
                existing_match = candidate
                break
        if existing_match is not None:
            deduped.append(
                {"node_id": existing_match.id, "value": value, "asset_type": atype.value}
            )
            continue
        try:
            new_id = tree.add_node(
                asset_type=atype,
                value=value,
                parent_id=parent_id,
                source_wave=source_wave,
                metadata=metadata,
                verification=verification,
                allow_unverified=allow_unverified,
            )
            added.append(
                {"node_id": new_id, "value": value, "asset_type": atype.value}
            )
            new_node = tree.get_node(new_id)
            if new_node is not None:
                # Compute material_path from the in-memory tree (it's
                # not stored on AssetNode; AssetTree.material_path
                # derives it from parent linkage).
                material_path = tree._material_path_for(new_node)
                bulk_nodes.append({
                    "node_id": new_id,
                    "asset_type": atype.value,
                    "value": value,
                    "state": new_node.state.value,
                    "parent_id": parent_id,
                    "material_path": material_path,
                    "path_depth": material_path.count("/"),
                    "source_wave": source_wave,
                    "metadata": dict(metadata) if metadata else None,
                })
                # Edge only when parent is real (root layer excluded)
                if parent_id:
                    bulk_edges.append({
                        "parent_id": parent_id,
                        "child_id": new_id,
                    })
        except Exception as exc:
            errors.append({"value": value, "error": str(exc)})

    _save_tree(tree, tree_id)

    # Phase 2: bulk-persist to backend (one transaction, sorted by depth).
    # If the backend write fails, the JSON snapshot is still consistent
    # (the in-memory tree holds the truth) and we surface the error.
    if bulk_nodes:
        try:
            backend = _backend()
            await backend.add_nodes_bulk(tree_id, bulk_nodes, bulk_edges)
        except Exception as exc:
            errors.append({
                "phase": "backend_persist",
                "error": str(exc),
                "note": "in-memory tree is consistent; backend write rolled back",
            })

    return json.dumps(
        {"added": added, "deduped": deduped, "errors": errors},
        ensure_ascii=False,
    )


@tool(
    name="asset_tree_find_unseen",
    description=(
        "List nodes in state UNSEEN — these are the targets for the next "
        "wave. Optionally filter by asset_type to drive a single wave at "
        "a time (e.g. only ROOT_DOMAIN nodes for the subdomain-enumeration "
        "wave, only IP nodes for the port-scan wave). Returns node ids plus "
        "type and value so the LLM can build HANDOFF envelopes without a "
        "follow-up read."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id from asset_tree_create."},
        "asset_type": {
            "type": "string",
            "description": (
                "Optional AssetType filter. If omitted, returns ALL UNSEEN "
                "nodes (caller must group them by type to drive waves)."
            ),
        },
    },
    required=["tree_id"],
)
async def asset_tree_find_unseen(
    tree_id: str,
    asset_type: str | None = None,
) -> str:
    """List UNSEEN nodes, optionally filtered by type."""
    tree = _load_tree(tree_id)
    type_filter: AssetType | None = None
    if asset_type is not None:
        type_filter = _validate_asset_type(asset_type)

    unseen = [
        {"node_id": n.id, "asset_type": n.asset_type.value, "value": n.value}
        for n in tree.nodes_by_state(AssetState.UNSEEN)
        if type_filter is None or n.asset_type == type_filter
    ]

    by_type: dict[str, int] = {}
    for entry in unseen:
        by_type[entry["asset_type"]] = by_type.get(entry["asset_type"], 0) + 1

    return json.dumps(
        {"unseen": unseen, "count": len(unseen), "by_type": by_type},
        ensure_ascii=False,
    )


# ── Phase 2 工具 ──────────────────────────────────────


@tool(
    name="asset_tree_update_state",
    description=(
        "Transition a node to a new AssetState. Typical transitions: "
        "UNSEEN → DISCOVERED (after specialist returns children); "
        "DISCOVERED → TRIAGED (after vulnerability analysis); "
        "any → ABANDONED (unreachable, low-value, etc.). "
        "Persists to disk after the update."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "node_id": {"type": "string", "description": "Node id whose state to update."},
        "state": {
            "type": "string",
            "description": (
                "New state: 'unseen' | 'discovered' | 'triaged' | "
                "'exploited' | 'abandoned'."
            ),
        },
    },
    required=["tree_id", "node_id", "state"],
)
async def asset_tree_update_state(tree_id: str, node_id: str, state: str) -> str:
    """Update one node's AssetState."""
    new_state = _validate_state(state)
    tree = _load_tree(tree_id)

    node = tree.get_node(node_id)
    if node is None:
        raise ToolError(f"Node not found: {node_id}")

    old_state = node.state
    tree.update_state(node_id, new_state)
    _save_tree(tree, tree_id)

    return json.dumps(
        {
            "node_id": node_id,
            "old_state": old_state.value,
            "new_state": new_state.value,
        },
        ensure_ascii=False,
    )


@tool(
    name="asset_tree_get_subtree",
    description=(
        "Render a subtree rooted at `node_id` as a human-readable text "
        "tree. Use this to give a specialist context about its parent / "
        "siblings / descendants before dispatching it."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "node_id": {
            "type": "string",
            "description": "Root of the subtree to render (defaults to root if omitted).",
        },
        "max_depth": {
            "type": "integer",
            "description": "Max depth to render. Default: 3.",
            "default": 3,
        },
    },
    required=["tree_id"],
)
async def asset_tree_get_subtree(
    tree_id: str,
    node_id: str | None = None,
    max_depth: int = 3,
) -> str:
    """Render a subtree as text."""
    tree = _load_tree(tree_id)
    if node_id is None:
        node_id = tree.root_id
    if node_id is None:
        raise ToolError("Tree has no root_id")

    root = tree.get_node(node_id)
    if root is None:
        raise ToolError(f"Node not found: {node_id}")

    lines: list[str] = []
    state_marker = {
        AssetState.UNSEEN: "○",
        AssetState.DISCOVERED: "●",
        AssetState.TRIAGED: "◉",
        AssetState.EXPLOITED: "✓",
        AssetState.ABANDONED: "✗",
    }

    def _walk(nid: str, depth: int, prefix: str, is_last: bool) -> None:
        node = tree.get_node(nid)
        if node is None:
            return
        marker = state_marker.get(node.state, "?")
        connector = "└── " if is_last else "├── "
        lines.append(
            f"{prefix}{connector}[{node.asset_type.value}] {node.value} {marker} ({node.state.value})"
        )
        if depth >= max_depth:
            return
        children = tree.get_children(nid)
        for i, child in enumerate(children):
            extension = "    " if is_last else "│   "
            _walk(child.id, depth + 1, prefix + extension, i == len(children) - 1)

    marker = state_marker.get(root.state, "?")
    lines.append(
        f"[{root.asset_type.value}] {root.value} {marker} ({root.state.value})"
    )
    children = tree.get_children(node_id)
    for i, child in enumerate(children):
        _walk(child.id, 1, "", i == len(children) - 1)

    return json.dumps(
        {
            "node_id": node_id,
            "rendered": "\n".join(lines),
            "node_count": sum(1 for _ in lines),
        },
        ensure_ascii=False,
    )


@tool(
    name="asset_tree_list_siblings",
    description=(
        "List sibling nodes (other children of the same parent) for "
        "context when dispatching a specialist. Returns each sibling's "
        "id, type, value, and state."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "node_id": {"type": "string", "description": "The node whose siblings to list."},
    },
    required=["tree_id", "node_id"],
)
async def asset_tree_list_siblings(tree_id: str, node_id: str) -> str:
    """List sibling nodes."""
    tree = _load_tree(tree_id)
    node = tree.get_node(node_id)
    if node is None:
        raise ToolError(f"Node not found: {node_id}")
    siblings = tree.get_siblings(node_id)
    return json.dumps(
        {
            "node_id": node_id,
            "siblings": [
                {
                    "node_id": s.id,
                    "asset_type": s.asset_type.value,
                    "value": s.value,
                    "state": s.state.value,
                }
                for s in siblings
            ],
            "count": len(siblings),
        },
        ensure_ascii=False,
    )


@tool(
    name="asset_tree_stats",
    description=(
        "Return a summary of the tree: total nodes, by type, by state, "
        "depth, shared-IP count, root domain. Use this at termination "
        "to produce the final report."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
    },
    required=["tree_id"],
)
async def asset_tree_stats(tree_id: str) -> str:
    """Return tree statistics."""
    tree = _load_tree(tree_id)
    return json.dumps(tree.stats(), ensure_ascii=False, default=str)


@tool(
    name="asset_tree_complete",
    description=(
        "Mark the find run as complete. Touches the on-disk file (no "
        "structural change), returns the absolute path to the persisted "
        "tree JSON. Phase 3 will pass this path to `sessions_spawn` as "
        "an artifact for the handoff to hack-deep. Always call this "
        "before reporting [DEEP FIND COMPLETE]."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
    },
    required=["tree_id"],
)
async def asset_tree_complete(tree_id: str) -> str:
    """Mark the find run complete and return the persisted path.

    Batch 5 (2026-06-15): generates a snapshot_id of the form
    ``<tree_id>--<iso_timestamp>`` so the same tree re-run later (e.g.
    via `opensquilla cron add --every ...`) produces a distinct
    snapshot that can be diffed via ``recon_diff_snapshots``.
    """
    tree = _load_tree(tree_id)
    _save_tree(tree, tree_id)  # touch
    path = _tree_path(tree_id)
    # ISO-8601 UTC timestamp, e.g. "2026-06-15T12-34-56Z" (filesystem-safe)
    snapshot_ts = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
    snapshot_id = f"{tree_id}--{snapshot_ts}"
    # Persist a time-stamped snapshot copy so the web UI's
    # "Diff vs 上次" button (and recon_diff_snapshots) can find a
    # stable historical baseline. Without this, the snapshot_id
    # in the response is just metadata — only ``<tree_id>.json``
    # exists on disk, so there's nothing to diff against later.
    snapshot_path = _default_state_root() / f"{snapshot_id}.json"
    try:
        snapshot_path.write_text(tree.to_json(), encoding="utf-8")
    except Exception as exc:  # pragma: no cover — best-effort
        # Snapshot persistence is non-critical: the cumulative
        # ``<tree_id>.json`` is already up to date. Log and proceed.
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "snapshot_persist_failed tree_id=%s path=%s err=%s",
            tree_id, snapshot_path, exc,
        )
    return json.dumps(
        {
            "tree_id": tree_id,
            "tree_path": str(path),
            "snapshot_id": snapshot_id,
            "snapshot_ts": snapshot_ts,
            "snapshot_path": str(snapshot_path),
            "stats": tree.stats(),
        },
        ensure_ascii=False,
        default=str,
    )

# ── Batch 4 (2026-06-15): cross-tree merge ───────────


@tool(
    name="asset_tree_merge",
    description=(
        "Merge nodes from one or more source trees into a target tree. "
        "Useful when running multiple find-runs (e.g. seeded by different "
        "ASN, IP range, or org-name) and you want a consolidated attack "
        "surface view. Dedup is by (asset_type, value) per parent; "
        "collisions preserve the target's existing node. Returns a "
        "summary: nodes_merged, nodes_deduped, nodes_added (per source)."
    ),
    params={
        "target_tree_id": {
            "type": "string",
            "description": "The tree to merge INTO (existing or new).",
        },
        "source_tree_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of source tree ids to merge from.",
        },
        "create_target_if_missing": {
            "type": "boolean",
            "default": False,
            "description": "If True, create the target tree using source[0]'s root_domain.",
        },
    },
    required=["target_tree_id", "source_tree_ids"],
    execution_timeout_seconds=60.0,
)
async def asset_tree_merge(
    target_tree_id: str,
    source_tree_ids: list[str],
    create_target_if_missing: bool = False,
) -> str:
    """Merge source trees into a target tree.

    Algorithm:
      1. Load target tree (or create it from source[0]'s root_domain).
      2. For each source tree:
         a. Load source tree.
         b. For each non-root node in source:
            - If (asset_type, value) already exists at the SAME parent_id
              under target → skip (deduped).
            - If (asset_type, value) exists at a DIFFERENT parent_id →
              add new node under target's matching parent (or skip if
              target has no matching parent — orphan).
            - Else → add new node under target.root_id (treat as new
              seed at the same level).
    """
    if not source_tree_ids:
        raise ToolError("source_tree_ids must be non-empty")

    target_path = _tree_path(target_tree_id)
    if target_path.exists():
        target = _load_tree(target_tree_id)
    elif create_target_if_missing:
        # Borrow root_domain from source[0]
        source0 = _load_tree(source_tree_ids[0])
        target = AssetTree(
            source0.root_domain,
            backend=_backend(),
            tree_id=target_tree_id,
        )
        _save_tree(target, target_tree_id)
    else:
        raise ToolError(
            f"Target tree not found: {target_tree_id}. "
            "Set create_target_if_missing=True to auto-create from source[0]."
        )

    summary = {
        "target_tree_id": target_tree_id,
        "sources": [],
    }

    # Build a lookup: (parent_id, asset_type, value) -> node_id in target
    def _target_index(t: AssetTree) -> dict[tuple[str | None, str, str], str]:
        idx: dict[tuple[str | None, str, str], str] = {}
        for nid, node in t._nodes.items():  # noqa: SLF001 (internal)
            key = (node.parent_id, node.asset_type.value, node.value)
            idx[key] = nid
        return idx

    target_idx = _target_index(target)

    for src_id in source_tree_ids:
        if src_id == target_tree_id:
            summary["sources"].append({"source": src_id, "skipped": "self_merge"})
            continue
        try:
            source = _load_tree(src_id)
        except Exception as exc:
            summary["sources"].append({"source": src_id, "error": str(exc)})
            continue

        added = 0
        deduped = 0
        # Iterate source nodes in BFS-ish order so parents exist before children
        # (source tree is already coherent, so we just iterate by depth).
        nodes_by_depth: dict[int, list[Any]] = {}
        for nid, node in source._nodes.items():  # noqa: SLF001
            if node.parent_id is None:
                continue  # skip source root
            depth = source._edges.get(node.parent_id, [])  # noqa: SLF001
            # crude depth: count ancestors
            cur = node
            d = 0
            while cur.parent_id is not None:
                cur = source._nodes[cur.parent_id]  # noqa: SLF001
                d += 1
            nodes_by_depth.setdefault(d, []).append(node)

        for d in sorted(nodes_by_depth):
            for src_node in nodes_by_depth[d]:
                # Resolve target parent: if source parent_id is the source root,
                # attach to target root. Otherwise look up the source parent in
                # the target's index under the same (asset_type, value).
                target_parent_id: str | None
                if src_node.parent_id == source.root_id:
                    target_parent_id = target.root_id
                else:
                    src_parent = source._nodes.get(src_node.parent_id)  # noqa: SLF001
                    if src_parent is None:
                        continue
                    key = (target.root_id, src_parent.asset_type.value, src_parent.value)
                    target_parent_id = target_idx.get(key, target.root_id)

                # Dedup check
                dedup_key = (target_parent_id, src_node.asset_type.value, src_node.value)
                if dedup_key in target_idx:
                    deduped += 1
                    continue

                # Add to target
                try:
                    new_id = target.add_node(
                        parent_id=target_parent_id,
                        asset_type=src_node.asset_type,
                        value=src_node.value,
                        state=src_node.state,
                        metadata=dict(src_node.metadata or {}),
                    )
                    target_idx[dedup_key] = new_id
                    added += 1
                except Exception as exc:
                    # Skip on add failure (e.g. invalid parent-child)
                    continue

        _save_tree(target, target_tree_id)
        summary["sources"].append(
            {"source": src_id, "added": added, "deduped": deduped}
        )

    summary["target_stats"] = target.stats()
    return json.dumps(summary, ensure_ascii=False, default=str)
