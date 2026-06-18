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

from opensquilla.asset_tree.models import (
    AssetState,
    AssetType,
    FIND_TERMINATION_DEPTH,
    MAX_TREE_DEPTH,
)
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

    # v5 (2026-06-18) 回填 depth: JSON round-trip 不会持久化 _depth
    # (它是 in-memory 字段), 重新构造的 tree 没 set_depth。
    # 没深度 -> is_skeleton_complete() 永远 False (max_depth=0)。
    # 用 BFS 从 root 沿 parent 链下溯, 给每个节点 set_depth(parent_depth+1)。
    _backfill_depths_locked(tree)
    return tree


def _find_existing_tree_for_root(
    root_domain: str, requested_tree_id: str
) -> tuple[str | None, str | None]:
    """Locate an existing AssetTree on disk that already covers
    ``root_domain`` so ``asset_tree_create`` can reconcile instead of
    spawning a duplicate.

    Returns ``(tree_id, json_payload)`` for the best match, or
    ``(None, None)`` if no candidate exists. Match rules, in order:

    1. Exact match: ``requested_tree_id`` file exists and its
       ``root_id`` points to a node whose ``value`` matches
       ``root_domain`` (case-insensitive). This is the happy path for
       idempotent re-runs of the same F0 / F1 wave.
    2. Same-root scan: any ``*.json`` under the asset_trees dir whose
       root node's ``value`` matches ``root_domain``. This catches the
       legacy ``tree-<sanitized>--<ts>`` files that a previous run
       might have left behind — the bug we are fixing.

    The function deliberately returns the JSON payload as-is so the
    caller (``asset_tree_create``) can stream it straight back to the
    LLM without re-serializing.
    """
    if not root_domain:
        return None, None
    target = root_domain.strip().lower()

    # Rule 1 + Rule 2 are folded into a single scan: we always look at
    # every candidate and keep the *largest* by node count. Rule 1 (the
    # exact tree_id the caller asked for) gets a small head-start so a
    # happy-path idempotent re-run still prefers it — but if a sibling
    # file with the same root has more nodes we still upgrade to it.
    # This prevents a fresh small duplicate (e.g. a 55-node tree that
    # an earlier F0 just spawned) from being reused forever.
    requested_payload: str | None = None
    requested_nodes: int = 0
    if _tree_path(requested_tree_id).exists():
        try:
            d = json.loads(_tree_path(requested_tree_id).read_text(encoding="utf-8"))
            root_id = d.get("root_id")
            nodes = d.get("nodes", {})
            root = nodes.get(root_id or "", {}) if root_id else {}
            if (root.get("value") or "").strip().lower() == target and nodes:
                requested_payload = _tree_path(requested_tree_id).read_text(encoding="utf-8")
                requested_nodes = len(nodes)
        except Exception:
            pass
    # Now scan all candidates and pick the one with the most nodes.
    # Prefer the tree with the most nodes — that is the one with the
    # most prior work, even if a fresh duplicate was just created by
    # a parallel F0 wave. mtime alone is unreliable: a brand-new
    # 55-node duplicate is *newer* than a 640-node old tree, but the
    # 640-node tree is what we want to reuse.
    best_id: str | None = None
    best_payload: str | None = None
    best_nodes: int = 0
    try:
        for path in _default_state_root().glob("*.json"):
            if path.name.startswith(".") or path.name.endswith(".tmp"):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            root_id = data.get("root_id")
            nodes = data.get("nodes", {})
            root = nodes.get(root_id or "", {}) if root_id else {}
            value = (root.get("value") or "").strip().lower()
            if value != target:
                continue
            # Skip the empty / sentinel trees (1 node, no edges).
            if len(nodes) <= 1 and not data.get("edges"):
                continue
            n = len(nodes)
            if n > best_nodes:
                best_id = path.stem
                best_payload = path.read_text(encoding="utf-8")
                best_nodes = n
    except Exception:
        pass
    if best_id is not None and best_nodes > requested_nodes:
        return best_id, best_payload
    if requested_payload is not None:
        return requested_tree_id, requested_payload
    return None, None


def _snapshot_dir() -> Path:
    """Directory where ``asset_tree_complete`` writes time-stamped snapshots.

    v4.6 (2026-06-18) hardening: snapshots are an audit artifact for
    ``recon_diff_snapshots`` and the web UI's diff button, NOT a
    separate tree. They must live in a subdirectory so that
    ``_default_state_root().glob("*.json")`` (used by
    ``_find_existing_tree_for_root`` to reconcile per root_domain) does
    not pick them up as candidate canonical trees. The sidebar used
    to list every snapshot as its own tree, which both confused the
    operator and made reconcile pick a snapshot over the real
    canonical when the snapshot happened to have more nodes.
    """
    d = _default_state_root() / ".snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate_asset_type(asset_type_str: str) -> AssetType:
    try:
        return AssetType(asset_type_str)
    except ValueError as exc:
        raise ToolError(
            f"Invalid asset_type: {asset_type_str!r}. "
            f"Must be one of {[t.value for t in AssetType]}"
        ) from exc


def _detect_missing_waves(tree) -> list[str]:
    """v5.2 (2026-06-18) 推断 find 还没跑的 wave 列表 (hack-deep-find 责任范围)。

    v5.2 重大变更: W2.5 (per-port attack plan) **不在 find 责任范围** —
    它由 hack-deep 在 find 终止后, attack phase 中执行。find 不产
    INJECTION_VECTOR 节点 (L7/L8 是漏洞向量, 不是资产)。因此
    ``_detect_missing_waves`` 不再建议 W2.5。

    find 责任范围: W0.5 / W1 / W1.5 / W1.5c / W3.5。
    启发式: 看每层是否还有 UNSEEN / 未达到 FIND_TERMINATION_DEPTH (L7)。
    """
    missing: list[str] = []
    max_d = tree.max_depth_reached()
    # L4+ = chain_fanout wave 需要 UNSEEN 处理
    # max_d >= 3 表示已有 SERVICE, 需要派生 URL
    if max_d >= 3:
        # 已有 SERVICE/URL, 检查 L4+ 是否还有 UNSEEN
        # 注意: 不再把 injection_vector 算进"find 缺漏", 它不在 find 责任范围
        unseen_url = sum(
            1 for n in tree._nodes.values()
            if n.asset_type.value in (
                "endpoint", "parameter",
                "static_asset", "auth_surface", "cookie",
                "header", "api_schema",
            )
            and n.state.value == "unseen"
        )
        # 关键修复: 即使 unseen_url=0 (L4+ 完全没跑), max_d<5 仍应建议 W1.5
        if unseen_url or max_d < 5:
            if max_d < 5:
                missing.append("W1.5")  # URL / endpoint 派生
            if max_d < 6:
                missing.append("W1.5c")  # parameter (L6 资产最深)
            missing.append("W3.5")  # STATIC_ASSET / COOKIE / HEADER
    # L3 UNSEEN
    unseen_l3 = sum(
        1 for n in tree._nodes.values()
        if n.asset_type.value in ("port", "service", "storage_object")
        and n.state.value == "unseen"
    )
    if unseen_l3:
        missing.append("W1")
    # L1/L2 UNSEEN
    unseen_l12 = sum(
        1 for n in tree._nodes.values()
        if n.asset_type.value in ("sub_domain", "ip", "storage")
        and n.state.value == "unseen"
    )
    if unseen_l12:
        missing.append("W0.5")
    return missing


def _backfill_depths_locked(tree: AssetTree) -> None:
    """v5 (2026-06-18) 从 JSON round-trip 后回填节点的 in-memory depth。

    AssetNode._depth 不是 Pydantic 字段, 不会被 model_dump 持久化,
    也不会被 from_dict 恢复。如果不补, 后续 is_skeleton_complete
    / skeleton_report 都会拿到 max_depth=0, 误判骨架没建好。

    BFS from root: root.depth=0; 子.depth=父.depth+1。
    """
    if tree.root_id is None:
        return
    # 先把 root 设为 0
    root = tree.get_node(tree.root_id)
    if root is not None:
        root.set_depth(0)
    # BFS: 用 _edges
    queue: list[str] = [tree.root_id]
    visited: set[str] = {tree.root_id}
    while queue:
        parent_id = queue.pop(0)
        parent_node = tree.get_node(parent_id)
        if parent_node is None:
            continue
        parent_d = parent_node.depth if parent_node.depth >= 0 else 0
        for child_id in tree._edges.get(parent_id, []):
            if child_id in visited:
                continue
            child = tree.get_node(child_id)
            if child is None:
                continue
            child.set_depth(parent_d + 1)
            visited.add(child_id)
            queue.append(child_id)


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

    # v4.6 (2026-06-18) canonical tree_id contract:
    # The single canonical tree_id for ``root_domain=X`` is
    # ``tree-{X}`` with dots preserved (e.g. ``tree-10jqka.com.cn``).
    # Reject any caller-supplied tree_id that does not match the
    # canonical form — the LLM orchestrator used to invent names
    # like ``10jqka.com.cn.zombie`` or
    # ``tree-51ifind.com-fresh-20260617T1346`` which created phantom
    # trees that the asset-tree sidebar listed alongside the real
    # canonical tree. Snapshots and reconciliation are handled
    # separately by ``asset_tree_complete`` (writes JSON only, no
    # DB row) and ``_find_existing_tree_for_root`` (picks the
    # largest tree for the root_domain), so callers never need to
    # invent a tree_id.
    def _canonical_tree_id(domain: str) -> str:
        # Keep alnum + dot + dash only; collapse anything else to ``-``
        # and strip leading/trailing dashes. Dots are preserved (the
        # ``root_domain`` already includes the TLD).
        sanitized = "".join(c if c.isalnum() or c in "-." else "-" for c in domain.strip())
        sanitized = sanitized.strip("-")
        return f"tree-{sanitized}" if sanitized else "tree-root"

    canonical = _canonical_tree_id(root_domain)
    if tree_id is not None and tree_id != canonical:
        raise ToolError(
            f"tree_id must equal the canonical id {canonical!r} for "
            f"root_domain={root_domain!r} (got {tree_id!r}). "
            "Pass tree_id=None to use the canonical id, or use "
            "asset_tree_complete to take a historical snapshot."
        )
    tree_id = canonical

    # Reuse-reconcile: if a tree with this exact tree_id already exists,
    # return it (idempotent). If a *different* tree has the same
    # root_domain, prefer it — this prevents the F0 specialist from
    # accidentally creating a fresh tree when an old one (named via the
    # legacy ``tree-<sanitized>--<ts>`` convention) is still on disk.
    # The orchestrator can still force a fresh tree by passing an
    # explicit, never-before-used tree_id.
    existing_id, existing_payload = _find_existing_tree_for_root(root_domain.strip(), tree_id)
    if existing_payload is not None:
        # Reuse the existing tree — return its tree_id + root_id, do not
        # create a new one. This is idempotent: callers can safely call
        # asset_tree_create at the start of every F0 / F1 wave without
        # worrying about whether a prior run already bootstrapped the
        # tree.
        return existing_payload
    if _tree_path(tree_id).exists():
        # tree_id is new but a file with this name already exists —
        # surface as a real error to avoid silent overwrites.
        raise ToolError(f"Tree already exists: {tree_id} (at {_tree_path(tree_id)})")

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
        "wave, only IP nodes for the port-scan wave). v5 (2026-06-18) adds "
        "a max_depth filter to keep the orchestrator from issuing waves "
        "against nodes that would push the tree past MAX_TREE_DEPTH=8. "
        "Returns node ids plus type and value so the LLM can build HANDOFF "
        "envelopes without a follow-up read."
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
        "max_depth": {
            "type": "integer",
            "description": (
                "v5 (2026-06-18): only return UNSEEN nodes with "
                "``path_depth <= max_depth``. Default ``MAX_TREE_DEPTH`` (= 8). "
                "Set lower to constrain the wave scope to upper layers "
                "(e.g. ``max_depth=2`` returns only root + sub + ip)."
            ),
            "default": MAX_TREE_DEPTH,
        },
    },
    required=["tree_id"],
)
async def asset_tree_find_unseen(
    tree_id: str,
    asset_type: str | None = None,
    max_depth: int = MAX_TREE_DEPTH,
) -> str:
    """List UNSEEN nodes, optionally filtered by type and depth."""
    tree = _load_tree(tree_id)
    type_filter: AssetType | None = None
    if asset_type is not None:
        type_filter = _validate_asset_type(asset_type)
    if max_depth < 0:
        raise ToolError(
            f"max_depth must be >= 0, got {max_depth}; "
            f"MAX_TREE_DEPTH={MAX_TREE_DEPTH}"
        )
    if max_depth > MAX_TREE_DEPTH:
        # 业务硬约束 8 层; 超过该值的入树请求被 validate_depth 拒绝, 
        # find_unseen 返回更深层无意义, 直接截断到 MAX_TREE_DEPTH。
        max_depth = MAX_TREE_DEPTH

    # v5 (2026-06-18): 读取 ``n.depth`` (AssetNode 上的 property, 由
    # ``AssetTree._add_node_locked`` 写入时 set_depth() 设置)。
    unseen = [
        {
            "node_id": n.id,
            "asset_type": n.asset_type.value,
            "value": n.value,
            "depth": n.depth,
        }
        for n in tree.nodes_by_state(AssetState.UNSEEN)
        if (type_filter is None or n.asset_type == type_filter)
        and n.depth <= max_depth
    ]

    by_type: dict[str, int] = {}
    by_depth: dict[str, int] = {}
    for entry in unseen:
        by_type[entry["asset_type"]] = by_type.get(entry["asset_type"], 0) + 1
        d = entry["depth"]
        by_depth[str(d)] = by_depth.get(str(d), 0) + 1

    return json.dumps(
        {
            "unseen": unseen,
            "count": len(unseen),
            "by_type": by_type,
            "by_depth": by_depth,
            "max_depth_applied": max_depth,
        },
        ensure_ascii=False,
    )


@tool(
    name="asset_tree_find_unseen_chain",
    description=(
        "v5 (2026-06-18) chain-fanout mode for L4+ discovery. Returns "
        "UNSEEN nodes grouped by their parent chain so the orchestrator "
        "can dispatch ONE specialist per chain (avoiding context blow-up "
        "when a service has 1000+ endpoints). Each chain entry: "
        "chain_root_node_id, chain_root_value, chain_path (L0..L[n] "
        "breadcrumb), unseen_children (list of {node_id, asset_type, "
        "value, depth}). Use this for W1.5 / W1.5c / W2.5 / W3.5 (L4+). "
        "Use asset_tree_find_unseen (bulk) for W0.5 / W1 (L0..L3)."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "asset_type": {
            "type": "string",
            "description": (
                "Optional AssetType filter. Common: url, endpoint, "
                "parameter, injection_vector."
            ),
        },
        "min_depth": {
            "type": "integer",
            "description": (
                "Only include chains whose root depth >= min_depth. "
                "Default 4 (= L4 URL layer) so bulk L0..L3 waves do not "
                "see this output."
            ),
            "default": 4,
        },
        "max_chains": {
            "type": "integer",
            "description": (
                "Limit number of chains returned (orchestrator pacing). "
                "Default 50. Each chain may itself have many unseen "
                "children; caller decides sub-batch size."
            ),
            "default": 50,
        },
    },
    required=["tree_id"],
)
async def asset_tree_find_unseen_chain(
    tree_id: str,
    asset_type: str | None = None,
    min_depth: int = 4,
    max_chains: int = 50,
) -> str:
    """List UNSEEN nodes grouped by their parent chain (L4+ discovery)."""
    tree = _load_tree(tree_id)
    type_filter: AssetType | None = None
    if asset_type is not None:
        type_filter = _validate_asset_type(asset_type)
    if min_depth < 0:
        min_depth = 0
    if max_chains <= 0:
        max_chains = 50

    # 1. Collect UNSEEN nodes (type filter + min_depth filter).
    unseen = [
        n for n in tree.nodes_by_state(AssetState.UNSEEN)
        if (type_filter is None or n.asset_type == type_filter)
        and n.depth >= min_depth
        and n.depth <= MAX_TREE_DEPTH
    ]

    # 2. Group by parent_id (one parent = one chain).
    by_parent: dict[str, list[AssetNode]] = {}
    for n in unseen:
        pid = n.parent_id or "<root>"
        by_parent.setdefault(pid, []).append(n)

    # 3. Assemble chain structure.
    chains: list[dict[str, Any]] = []
    for parent_id, children in by_parent.items():
        if len(chains) >= max_chains:
            break
        if parent_id == "<root>":
            chain_root_id = tree.root_id
            chain_root_value = tree.root_domain
        else:
            chain_root_id = parent_id
            parent_node = tree.get_node(parent_id)
            chain_root_value = parent_node.value if parent_node else "<unknown>"
        # Path breadcrumb: ROOT -> ... -> parent_id
        path_parts: list[str] = []
        cur = parent_id if parent_id != "<root>" else tree.root_id
        seen_pids: set[str] = set()
        while cur and cur not in seen_pids:
            seen_pids.add(cur)
            node = tree.get_node(cur)
            if node is None:
                break
            path_parts.append(f"{node.asset_type.value}={node.value}")
            cur = node.parent_id
        path_parts.reverse()
        chains.append({
            "chain_root_node_id": chain_root_id,
            "chain_root_value": chain_root_value,
            "chain_path": " → ".join(path_parts),
            "unseen_children": [
                {
                    "node_id": c.id,
                    "asset_type": c.asset_type.value,
                    "value": c.value,
                    "depth": c.depth,
                }
                for c in children
            ],
            "unseen_count": len(children),
        })
    # Sort by unseen_count desc so orchestrator tackles the "biggest" chains first.
    chains.sort(key=lambda c: -c["unseen_count"])

    return json.dumps(
        {
            "chains": chains,
            "chain_count": len(chains),
            "unseen_total": len(unseen),
            "min_depth_applied": min_depth,
            "strategy": "chain_fanout",
        },
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
            "description": (
                "Max depth to render. v5 (2026-06-18) default 8 (= "
                "MAX_TREE_DEPTH) so a subtree render covers the full "
                "business-deepest chain (root → ... → injection_vector)."
            ),
            "default": MAX_TREE_DEPTH,
        },
    },
    required=["tree_id"],
)
async def asset_tree_get_subtree(
    tree_id: str,
    node_id: str | None = None,
    max_depth: int = MAX_TREE_DEPTH,
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
    name="asset_tree_check_skeleton",
    description=(
        "v5 (2026-06-18) 8-layer skeleton integrity report. "
        "Returns: completion flag, max_depth_reached, completion_pct, "
        "nodes_per_layer, unseen counts (total / by_type / by_layer), "
        "abandoned count. Call this BEFORE emitting find-complete-v1 to "
        "verify the skeleton is fully built (complete=true), otherwise "
        "F-final-pre must run another F-resume pass."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
    },
    required=["tree_id"],
)
async def asset_tree_check_skeleton(tree_id: str) -> str:
    """Return 8-layer skeleton integrity report."""
    tree = _load_tree(tree_id)
    return json.dumps(tree.skeleton_report(), ensure_ascii=False, default=str)


@tool(
    name="asset_tree_dispatch_plan",
    description=(
        "v5 (2026-06-18) orchestrator spawn-plan generator. For each "
        "wave, returns: strategy (bulk_layer or chain_fanout), "
        "spawn_count (number of sessions_spawn to fire), unseen_total, "
        "sample_targets, fanout_agents. Use this ONCE per find-run to "
        "compute the full dispatch plan before F0..F3.5; or per wave "
        "to decide spawning. L0..L3 (W0.5, W1) use bulk_layer; L4+ "
        "(W1.5, W1.5c, W2.5, W3.5) use chain_fanout."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "max_chains": {
            "type": "integer",
            "description": (
                "For chain_fanout waves, max number of chains to dispatch. "
                "Default 50."
            ),
            "default": 50,
        },
        "batch_size_bulk": {
            "type": "integer",
            "description": (
                "For bulk_layer waves, batch size (UNSEEN per spawn). "
                "Default 10. port-scanner uses 5-10 IP, "
                "service-fingerprint uses 10-20 port."
            ),
            "default": 10,
        },
    },
    required=["tree_id"],
)
async def asset_tree_dispatch_plan(
    tree_id: str,
    max_chains: int = 50,
    batch_size_bulk: int = 10,
) -> str:
    """Return per-wave dispatch plan (strategy + spawn_count)."""
    tree = _load_tree(tree_id)
    return json.dumps(
        tree.dispatch_plan(max_chains=max_chains, batch_size_bulk=batch_size_bulk),
        ensure_ascii=False,
        default=str,
    )


@tool(
    name="asset_tree_complete",
    description=(
        "Mark the find run as complete. Touches the on-disk file (no "
        "structural change), returns the absolute path to the persisted "
        "tree JSON. The handoff to the next phase is handled by the "
        "caller (orchestrator / cron / main agent) after this tool returns.\n\n"
        "v5.2 (2026-06-18) HARD GATE: this tool enforces the find-skeleton "
        "termination contract. If ``is_skeleton_complete()`` returns false "
        "(i.e. tree has not reached path_depth>=7 / L7 PARAMETER or has "
        "UNSEEN nodes), the call raises ``IncompleteSkeletonError`` and "
        "returns a diagnostic report showing what is missing. To bypass "
        "(emergency only), pass ``force=True``.\n\n"
        "v5.2 重大变更: find 终止深度从 L8 INJECTION_VECTOR 改为 L7 "
        "PARAMETER (path_depth=7, 业务最深资产层). L8 节点属于漏洞向量, "
        "由 hack-deep 在 attack phase 写入, find 不再要求也不负责.\n\n"
        "v5.1 修过的 bug: find-complete-v1 之前可能在只跑 F0/F1 (L0..L3) 时 "
        "就 emit, 8 层骨架根本没建. 本 HARD GATE 解决此问题.\n\n"
        "v4.6 (2026-06-18): a time-stamped snapshot copy is written to "
        "``~/.opensquilla/state/asset_trees/.snapshots/<tree_id>--<ts>.json`` "
        "(separate from the live canonical tree) so the web UI's "
        "diff-vs-last button and ``recon_diff_snapshots`` keep working. "
        "Snapshots are NOT inserted into the MySQL ``asset_trees`` table "
        "and must not be confused with new trees."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "force": {
            "type": "boolean",
            "description": (
                "Bypass the find-skeleton hard gate. Default False. "
                "Emergency-only — do not use in normal find runs. Setting "
                "force=True emits a warning to the response."
            ),
            "default": False,
        },
    },
    required=["tree_id"],
)
async def asset_tree_complete(tree_id: str, force: bool = False) -> str:
    """Mark the find run complete and return the persisted path.

    Batch 5 (2026-06-15): generates a snapshot_id of the form
    ``<tree_id>--<iso_timestamp>`` so the same tree re-run later (e.g.
    via `opensquilla cron add --every ...`) produces a distinct
    snapshot that can be diffed via ``recon_diff_snapshots``.

    v5.2 (2026-06-18) HARD GATE: refuses to complete when find-skeleton
    is not complete. Returns a diagnostic report and raises
    ``IncompleteSkeletonError`` so the orchestrator can re-run F-resume.
    Termination depth is L6 (PARAMETER), not L8.
    """
    tree = _load_tree(tree_id)
    # v5.2 HARD GATE: refuse to mark complete if find-skeleton is not built.
    # find 终止契约: max_depth >= FIND_TERMINATION_DEPTH (L6 PARAMETER)
    # AND no UNSEEN nodes. ABANDONED nodes don't block (软删合法).
    if not force and not tree.is_skeleton_complete():
        report = tree.skeleton_report()
        # 用专门的 IncompleteSkeletonError (v5.2), 让编排器可以精确捕获
        # 并触发 F-resume, 而不是被通用 ToolError 吞掉。
        # max_depth_required 用 find_termination_depth (L6) — 反映 find
        # 终止契约; max_depth_cap (L8) 仍在 report 里给出, 仅作参考。
        from opensquilla.asset_tree.models import IncompleteSkeletonError as _ISE
        raise _ISE(
            tree_id=tree_id,
            max_depth_reached=report["max_depth_reached"],
            max_depth_required=report["find_termination_depth"],
            unseen_total=report["unseen_total"],
            completion_pct=report["completion_pct"],
            missing_waves=_detect_missing_waves(tree),
        )
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
    # v4.6 (2026-06-18) snapshots go under ``.snapshots/`` so the
    # reconcile glob in ``_default_state_root().glob("*.json")`` does
    # not mistake them for live trees. See ``_snapshot_dir`` docstring.
    snapshot_path = _snapshot_dir() / f"{snapshot_id}.json"
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
            "skeleton": tree.skeleton_report(),
            "force_used": force,
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


# ── v4.5 增量更新工具 (2026-06-18) ────────────────────
# Soft-delete / resurrect semantics for incremental asset discovery.
# When hack-deep-find runs F0 / F1 / F3.5 again on a previously-scanned
# target, the LLM-coordinator needs:
#   (a) The set of nodes present in the tree that were NOT redetected
#       in the current wave -> mark ABANDONED.
#   (b) The set of nodes already ABANDONED that WERE redetected ->
#       flipped back to DISCOVERED automatically (handled in tree.py
#       add_node dedup hit path).
#   (c) A summary of new vs preserved vs abandoned so the LLM can
#       write a clean evidence block at the end of the wave.


@tool(
    name="asset_tree_diff_existing",
    description=(
        "v4.5: For incremental re-discovery on a target that has "
        "already been scanned. Returns 3 lists:\n"
        "  - 'preserved': existing DISCOVERED/UNSEEN nodes whose "
        "(asset_type, value) appears in the current evidence. The "
        "caller does NOT need to call add_node for these — they are "
        "still in the tree and will be dedup-hit on add_node (which "
        "also auto-resurrects any ABANDONED ones).\n"
        "  - 'abandoned_candidates': existing DISCOVERED/UNSEEN nodes "
        "whose (asset_type, value) does NOT appear in the current "
        "evidence. The caller should call asset_tree_update_state for "
        "each of these to mark them ABANDONED. Soft-delete: the node "
        "is kept in the tree (not removed); if the same asset comes "
        "back in a future wave, add_node will resurrect it.\n"
        "  - 'rediscovered_abandoned': nodes that were ABANDONED but "
        "are now in the current evidence. The caller does NOT need to "
        "do anything for these — the upcoming add_node call will "
        "auto-resurrect them. This list is informational.\n"
        "Returns the lists as JSON arrays of {node_id, asset_type, "
        "value, state, last_seen, parent_id}. The LLM-coordinator "
        "uses this to drive the 'incremental re-discovery' workflow "
        "without re-reading the entire AssetTree."
    ),
    params={
        "tree_id": {"type": "string", "description": "Tree id."},
        "current_evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "description": (
                    "An asset from the current wave's specialist "
                    "evidence. Required: 'asset_type' and 'value'. "
                    "Optional: 'parent_value' (matches the existing "
                    "tree node's parent_id by traversing parent "
                    "value->id for per-parent-state types like "
                    "COOKIE / HEADER / PARAMETER / STATIC_ASSET)."
                ),
            },
            "description": (
                "List of {asset_type, value, [parent_value]} from "
                "the current wave's specialist evidence. Typically the "
                "union of all specialist findings for the wave."
            ),
        },
    },
    required=["tree_id", "current_evidence"],
)
async def asset_tree_diff_existing(
    tree_id: str,
    current_evidence: list[dict[str, Any]],
) -> str:
    """Compute preserved / abandoned_candidates / rediscovered_abandoned.

    This is a read-only tool. It does NOT mutate the tree. The caller
    is expected to:
      1. Call add_node for everything in `current_evidence` (which
         dedup-hits preserved items, resurrects rediscovered_abandoned
         items, and creates new items).
      2. Call update_state(id, ABANDONED) for every node in
         `abandoned_candidates`.
    """
    tree = _load_tree(tree_id)

    # Build a set of (asset_type, value) tuples from the current
    # evidence for fast lookup.
    current_set: set[tuple[str, str]] = set()
    for entry in current_evidence or []:
        at = (entry.get("asset_type") or "").strip()
        v = (entry.get("value") or "").strip()
        if at and v:
            current_set.add((at, v))

    preserved: list[dict[str, Any]] = []
    abandoned_candidates: list[dict[str, Any]] = []
    rediscovered_abandoned: list[dict[str, Any]] = []

    for node in tree._nodes.values():
        # ROOT_DOMAIN is the run target itself; it represents the
        # scope of the run, not a discovered asset. Never mark it
        # ABANDONED (that would orphan the rest of the tree).
        if node.asset_type == AssetType.ROOT_DOMAIN:
            continue
        key = (node.asset_type.value, node.value)
        is_currently_active = node.state in (
            AssetState.DISCOVERED,
            AssetState.UNSEEN,
        )
        in_current_wave = key in current_set
        if is_currently_active and in_current_wave:
            preserved.append({
                "node_id": node.id,
                "asset_type": node.asset_type.value,
                "value": node.value,
                "state": node.state.value,
                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                "parent_id": node.parent_id,
            })
        elif is_currently_active and not in_current_wave:
            abandoned_candidates.append({
                "node_id": node.id,
                "asset_type": node.asset_type.value,
                "value": node.value,
                "state": node.state.value,
                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                "parent_id": node.parent_id,
                "abandoned_at": _utcnow_iso(),
            })
        elif node.state == AssetState.ABANDONED and in_current_wave:
            rediscovered_abandoned.append({
                "node_id": node.id,
                "asset_type": node.asset_type.value,
                "value": node.value,
                "state": node.state.value,
                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                "parent_id": node.parent_id,
            })

    return json.dumps(
        {
            "tree_id": tree_id,
            "current_wave_size": len(current_set),
            "preserved": preserved,
            "abandoned_candidates": abandoned_candidates,
            "rediscovered_abandoned": rediscovered_abandoned,
            "summary": {
                "preserved_count": len(preserved),
                "abandoned_candidates_count": len(abandoned_candidates),
                "rediscovered_abandoned_count": len(rediscovered_abandoned),
            },
        },
        ensure_ascii=False,
        default=str,
    )


@tool(
    name="asset_tree_plan_pending",
    description=(
        "v4.5.1: For incremental re-discovery on a target that has "
        "already been scanned but is incomplete. Returns a structured "
        "plan the LLM-coordinator can use to drive a 'resume scan' "
        "loop:\n"
        "  - 'completion_pct': 1 - (unseen / total) - when this "
        "reaches 1.0 the tree is fully built.\n"
        "  - 'incomplete_by_type_state': {asset_type: {state: count}} "
        "for nodes still in UNSEEN state. The LLM uses this to "
        "decide which specialists to dispatch.\n"
        "  - 'pending_waves': a list of waves to run, each with the "
        "target asset_type, count, and recommended specialists. "
        "Wave mapping (per SOUL_BODY.md F0-F-final):\n"
        "    W1   <- ip:unseen  (port-scanner), port:unseen "
        "(service-fingerprint, optionally webapp-discoverer)\n"
        "    W1.5 <- sub_domain:unseen, service:unseen, "
        "storage:unseen (webapp-discoverer, component-detector, "
        "storage-discoverer, secret-scanner)\n"
        "    W3.5 <- url:unseen, endpoint:unseen, component:unseen "
        "(webapp-discoverer, content-classifier, api-surface-mapper)\n"
        "  - 'abandoned_to_retry': list of ABANDONED non-root_domain "
        "nodes the LLM may want to revisit (e.g. an IP that was "
        "temporarily unreachable but is back). Read-only; resurrection "
        "happens automatically when add_node dedup-hits.\n"
        "  - 'discovered_breakdown' / 'triaged_or_exploited_breakdown': "
        "supporting counts for sanity check.\n"
        "  - 'sample_unseen': a small (<=10) sample of unseen nodes per "
        "asset_type for the LLM to know the values before dispatching "
        "(so it doesn't have to make a second read of the tree).\n"
        "Read-only tool - does NOT mutate the tree."
    ),
    params={
        "tree_id": {
            "type": "string",
            "description": "Tree id (e.g. '10jqka.com.cn').",
        },
        "max_sample_per_type": {
            "type": "integer",
            "description": (
                "Max unseen node values to sample per asset_type in "
                "'sample_unseen'. Default 10, capped at 50."
            ),
        },
    },
    required=["tree_id"],
)
async def asset_tree_plan_pending(
    tree_id: str,
    max_sample_per_type: int = 10,
) -> str:
    """Build a resume-scan plan for an incomplete asset tree.

    Walks the tree, groups incomplete (UNSEEN) nodes by asset_type,
    maps them to the wave that owns that asset_type, and surfaces
    ABANDONED nodes as a retry candidate list. Read-only.
    """
    tree = _load_tree(tree_id)

    cap = max(0, min(int(max_sample_per_type or 0), 50))

    # Wave assignment by asset_type. UNSEEN-only - DISCOVERED/TRIAGED/
    # EXPLOITED nodes are considered done.
    # v4.5.1 fix: SUB_DOMAIN:unseen -> W0.5 (not W1.5). v3-residual
    # mapping put it under W1.5 which dragged webapp-discoverer
    # onto the wrong fanout object (sub_domain has no port context,
    # webapp-discoverer needs a service with banner).
    WAVE_BY_TYPE: dict[str, str] = {
        AssetType.SUB_DOMAIN.value: "W0.5",   # ← W0.5: domain-expander / osint-collector
        AssetType.IP.value: "W1",
        AssetType.PORT.value: "W1",
        AssetType.SERVICE.value: "W1.5",      # ← W1.5: webapp-discoverer / component-detector (per-service)
        AssetType.STORAGE.value: "W1.5",     # ← W1.5: storage-discoverer (per-subdomain via parent)
        AssetType.URL.value: "W3.5",         # ← W3.5: webapp-discoverer / content-classifier / api-surface-mapper (per-url)
        AssetType.ENDPOINT.value: "W3.5",
        AssetType.COMPONENT.value: "W3.5",   # ← component-detector 也可在此二探 (per-url JS bundle)
    }
    SPECIALISTS_BY_WAVE: dict[str, list[str]] = {
        "W0.5": ["domain-expander", "osint-collector"],
        "W1": ["port-scanner", "service-fingerprint"],
        "W1.5": [
            "webapp-discoverer",     # per-service
            "component-detector",    # per-service (also per-url for JS bundle)
            "storage-discoverer",    # per-subdomain (via parent walk)
            "secret-scanner",        # per-url
        ],
        "W3.5": [
            "webapp-discoverer",     # per-url — dir busting / path discovery
            "content-classifier",    # per-url — page type / auth surface
            "api-surface-mapper",    # per-url — endpoint / parameter / API schema
        ],
    }

    # Counters
    total = 0
    unseen_count = 0
    incomplete_by_type_state: dict[str, dict[str, int]] = {}
    discovered_breakdown: dict[str, int] = {}
    triaged_or_exploited_breakdown: dict[str, int] = {}
    sample_unseen: dict[str, list[dict[str, Any]]] = {}
    abandoned_to_retry: list[dict[str, Any]] = []

    for node in tree._nodes.values():
        if node.asset_type == AssetType.ROOT_DOMAIN:
            continue
        total += 1
        at = node.asset_type.value
        st = node.state.value
        if node.state == AssetState.UNSEEN:
            unseen_count += 1
            slot = incomplete_by_type_state.setdefault(at, {})
            slot[st] = slot.get(st, 0) + 1
            cap_t = sample_unseen.setdefault(at, [])
            if cap == 0 or len(cap_t) < cap:
                cap_t.append({
                    "node_id": node.id,
                    "value": node.value,
                    "parent_id": node.parent_id,
                    "first_seen": (
                        node.first_seen.isoformat()
                        if node.first_seen
                        else None
                    ),
                })
        elif node.state == AssetState.DISCOVERED:
            discovered_breakdown[at] = discovered_breakdown.get(at, 0) + 1
        elif node.state in (
            AssetState.TRIAGED,
            AssetState.EXPLOITED,
        ):
            triaged_or_exploited_breakdown[at] = (
                triaged_or_exploited_breakdown.get(at, 0) + 1
            )
        elif node.state == AssetState.ABANDONED:
            abandoned_to_retry.append({
                "node_id": node.id,
                "asset_type": at,
                "value": node.value,
                "parent_id": node.parent_id,
                "last_seen": (
                    node.last_seen.isoformat() if node.last_seen else None
                ),
            })

    # Build pending_waves from incomplete_by_type_state.
    wave_counts: dict[str, int] = {}
    wave_types: dict[str, list[str]] = {}
    for at, by_state in incomplete_by_type_state.items():
        wave = WAVE_BY_TYPE.get(at)
        if not wave:
            # UNSEEN nodes of unmapped types are surfaced as
            # 'unmapped_unseen' so the LLM can decide.
            continue
        c = sum(by_state.values())
        wave_counts[wave] = wave_counts.get(wave, 0) + c
        wave_types.setdefault(wave, []).append(at)

    # Wave order: W0.5 (subdomain) -> W1 (ip/port) -> W1.5 (service/storage)
    # -> W3.5 (url/endpoint/component). Strict upstream-to-downstream
    # because URL/endpoint need SERVICE as parent and SERVICE needs
    # PORT as parent.
    pending_waves: list[dict[str, Any]] = []
    for wave in ("W0.5", "W1", "W1.5", "W3.5"):
        if wave_counts.get(wave, 0) > 0:
            pending_waves.append({
                "wave": wave,
                "specialists": SPECIALISTS_BY_WAVE[wave],
                "asset_types": sorted(wave_types[wave]),
                "unseen_count": wave_counts[wave],
            })

    # Unmapped UNSEEN types (PARAMETER, INJECTION_VECTOR, etc.)
    # are deeper-tier - the LLM should finish W1/W1.5/W3.5 first.
    unmapped_unseen: dict[str, int] = {
        at: sum(by_state.values())
        for at, by_state in incomplete_by_type_state.items()
        if at not in WAVE_BY_TYPE
    }

    completion_pct = (
        1.0 - (unseen_count / total) if total else 1.0
    )
    is_complete = unseen_count == 0

    return json.dumps(
        {
            "tree_id": tree_id,
            "total_nodes": total,
            "unseen_count": unseen_count,
            "completion_pct": round(completion_pct, 4),
            "is_complete": is_complete,
            "incomplete_by_type_state": incomplete_by_type_state,
            "pending_waves": pending_waves,
            "unmapped_unseen": unmapped_unseen,
            "abandoned_to_retry": abandoned_to_retry,
            "abandoned_to_retry_count": len(abandoned_to_retry),
            "discovered_breakdown": discovered_breakdown,
            "triaged_or_exploited_breakdown": (
                triaged_or_exploited_breakdown
            ),
            "sample_unseen": sample_unseen,
            "generated_at": _utcnow_iso(),
        },
        ensure_ascii=False,
        default=str,
    )


def _utcnow_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
