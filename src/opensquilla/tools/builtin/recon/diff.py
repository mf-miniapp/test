"""Asset tree diff tools (Batch 5, group:recon:diff).

Tools:
  - recon_diff_snapshots   Compare two AssetTree JSON files, return added /
                           removed / changed nodes per layer
  - recon_list_snapshots   List all historical snapshots under
                           ~/.opensquilla/state/asset_trees/, optionally
                           filtered by root_domain substring

Batch 5 (2026-06-15): time-dimension support for hack-deep-find. Re-uses
the JSON snapshot file produced by `asset_tree_complete` (which now
embeds a `snapshot_id` of the form `<tree_id>--<iso_ts>`).

Pure-stdlib; no network, no DB.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opensquilla.tools.registry import tool


# ── helpers ──────────────────────────────────────────


def _state_root() -> Path:
    """Resolve the asset_trees state dir lazily so OPEN_SQUILLA_STATE_DIR is respected.

    Tests set OPEN_SQUILLA_STATE_DIR to a tmp_path via monkeypatch; we
    must re-read the env on every call rather than caching at import time.
    """
    env = os.environ.get("OPEN_SQUILLA_STATE_DIR")
    return Path(env) if env else (Path.home() / ".opensquilla" / "state" / "asset_trees")


def _list_snapshot_files(root_domain_substr: str | None = None) -> list[Path]:
    """Return all *.json files in the asset_trees dir, optionally filtered."""
    root = _state_root()
    if not root.exists():
        return []
    files = sorted(root.glob("*.json"))
    if root_domain_substr:
        files = [f for f in files if root_domain_substr in f.name]
    return files


def _load_tree_nodes(path: Path) -> dict[str, dict[str, Any]]:
    """Load an AssetTree JSON and return {node_id: {asset_type, value, parent_id, metadata, state}}.

    Best-effort: tolerates the on-disk format (which may have nodes nested
    inside a top-level `nodes` dict, or flattened as `_nodes`).
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    # The serialized format: top-level `nodes` is a dict[ node_id, node_dict ]
    # (per asset_tree.tree.to_dict). Each node_dict has asset_type, value,
    # parent_id, metadata, state, ...
    nodes = doc.get("nodes") or {}
    return nodes


# ── 1. recon_diff_snapshots ──────────────────────────


@tool(
    name="recon_diff_snapshots",
    description=(
        "Diff two AssetTree JSON snapshots. Returns added/removed/changed "
        "nodes bucketed by asset_type, plus a high-level summary "
        "(new_attack_surface_count, disappeared_count, sensitivity_escalation_count). "
        "Use this for time-dimension (Batch 5) or merge-dimension (Batch 4) "
        "delta detection."
    ),
    params={
        "snapshot_a_path": {
            "type": "string",
            "description": "Path to the older snapshot (or left-hand tree).",
        },
        "snapshot_b_path": {
            "type": "string",
            "description": "Path to the newer snapshot (or right-hand tree).",
        },
        "sensitivity_field": {
            "type": "string",
            "default": "risk",
            "description": (
                "Node metadata field to compare for ladder-escalation detection. "
                "Defaults to 'risk' (the canonical field used by the "
                "cookie-header specialist). For STATIC_ASSET, you may want to "
                "pass 'sensitivity' explicitly. Any value not in the risk "
                "ladder (info/low/medium/high/critical) is simply ignored."
            ),
        },
        "include_subtree_moves": {
            "type": "boolean",
            "default": True,
            "description": (
                "If True, also report nodes whose parent_id changed (subtree move). "
                "Default: True."
            ),
        },
    },
    required=["snapshot_a_path", "snapshot_b_path"],
    execution_timeout_seconds=15.0,
)
async def recon_diff_snapshots(
    snapshot_a_path: str,
    snapshot_b_path: str,
    sensitivity_field: str = "risk",
    include_subtree_moves: bool = True,
) -> str:
    """Diff two snapshots."""
    pa = Path(snapshot_a_path)
    pb = Path(snapshot_b_path)
    if not pa.exists():
        raise FileNotFoundError(f"snapshot_a not found: {snapshot_a_path}")
    if not pb.exists():
        raise FileNotFoundError(f"snapshot_b not found: {snapshot_b_path}")

    a_nodes = _load_tree_nodes(pa)
    b_nodes = _load_tree_nodes(pb)

    a_ids = set(a_nodes.keys())
    b_ids = set(b_nodes.keys())

    # Buckets
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    moved: list[dict[str, Any]] = []

    # Added: in B, not in A
    for nid in b_ids - a_ids:
        n = b_nodes[nid]
        added.append(
            {
                "node_id": nid,
                "asset_type": n.get("asset_type"),
                "value": n.get("value"),
                "parent_id": n.get("parent_id"),
                "metadata": n.get("metadata") or {},
            }
        )
    # Removed: in A, not in B
    for nid in a_ids - b_ids:
        n = a_nodes[nid]
        removed.append(
            {
                "node_id": nid,
                "asset_type": n.get("asset_type"),
                "value": n.get("value"),
                "parent_id": n.get("parent_id"),
            }
        )
    # Common: check value / metadata / parent_id changes
    for nid in a_ids & b_ids:
        a, b = a_nodes[nid], b_nodes[nid]
        diffs: dict[str, Any] = {}
        # value
        if a.get("value") != b.get("value"):
            diffs["value"] = {"from": a.get("value"), "to": b.get("value")}
        # parent_id
        if include_subtree_moves and a.get("parent_id") != b.get("parent_id"):
            diffs["parent_id"] = {"from": a.get("parent_id"), "to": b.get("parent_id")}
            moved.append(
                {
                    "node_id": nid,
                    "asset_type": a.get("asset_type"),
                    "value": b.get("value"),
                    "from_parent": a.get("parent_id"),
                    "to_parent": b.get("parent_id"),
                }
            )
        # state
        if a.get("state") != b.get("state"):
            diffs["state"] = {"from": a.get("state"), "to": b.get("state")}
        # metadata: diff EVERY key (added/removed/changed). The
        # `sensitivity_field` parameter is used downstream only to
        # detect ladder escalations; it does NOT limit which
        # metadata diffs contribute to the "changed" bucket.
        a_meta = a.get("metadata") or {}
        b_meta = b.get("metadata") or {}
        if isinstance(a_meta, str):
            a_meta = _try_json(a_meta)
        if isinstance(b_meta, str):
            b_meta = _try_json(b_meta)
        all_keys = set(a_meta.keys()) | set(b_meta.keys())
        for k in all_keys:
            av = a_meta.get(k)
            bv = b_meta.get(k)
            if av != bv:
                diffs[k] = {"from": av, "to": bv}
        if diffs:
            changed.append(
                {
                    "node_id": nid,
                    "asset_type": a.get("asset_type"),
                    "value": b.get("value"),
                    "diffs": diffs,
                }
            )

    # Summary by asset_type
    by_type: dict[str, dict[str, int]] = {}
    for bucket_name, items in (("added", added), ("removed", removed), ("changed", changed)):
        for it in items:
            t = it.get("asset_type") or "unknown"
            by_type.setdefault(t, {"added": 0, "removed": 0, "changed": 0})[bucket_name] += 1

    # Sensitivity escalations: 'to' is higher than 'from' in the risk ladder.
    # The diffs key for a metadata field is the bare key name (e.g. "risk",
    # "sensitivity", "http_only"). The `sensitivity_field` parameter
    # selects which key to look at for ladder escalation.
    RISK_LADDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    escalations = [
        c for c in changed
        if sensitivity_field in c.get("diffs", {})
        and RISK_LADDER.get(c["diffs"][sensitivity_field].get("to", ""), 0)
        > RISK_LADDER.get(c["diffs"][sensitivity_field].get("from", ""), 0)
    ]

    return json.dumps(
        {
            "snapshot_a": str(pa),
            "snapshot_b": str(pb),
            "summary": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
                "moved": len(moved),
                "sensitivity_escalations": len(escalations),
                "by_type": by_type,
            },
            "added": added,
            "removed": removed,
            "changed": changed,
            "moved": moved,
            "sensitivity_escalations": escalations,
        },
        ensure_ascii=False,
        default=str,
    )


def _try_json(s: str) -> dict[str, Any]:
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


# ── 2. recon_list_snapshots ──────────────────────────


@tool(
    name="recon_list_snapshots",
    description=(
        "List all AssetTree JSON snapshots under the state dir, optionally "
        "filtered by root_domain substring. Returns tree_id, snapshot_id "
        "(derived from filename: <tree_id>--<iso_ts>), file mtime, size, "
        "and stats summary (node_count by type). Use this to pick the two "
        "snapshots to feed into `recon_diff_snapshots` for time-dimension "
        "deltas (Batch 5)."
    ),
    params={
        "root_domain_substr": {
            "type": "string",
            "description": "Filter snapshots whose tree_id contains this substring.",
        },
        "limit": {
            "type": "integer",
            "default": 50,
            "description": "Cap the number of returned snapshots (newest first).",
        },
    },
)
async def recon_list_snapshots(
    root_domain_substr: str | None = None,
    limit: int = 50,
) -> str:
    files = _list_snapshot_files(root_domain_substr)
    # Sort by mtime descending (newest first)
    files_with_mtime = [(f, f.stat().st_mtime) for f in files if f.exists()]
    files_with_mtime.sort(key=lambda x: -x[1])

    snapshots: list[dict[str, Any]] = []
    for f, mtime in files_with_mtime[:limit]:
        # Filename: <tree_id>.json or <tree_id>--<iso_ts>.json
        stem = f.stem
        if "--" in stem:
            tree_id, snap_ts = stem.rsplit("--", 1)
            snapshot_id = stem
        else:
            tree_id = stem
            snap_ts = None
            snapshot_id = stem
        # Load stats summary
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            doc = {}
        nodes = doc.get("nodes") or {}
        by_type_count: dict[str, int] = {}
        for n in nodes.values():
            t = n.get("asset_type", "unknown")
            by_type_count[t] = by_type_count.get(t, 0) + 1
        snapshots.append(
            {
                "snapshot_id": snapshot_id,
                "tree_id": tree_id,
                "snapshot_ts": snap_ts,
                "file_path": str(f),
                "file_mtime_iso": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                "file_size_bytes": f.stat().st_size,
                "node_count": len(nodes),
                "node_count_by_type": by_type_count,
            }
        )

    return json.dumps(
        {
            "root_domain_substr": root_domain_substr,
            "snapshot_count": len(snapshots),
            "total_matching": len(files_with_mtime),
            "snapshots": snapshots,
        },
        ensure_ascii=False,
    )
