"""AttackPathStore — read API for the attack-paths dashboard (v6, 2026-06-19).

Wraps the shared ``AssetTreeBackend`` so the dashboard reads from the
same connection pool as the asset-tree and vulnerabilities modules.

The dashboard needs three slices:

  1. **List of trees** — populates the tree-selector dropdown.
  2. **Per-tree path list** — every L0..L7 path, filterable by status.
  3. **Per-path detail bundle** — the path row + the vulnerabilities
     it produced + the nodes it re-fed (反哺) — all in one call so the
     detail page renders with a single round-trip.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from opensquilla.asset_tree.db import get_default_backend
from opensquilla.vulnerabilities.web.store import VulnStore


class AttackPathStore:
    """Read-side API for the attack-paths dashboard."""

    def __init__(self) -> None:
        self._vulns = VulnStore()

    @property
    def db_available(self) -> bool:
        try:
            get_default_backend()
            return True
        except Exception:
            return False

    def db_status_payload(self) -> dict[str, Any]:
        if self.db_available:
            return {"mode": "db", "hint": None}
        return {
            "mode": "db_unavailable",
            "hint": (
                "ASSET_TREE_DB_URL is unset. Attack-path reads are "
                "unavailable until the asset-tree MySQL is configured."
            ),
        }

    # ── Trees ──────────────────────────────────────────────

    async def list_trees(self) -> list[dict[str, Any]]:
        """Lightweight list for the tree-selector dropdown.

        Reuses :class:`TreeStore` (asset_tree.web.store) so the
        dashboard sees the same trees the user sees in the asset-tree
        module — single source of truth.
        """
        try:
            from opensquilla.asset_tree.web.store import TreeStore
            return await TreeStore().list_trees()
        except Exception:
            return []

    # ── Paths ──────────────────────────────────────────────

    async def list_paths(
        self,
        tree_id: str,
        *,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List attack paths for one tree, optionally filtered by status."""
        return await self._vulns.list_attack_paths(tree_id=tree_id, status=status)

    async def get_path(self, path_id: str) -> dict[str, Any] | None:
        return await self._vulns.get_attack_path(path_id)

    async def path_summary(self, tree_id: str) -> dict[str, Any]:
        """Return KPI aggregates for the dashboard header.

        Counts: total, by status, by leaf_type, total vulns produced.
        """
        paths = await self._vulns.list_attack_paths(tree_id=tree_id)
        status_hist: dict[str, int] = {}
        leaf_type_hist: dict[str, int] = {}
        for p in paths:
            status_hist[p.get("status", "unknown")] = (
                status_hist.get(p.get("status", "unknown"), 0) + 1
            )
            leaf_type_hist[p.get("leaf_type", "unknown")] = (
                leaf_type_hist.get(p.get("leaf_type", "unknown"), 0) + 1
            )
        # Vuln total — sum per-path vuln_count column (cheap) instead of
        # recounting via JOIN.  The column is updated by the orchestrator
        # on every status transition so it stays consistent.
        total_vulns = sum(int(p.get("vuln_count") or 0) for p in paths)
        return {
            "tree_id": tree_id,
            "path_total": len(paths),
            "by_status": status_hist,
            "by_leaf_type": leaf_type_hist,
            "vuln_total": total_vulns,
        }

    # ── Per-path detail bundle ─────────────────────────────

    async def path_detail_bundle(
        self, path_id: str,
    ) -> dict[str, Any] | None:
        """Build the full payload for the path detail page in one call.

        Returns::

            {
              "path":          <row from vuln_attack_paths>,
              "vulnerabilities": [...],      # all vulns for this path
              "node_feeds":    [             # 反哺: (node_id, vuln_ids[])
                  {"node_id": "...", "vuln_ids": [...]},
                  ...
              ],
              "edges":         [...]         # edge_chain_json.edges[] (parsed)
            }

        Returns ``None`` if the path itself is missing.
        """
        path = await self._vulns.get_attack_path(path_id)
        if path is None:
            return None
        vulns = await self._vulns.list_vulnerabilities(
            tree_id=path.get("tree_id"),
            attack_path_id=path_id,
        )
        node_feeds = self._aggregate_node_feeds(vulns)
        ecj = path.get("edge_chain_json") or {}
        if isinstance(ecj, str):
            import json
            try:
                ecj = json.loads(ecj)
            except Exception:
                ecj = {}
        edges = (ecj or {}).get("edges", []) if isinstance(ecj, dict) else []
        return {
            "path": path,
            "vulnerabilities": vulns,
            "node_feeds": node_feeds,
            "edges": edges,
        }

    def _aggregate_node_feeds(
        self, vulns: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Bucket vulns by ``node_id`` so the UI can show the
        re-feed pattern (which leaf/ancestor nodes got vulns)."""
        bucket: dict[str, list[str]] = {}
        for v in vulns:
            nid = v.get("leaf_node_id")
            if not nid:
                continue
            bucket.setdefault(nid, []).append(v.get("id"))
        # Stable order: by node_id alphabetical
        return [
            {"node_id": nid, "vuln_ids": ids}
            for nid, ids in sorted(bucket.items())
        ]

    async def list_trees_with_path_counts(self) -> list[dict[str, Any]]:
        """Annotate each tree with its attack-path count for the
        tree-selector dropdown.  Cheap because we read the small
        ``vuln_attack_paths`` table and bucket by tree_id."""
        try:
            from sqlalchemy import text
            be = get_default_backend()
            async with be._engine.begin() as conn:  # type: ignore[attr-defined]
                rows = (await conn.execute(text(
                    "SELECT tree_id, status, COUNT(*) AS n "
                    "FROM vuln_attack_paths GROUP BY tree_id, status"
                ))).all()
        except Exception:
            return []
        per_tree: dict[str, dict[str, int]] = {}
        for r in rows:
            d = dict(r._mapping)
            per_tree.setdefault(d["tree_id"], {"total": 0, "by_status": {}})
            per_tree[d["tree_id"]]["total"] += int(d["n"])
            per_tree[d["tree_id"]]["by_status"][d["status"]] = (
                per_tree[d["tree_id"]]["by_status"].get(d["status"], 0)
                + int(d["n"])
            )
        out: list[dict[str, Any]] = []
        for tid, info in sorted(per_tree.items()):
            out.append({
                "tree_id": tid,
                "path_count": info["total"],
                "by_status": info["by_status"],
            })
        return out
