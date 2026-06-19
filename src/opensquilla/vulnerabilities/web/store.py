"""VulnerabilityStore — 漏洞模块的 DB 读取层。

与 asset_tree.web.store.TreeStore 风格一致: 走同一 backend (复用
``opensquilla.asset_tree.db.get_default_backend()``), 失败时
回退 JSON (当前 vulnerabilities 没有 JSON snapshot, 故读失败
直接 raise 503, 不静默返回空列表 — 避免 2026-06-17 51ifind.com
"tree 看起来空" 那种 bug)。
"""
from __future__ import annotations

from typing import Any

from opensquilla.asset_tree.db import get_default_backend


class VulnStore:
    """DB-backed vulnerability read API.

    All methods are async; they proxy to the shared ``AssetTreeBackend``
    instance so vulnerability reads share a connection pool with the
    asset-tree reads.
    """

    def __init__(self) -> None:
        self._db_available: bool | None = None

    @property
    def db_available(self) -> bool:
        if self._db_available is None:
            try:
                get_default_backend()
                self._db_available = True
            except Exception:
                self._db_available = False
        return self._db_available

    def db_status_payload(self) -> dict[str, Any]:
        if self.db_available:
            return {"mode": "db", "hint": None}
        return {
            "mode": "db_unavailable",
            "hint": (
                "ASSET_TREE_DB_URL is unset. Vulnerability reads are "
                "unavailable. Set ASSET_TREE_DB_URL to a "
                "'mysql+aiomysql://...' string to enable."
            ),
        }

    # ── Public read API ──────────────────────────────────────

    async def list_vulnerabilities(
        self,
        *,
        tree_id: str | None = None,
        attack_path_id: str | None = None,
        node_id: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        be = get_default_backend()
        if node_id is not None and tree_id is None:
            raise ValueError("node_id requires tree_id")
        if tree_id is None:
            return await self._list_all_vulns(limit=limit)
        vulns = await be.list_vulnerabilities(
            tree_id=tree_id,
            attack_path_id=attack_path_id,
            leaf_node_id=node_id,
            severity=severity,
            limit=limit,
        )
        if node_id is not None and attack_path_id is None:
            # node_id 过滤后还想看祖先节点关联的所有漏洞, 走 vuln_node_vulns
            ids = await be.list_node_vulnerability_ids(tree_id, node_id)
            id_set = set(ids)
            vulns = [v for v in vulns if v["id"] in id_set]
        return vulns

    async def _list_all_vulns(self, *, limit: int) -> list[dict[str, Any]]:
        """列出所有漏洞 (跨树), 简单 limit cap, 不可分页 (UI 列表够用)."""
        from sqlalchemy import text
        from opensquilla.asset_tree.db.schema import vulnerabilities as _v
        from opensquilla.asset_tree.db.schema import _metadata  # noqa
        be = get_default_backend()
        async with be._engine.begin() as conn:
            rows = (await conn.execute(text(
                "SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT :lim"
            ), {"lim": limit})).all()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r._mapping)
            out.append(d)
        return out

    async def get_vulnerability(self, vuln_id: str) -> dict[str, Any] | None:
        be = get_default_backend()
        return await be.get_vulnerability(vuln_id)

    async def list_node_vulnerability_ids(
        self, tree_id: str, node_id: str,
    ) -> list[str]:
        be = get_default_backend()
        return await be.list_node_vulnerability_ids(tree_id, node_id)

    async def get_attack_path(self, path_id: str) -> dict[str, Any] | None:
        be = get_default_backend()
        return await be.get_attack_path(path_id)

    async def list_attack_paths(
        self, tree_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        be = get_default_backend()
        if tree_id is None:
            # 跨树; backend 没提供, 用 raw query
            from sqlalchemy import text
            async with be._engine.begin() as conn:
                rows = (await conn.execute(text(
                    "SELECT * FROM vuln_attack_paths ORDER BY created_at DESC LIMIT 500"
                ))).all()
            out = [dict(r._mapping) for r in rows]
            if status is not None:
                out = [r for r in out if r.get("status") == status]
            return out
        return await be.list_attack_paths(tree_id, status=status)
