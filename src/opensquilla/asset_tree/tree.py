"""AssetTree — 树状资产记忆的核心引擎。

提供节点 CRUD、状态流转、路径查询、去重、统计和序列化能力。
与 hack-deep 波次系统解耦，可在测试中独立使用。

典型使用::

    tree = AssetTree("example.com")
    sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com")
    ip  = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
    port = tree.add_node(AssetType.PORT, "443", parent_id=ip)
    svc = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port)
    tree.update_state(svc, AssetState.DISCOVERED)
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from opensquilla.asset_tree.models import (
    AssetNode,
    AssetNodeRef,
    AssetPath,
    AssetState,
    AssetType,
    validate_parent_child,
)


class AssetTree:
    """树状资产记忆的核心引擎。

    内部维护四个索引以支持高效查询:
      - ``_nodes``      : id → AssetNode
      - ``_edges``      : parent_id → [child_id, ...]
      - ``_by_type``    : AssetType → [node_id, ...]
      - ``_value_index``: (AssetType, value) → node_id  (去重用)
    """

    def __init__(
        self,
        root_domain: str,
        *,
        backend: Any | None = None,
        tree_id: str | None = None,
    ) -> None:
        """Build an AssetTree.

        Args:
            root_domain: The root domain (e.g. "example.com").
            backend: Optional ``AssetTreeBackend``. When provided, every
                mutation is persisted to the backend after the in-memory
                indexes are updated. When None, the tree is purely
                in-memory (test mode without DB).
            tree_id: Required when backend is set — the DB primary key for
                this tree. Ignored when backend is None.
        """
        self._nodes: dict[str, AssetNode] = {}
        self._edges: dict[str, list[str]] = {}
        self._by_type: dict[AssetType, list[str]] = {}
        # Root-layer dedup only. Non-root duplicates across parents are LEGITIMATE
        # (e.g. shared IPs, shared ports); they are deduped by parent walk instead.
        self._value_index: dict[tuple[AssetType, str], str] = {}
        self._lock = threading.RLock()
        # Use getattr-tolerant attributes so legacy trees loaded from
        # JSON (without these set) don't AttributeError on first mutation.
        self._backend = backend
        self._tree_id = tree_id
        if backend is not None and tree_id is None:
            raise ValueError("tree_id is required when backend is set")
        self.root_id: Optional[str] = None
        self.root_domain: str = root_domain

        # 创建根节点（直接调用锁内方法，避开 add_node 的锁保护，因为 _lock 刚刚初始化）
        self.root_id = self._add_node_locked(
            asset_type=AssetType.ROOT_DOMAIN,
            value=root_domain,
        )

    # ── 节点 CRUD ──────────────────────────────────────

    # v4 (2026-06-17) verification-required types — these nodes claim a
    # real-time property of a network endpoint ("port X is open",
    # "URL Y returns 200 with a real page") that must be verified at
    # add_node time. The verification object is the result envelope
    # from recon_url_validate (for URL) or recon_port_verify (for
    # PORT / SERVICE / ENDPOINT). Without it the node is rejected.
    #
    # This closes the false-positive bug from 51ifind.com run
    # 2026-06-17 where 84 naabu ports were reported but only 14 made
    # it into the tree, and 13 reported URLs that turned out to be
    # error pages / timeouts were still marked as discovered.
    _VERIFICATION_REQUIRED_TYPES: frozenset[str] = frozenset({
        "port", "service", "url", "endpoint",
    })

    def add_node(
        self,
        asset_type: AssetType,
        value: str,
        parent_id: Optional[str] = None,
        source_wave: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        *,
        id_override: Optional[str] = None,
        verification: Optional[dict[str, Any]] = None,
        allow_unverified: bool = False,
    ) -> str:
        """添加节点，返回 node_id。

        去重策略: 共享单例类型 (singleton) 全局按 (asset_type, value) 去重;
        非单例类型 (cookie/header/parameter/secret 等) 同父去重。

        v4 (2026-06-17) verification contract: PORT / SERVICE / URL /
        ENDPOINT 节点**必须**携带 ``verification`` 参数 (recon_port_verify
        或 recon_url_validate 的 result envelope), 且 ``verification.verified``
        必须为 True。缺失或 verified=False 会被拒绝 (raise ValueError),
        除非显式传 ``allow_unverified=True`` (用于反序列化历史 tree /
        测试 fixture, **生产路径不允许**)。

        Args:
            asset_type: 节点类型。
            value: 节点值。
            parent_id: 父节点 ID（根节点为 None）。
            source_wave: 发现此节点的波次标识。
            metadata: 附加元数据。
            id_override: 仅用于反序列化，覆盖自动生成的 id。
            verification: 探测结果 envelope, 含 verified/reason/probe/verified_at。
                Required for PORT/SERVICE/URL/ENDPOINT.
            allow_unverified: 跳过 verification 检查 (反序列化/测试用).

        Returns:
            节点 ID（新建或已有）。
        """
        with self._lock:
            return self._add_node_locked(
                asset_type=asset_type,
                value=value,
                parent_id=parent_id,
                source_wave=source_wave,
                metadata=metadata,
                id_override=id_override,
                verification=verification,
                allow_unverified=allow_unverified,
            )

    # v4 (2026-06-17) shared-singleton asset types — these are nodes
    # that have a global identity (one IP per IP, one bucket per bucket)
    # and must dedup globally across the whole tree, regardless of which
    # parent tried to create them. Per-parent state types (Cookie/Header/
    # Parameter/Secret/AuthSurface/StaticAsset) are NOT in this set:
    # a Cookie set by URL A and URL B is 2 distinct Cookie nodes.
    _SHARED_SINGLETON_TYPES: frozenset[str] = frozenset({
        "root_domain", "sub_domain", "ip", "port", "service",
        "url", "endpoint", "api_schema", "component",
        "storage", "storage_object",
    })

    def _add_node_locked(
        self,
        asset_type: AssetType,
        value: str,
        parent_id: Optional[str] = None,
        source_wave: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        *,
        id_override: Optional[str] = None,
        verification: Optional[dict[str, Any]] = None,
        allow_unverified: bool = False,
    ) -> str:
        """`add_node` 的锁内实现。`__init__` 在持有锁之前不能调用此方法。

        v4 (2026-06-17) dedup strategy:
          - Shared-singleton types: global dedup by (asset_type, value).
            One IP 121.52.252.15 exists exactly once in the tree.
          - Per-parent state types: parent-walk dedup. A Cookie under
            URL A and a Cookie under URL B are 2 distinct nodes.

        v4 (2026-06-17) verification contract:
          - PORT / SERVICE / URL / ENDPOINT require ``verification.verified==True``.
          - Missing or unverified → ValueError (unless allow_unverified=True).
          - On dedup (existing node), verification is still applied: if
            the existing node has no prior verification, the new
            verification upgrades it; if the existing node was previously
            verified, the new verification overwrites verification fields
            (for re-checks).
        """
        is_singleton = asset_type.value in self._SHARED_SINGLETON_TYPES

        if is_singleton:
            # Global dedup: same (asset_type, value) anywhere = same node.
            existing_id = self._value_index.get((asset_type, value))
            if existing_id and existing_id in self._nodes:
                node = self._nodes[existing_id]
                node.last_seen = datetime.now(timezone.utc)
                if source_wave and not node.source_wave:
                    node.source_wave = source_wave
                if metadata:
                    node.metadata.update(metadata)
                # v4 verification: re-record on dedup hit (re-check)
                if verification and verification.get("verified"):
                    node.metadata["verification"] = verification
                # v4.5 (2026-06-18) resurrection: if a previously
                # ABANDONED node is rediscovered, flip it back to
                # DISCOVERED. first_seen is preserved (historical
                # record); only last_seen + state change. Soft-delete
                # semantics: we never delete, only mark.
                if node.state == AssetState.ABANDONED:
                    node.state = AssetState.DISCOVERED
                return existing_id
        else:
            # Parent-walk dedup: only check siblings under same parent.
            for child_id in self._edges.get(parent_id or "", []):
                child = self._nodes[child_id]
                if child.asset_type == asset_type and child.value == value:
                    child.last_seen = datetime.now(timezone.utc)
                    if source_wave and not child.source_wave:
                        child.source_wave = source_wave
                    if metadata:
                        child.metadata.update(metadata)
                    # v4 verification: re-record on dedup hit
                    if verification and verification.get("verified"):
                        child.metadata["verification"] = verification
                    # v4.5 (2026-06-18) resurrection: same as singleton
                    # path — flip ABANDONED -> DISCOVERED on rediscovery.
                    if child.state == AssetState.ABANDONED:
                        child.state = AssetState.DISCOVERED
                    return child_id

        # v4 (2026-06-17) verification check: PORT / SERVICE / URL / ENDPOINT
        # must carry a verification envelope with verified=True. Without
        # this gate, specialist-reported nodes (e.g. naabu ports,
        # endpoint-crawler URLs) get into the tree as "discovered"
        # regardless of whether they're actually reachable. The 51ifind.com
        # run on 2026-06-17 had 14/84 ports and 13 URL nodes that
        # turned out to be unreachable / error pages — all marked
        # discovered, polluting the tree.
        if (
            asset_type.value in self._VERIFICATION_REQUIRED_TYPES
            and not allow_unverified
        ):
            if verification is None:
                raise ValueError(
                    f"asset_type={asset_type.value} requires verification "
                    f"envelope (recon_url_validate for url/endpoint, "
                    f"recon_port_verify for port/service). "
                    f"Got no verification for value={value!r}. "
                    f"Pass allow_unverified=True only for "
                    f"deserialization / test fixtures."
                )
            if not isinstance(verification, dict):
                raise ValueError(
                    f"verification must be a dict, got {type(verification).__name__}"
                )
            if not verification.get("verified"):
                reason = verification.get("reason") or "unknown"
                raise ValueError(
                    f"asset_type={asset_type.value} rejected: "
                    f"verification.verified is not True "
                    f"(reason={reason!r}, value={value!r}). "
                    f"Reachable verification is required for "
                    f"port/service/url/endpoint ingestion."
                )

        # 校验父子关系
        if parent_id is not None:
            parent = self._nodes.get(parent_id)
            if parent is None:
                raise ValueError(f"Parent node not found: {parent_id}")
            validate_parent_child(parent.asset_type, asset_type)

        node = AssetNode(
            id=id_override or AssetNode.__pydantic_fields__["id"].default_factory(),
            asset_type=asset_type,
            value=value,
            parent_id=parent_id,
            source_wave=source_wave,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            metadata=metadata or {},
        )

        # v4.5 (2026-06-18): attach verification to metadata so the
        # node record carries the probe envelope for downstream
        # consumers. v4 used attack-priority-v1 evidence (since
        # removed — see tree-finalizer rename); v4.5 consumers are
        # tree-finalizer's liveness recheck (filters by verified=True
        # before HEAD probe) and hack-deep W2 priority ranking
        # (verified=True URLs are higher confidence).
        if verification and verification.get("verified"):
            if node.metadata is None:
                node.metadata = {}
            node.metadata["verification"] = verification

        # 注册到所有索引
        self._nodes[node.id] = node
        # v4 (2026-06-17): shared-singleton types write to global
        # _value_index regardless of parent (global dedup). Per-parent
        # state types do NOT write _value_index; they dedup by parent walk.
        if asset_type.value in self._SHARED_SINGLETON_TYPES:
            self._value_index[(asset_type, value)] = node.id

        if parent_id is not None:
            self._nodes[parent_id].children_ids.append(node.id)
            self._edges.setdefault(parent_id, []).append(node.id)

        self._by_type.setdefault(asset_type, []).append(node.id)

        # Backend persistence (Phase 4). Fire-and-forget when no loop is
        # running; in async contexts the caller wraps the tree in an
        # event loop. To avoid blocking sync tests, only call when a loop
        # is active.
        if getattr(self, "_backend", None) is not None:
            self._persist_node(node)

        return node.id

    def _persist_node(self, node: AssetNode) -> None:
        """Optional auto-persist hook — DISABLED in Phase 4.

        The tools' ``asset_tree_add_nodes`` already does an explicit
        awaited bulk write via ``backend.add_nodes_bulk``. Firing a
        per-node fire-and-forget here races with the bulk insert
        (FK constraints against not-yet-committed parents). Keep the
        method as a hook for future callers that need per-node
        incremental persistence, but do nothing by default.
        """
        return None

    def _material_path_for(self, node: AssetNode) -> str:
        """Build the slash-separated id chain for the node."""
        if node.parent_id is None:
            return node.id
        parent = self._nodes.get(node.parent_id)
        if parent is None:
            return node.id
        return self._material_path_for(parent) + "/" + node.id

    def get_node(self, node_id: str) -> Optional[AssetNode]:
        """按 ID 获取节点。"""
        with self._lock:
            return self._nodes.get(node_id)

    def update_state(self, node_id: str, new_state: AssetState) -> None:
        """更新节点探测状态。"""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                raise ValueError(f"Node not found: {node_id}")
            old_state = node.state
            node.state = new_state
            node.last_seen = datetime.now(timezone.utc)

        # Persist state change + record audit log entry (Phase 4)
        if getattr(self, "_backend", None) is not None and getattr(self, "_tree_id", None) is not None:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return
            asyncio.ensure_future(self._backend.update_node_state(
                node_id=node_id, tree_id=self._tree_id,
                new_state=new_state.value,
            ))
            asyncio.ensure_future(self._backend.add_state_transition(
                tree_id=self._tree_id, node_id=node_id,
                from_state=old_state.value, to_state=new_state.value,
            ))

    def update_metadata(self, node_id: str, **fields: Any) -> None:
        """更新节点的 metadata 字段（merge 语义）。"""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                raise ValueError(f"Node not found: {node_id}")
            node.metadata.update(fields)
            node.last_seen = datetime.now(timezone.utc)

    def add_evidence_ref(self, node_id: str, handoff_id: str) -> None:
        """为节点关联一个 evidence handoff_id（去重）。"""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                raise ValueError(f"Node not found: {node_id}")
            if handoff_id not in node.evidence_refs:
                node.evidence_refs.append(handoff_id)

    def assign_wave(self, node_id: str, wave: str) -> None:
        """标记节点正在被哪个波次处理。"""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                raise ValueError(f"Node not found: {node_id}")
            node.assigned_wave = wave

    def remove_subtree(self, node_id: str) -> None:
        """删除以 node_id 为根的子树（含该节点）。

        清理所有内部索引和父节点的 children_ids 列表。
        不允许删除根节点。
        """
        with self._lock:
            if node_id == self.root_id:
                raise ValueError("Cannot delete root node")

            # 收集待删除节点（BFS）
            to_remove: list[str] = []
            queue = [node_id]
            while queue:
                current = queue.pop()
                to_remove.append(current)
                queue.extend(self._edges.get(current, []))

            to_remove_set = set(to_remove)

            # 找到被删节点的父节点
            target_node = self._nodes.get(node_id)
            parent_id = target_node.parent_id if target_node else None
            if not parent_id:
                # 尝试从 edges 反查
                for pid, children in self._edges.items():
                    if node_id in children:
                        parent_id = pid
                        break

            # 从所有索引中移除
            for nid in to_remove:
                node = self._nodes.pop(nid, None)
                if node is None:
                    continue

                # 只为根层节点 pop _value_index；非根层节点本就不在索引中
                if node.parent_id is None:
                    self._value_index.pop((node.asset_type, node.value), None)

                # 移除 type index
                type_list = self._by_type.get(node.asset_type, [])
                if nid in type_list:
                    type_list.remove(nid)

                # 移除 edges (parent → child)
                self._edges.pop(nid, None)

            # 从父节点的 children 列表和 edges 中移除
            if parent_id and parent_id in self._nodes:
                self._nodes[parent_id].children_ids = [
                    c for c in self._nodes[parent_id].children_ids if c not in to_remove_set
                ]
            if parent_id and parent_id in self._edges:
                self._edges[parent_id] = [
                    c for c in self._edges[parent_id] if c not in to_remove_set
                ]

        # ── 关系查询 ──────────────────────────────────────

    def get_children(self, node_id: str) -> list[AssetNode]:
        """获取节点的直接子节点列表。"""
        return [self._nodes[cid] for cid in self._edges.get(node_id, []) if cid in self._nodes]

    def get_parent(self, node_id: str) -> Optional[AssetNode]:
        """获取节点的父节点。"""
        node = self._nodes.get(node_id)
        if node and node.parent_id:
            return self._nodes.get(node.parent_id)
        return None

    def get_path_to_root(self, node_id: str) -> AssetPath:
        """回溯从当前节点到根的完整路径。"""
        parts: list[AssetNodeRef] = []
        current: Optional[str] = node_id
        while current and current in self._nodes:
            node = self._nodes[current]
            parts.append(node.to_ref())
            current = node.parent_id
        parts.reverse()
        return AssetPath(parts=parts)

    def get_siblings(self, node_id: str) -> list[AssetNode]:
        """获取节点的兄弟节点（同父，不含自身）。"""
        node = self._nodes.get(node_id)
        if not node or not node.parent_id:
            return []
        return [self._nodes[cid] for cid in self._edges.get(node.parent_id, []) if cid != node_id and cid in self._nodes]

    def get_all_descendants(self, node_id: str) -> list[AssetNode]:
        """获取节点的所有后代（BFS 展开）。"""
        result: list[AssetNode] = []
        queue = list(self._edges.get(node_id, []))
        while queue:
            cid = queue.pop(0)
            if cid in self._nodes:
                result.append(self._nodes[cid])
                queue.extend(self._edges.get(cid, []))
        return result

    def find_shared_ips(self) -> dict[str, list[str]]:
        """发现被多个子域名共享的 IP — 返回 {ip_value: [sub_domain_id, ...]}。"""
        ip_to_parents: dict[str, list[str]] = {}
        for node in self._nodes.values():
            if node.asset_type == AssetType.IP and node.parent_id:
                parent = self._nodes.get(node.parent_id)
                if parent and parent.asset_type == AssetType.SUB_DOMAIN:
                    ip_to_parents.setdefault(node.value, []).append(node.parent_id)
        return {ip: parents for ip, parents in ip_to_parents.items() if len(parents) > 1}

    def find_shared_components(self) -> dict[str, list[str]]:
        """发现被多个 SERVICE / URL 复用的组件（product+version 一致）。

        返回 ``{component_value: [parent_id, ...]}``，仅保留 2+ 父节点共享的项。
        用于波次选择：共享组件一旦被攻破，影响面更大、优先级更高。
        """
        comp_to_parents: dict[str, list[str]] = {}
        for node in self._nodes.values():
            if node.asset_type != AssetType.COMPONENT or not node.parent_id:
                continue
            parent = self._nodes.get(node.parent_id)
            if parent is None:
                continue
            if parent.asset_type not in {AssetType.SERVICE, AssetType.URL}:
                continue
            comp_to_parents.setdefault(node.value, []).append(node.parent_id)
        return {c: ps for c, ps in comp_to_parents.items() if len(ps) > 1}

    def find_leaked_secrets(self, *, validated_only: bool = False) -> list[AssetNode]:
        """发现所有 ``SECRET`` 节点。

        Args:
            validated_only: 若为 True，仅返回 ``metadata.validated is True`` 的节点。
                默认 False，返回全部以便 triage。
        """
        results: list[AssetNode] = []
        for node in self._nodes.values():
            if node.asset_type != AssetType.SECRET:
                continue
            if validated_only and not node.metadata.get("validated"):
                continue
            results.append(node)
        return results

    def find_injection_vectors(
        self,
        *,
        category: Optional[str] = None,
        verified_only: bool = False,
    ) -> list[AssetNode]:
        """发现 ``INJECTION_VECTOR`` 节点。

        Args:
            category: 可选过滤，如 ``"sqli"`` / ``"ssrf"`` / ``"xss"`` /
                ``"path_traversal"``。匹配 ``metadata.category``。
            verified_only: 仅返回 ``metadata.verified is True`` 的节点。
        """
        results: list[AssetNode] = []
        for node in self._nodes.values():
            if node.asset_type != AssetType.INJECTION_VECTOR:
                continue
            if category is not None and node.metadata.get("category") != category:
                continue
            if verified_only and not node.metadata.get("verified"):
                continue
            results.append(node)
        return results

    # ── 状态查询 ──────────────────────────────────────

    def nodes_by_state(self, state: AssetState) -> list[AssetNode]:
        """获取特定状态的所有节点。"""
        return [n for n in self._nodes.values() if n.state == state]

    def nodes_by_type(self, asset_type: AssetType) -> list[AssetNode]:
        """获取特定类型的所有节点。"""
        return [self._nodes[nid] for nid in self._by_type.get(asset_type, []) if nid in self._nodes]

    def unseen_leaves(self) -> list[AssetNode]:
        """所有未探测的叶节点 — 下一波次的目标候选。"""
        return [n for n in self._nodes.values() if n.state == AssetState.UNSEEN and n.is_leaf()]

    def frontier(self) -> list[AssetNode]:
        """前沿节点 — 已发现但未深入（DISCOVERED 状态）。"""
        return self.nodes_by_state(AssetState.DISCOVERED)

    def find_node(self, asset_type: AssetType, value: str) -> Optional[AssetNode]:
        """按类型+值查找节点。"""
        node_id = self._value_index.get((asset_type, value))
        return self._nodes.get(node_id) if node_id else None

    def find_nodes_by_value(self, value: str) -> list[AssetNode]:
        """按值模糊查找（所有类型）。"""
        return [n for n in self._nodes.values() if n.value == value]

    # ── 统计 ──────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """返回树的统计概览。"""
        type_counts = Counter(n.asset_type.value for n in self._nodes.values())
        state_counts = Counter(n.state.value for n in self._nodes.values())
        return {
            "total_nodes": len(self._nodes),
            "by_type": dict(type_counts),
            "by_state": dict(state_counts),
            "depth": self.max_depth(),
            "shared_ips": len(self.find_shared_ips()),
            "root_domain": self._nodes[self.root_id].value if self.root_id else None,
        }

    def max_depth(self) -> int:
        """树的最大深度。"""
        if not self.root_id:
            return 0
        depth = 0
        queue = [self.root_id]
        while queue:
            next_queue: list[str] = []
            for nid in queue:
                next_queue.extend(self._edges.get(nid, []))
            if next_queue:
                depth += 1
            queue = next_queue
        return depth

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes

    # ── 序列化 ──────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """持久化用序列化 — 完整信息。"""
        return {
            "root_id": self.root_id,
            "nodes": {nid: n.model_dump(mode="json") for nid, n in self._nodes.items()},
            "edges": dict(self._edges),
        }

    def to_json(self, **kwargs: Any) -> str:
        """序列化为 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, **kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetTree:
        """从序列化数据恢复 AssetTree。

        这是一个工厂方法: 它创建一个空的 AssetTree 实例并手动填充内部状态，
        而不是走正常的 add_node 流程（因为 add_node 会触发去重和校验）。
        """
        root_id = data.get("root_id")
        nodes_data = data.get("nodes", {})
        edges_data = data.get("edges", {})

        if root_id and root_id in nodes_data:
            root_domain = nodes_data[root_id]["value"]
        else:
            root_domain = "<unknown>"

        tree = cls.__new__(cls)
        tree._nodes = {}
        tree._edges = {}
        tree._by_type = {}
        tree._value_index = {}
        tree._lock = threading.RLock()
        tree.root_id = root_id
        tree.root_domain = root_domain  # 恢复 from_dict 上的 root_domain 属性

        # 恢复节点
        for nid, n_data in nodes_data.items():
            # ``to_dict`` 走 ``model_dump(mode="json")`` 把 ``metadata`` 序列化成
            # JSON 字符串。db-backed ``AssetTree`` 重建走的也是这条路,所以
            # ``from_dict`` 在 ``model_validate`` 之前先把 ``metadata`` 解码回
            # ``dict``,否则 Pydantic 会因为拿到 ``str`` 而校验失败。
            meta = n_data.get("metadata")
            if isinstance(meta, str):
                try:
                    decoded = json.loads(meta) if meta.strip() else {}
                    n_data["metadata"] = {} if decoded is None else decoded
                except (ValueError, TypeError):
                    n_data["metadata"] = {}
            node = AssetNode.model_validate(n_data)
            tree._nodes[nid] = node
            # 仅根层节点（parent_id is None）写入 _value_index，与 add_node 一致
            if node.parent_id is None:
                tree._value_index.setdefault((node.asset_type, node.value), nid)
            tree._by_type.setdefault(node.asset_type, []).append(nid)

        # 恢复边
        tree._edges = {k: list(v) for k, v in edges_data.items()}

        # 重建每个节点的 children_ids（to_dict 只写 _edges，序列化节点不带 children_ids 重建）
        for parent_id, child_ids in tree._edges.items():
            parent = tree._nodes.get(parent_id)
            if parent is None:
                continue
            existing = set(parent.children_ids)
            for cid in child_ids:
                if cid not in existing:
                    parent.children_ids.append(cid)
                    existing.add(cid)

        return tree

    @classmethod
    def from_json(cls, json_str: str) -> AssetTree:
        """从 JSON 字符串恢复。"""
        return cls.from_dict(json.loads(json_str))

    def snapshot(self) -> dict[str, Any]:
        """轻量快照 — 仅包含节点状态，用于 checkpoint 对比。"""
        return {
            nid: {"state": n.state.value, "assigned_wave": n.assigned_wave}
            for nid, n in self._nodes.items()
        }

    # ── 可视化 (调试用) ──────────────────────────────

    def render_tree(self) -> str:
        """渲染树的文本表示，用于调试和日志。"""
        if not self.root_id:
            return "<empty tree>"

        lines: list[str] = []
        root = self._nodes[self.root_id]
        lines.append(f"[ROOT] {root.value} ({root.state.value})")

        def _render(node_id: str, prefix: str, is_last: bool) -> None:
            children = self._edges.get(node_id, [])
            for i, cid in enumerate(children):
                if cid not in self._nodes:
                    continue
                child = self._nodes[cid]
                connector = "└── " if i == len(children) - 1 else "├── "
                state_mark = f" [{child.state.value}]" if child.state != AssetState.UNSEEN else ""
                lines.append(f"{prefix}{connector}[{child.asset_type.value}] {child.value}{state_mark}")
                extension = "    " if i == len(children) - 1 else "│   "
                _render(cid, prefix + extension, i == len(children) - 1)

        _render(self.root_id, "", True)
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"AssetTree(root={self._nodes[self.root_id].value if self.root_id else '?'}, nodes={len(self._nodes)})"
