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

import json
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

    def __init__(self, root_domain: str) -> None:
        self._nodes: dict[str, AssetNode] = {}
        self._edges: dict[str, list[str]] = {}
        self._by_type: dict[AssetType, list[str]] = {}
        self._value_index: dict[tuple[AssetType, str], str] = {}
        self.root_id: Optional[str] = None
        self.root_domain: str = root_domain

        # 创建根节点
        self.root_id = self.add_node(
            asset_type=AssetType.ROOT_DOMAIN,
            value=root_domain,
        )

    # ── 节点 CRUD ──────────────────────────────────────

    def add_node(
        self,
        asset_type: AssetType,
        value: str,
        parent_id: Optional[str] = None,
        source_wave: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        *,
        id_override: Optional[str] = None,
    ) -> str:
        """添加节点，返回 node_id。

        去重策略: 同类型 + 同值 + 同父 → 返回已有节点 id 并更新 ``last_seen``。

        Args:
            asset_type: 节点类型。
            value: 节点值。
            parent_id: 父节点 ID（根节点为 None）。
            source_wave: 发现此节点的波次标识。
            metadata: 附加元数据。
            id_override: 仅用于反序列化，覆盖自动生成的 id。

        Returns:
            节点 ID（新建或已有）。
        """
        # 去重: 同父 + 同类型 + 同值
        if parent_id:
            for child_id in self._edges.get(parent_id, []):
                child = self._nodes[child_id]
                if child.asset_type == asset_type and child.value == value:
                    child.last_seen = datetime.now(timezone.utc)
                    if source_wave and not child.source_wave:
                        child.source_wave = source_wave
                    if metadata:
                        child.metadata.update(metadata)
                    return child_id

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

        # 注册到所有索引
        self._nodes[node.id] = node
        self._value_index[(asset_type, value)] = node.id

        if parent_id is not None:
            self._nodes[parent_id].children_ids.append(node.id)
            self._edges.setdefault(parent_id, []).append(node.id)

        self._by_type.setdefault(asset_type, []).append(node.id)
        return node.id

    def get_node(self, node_id: str) -> Optional[AssetNode]:
        """按 ID 获取节点。"""
        return self._nodes.get(node_id)

    def update_state(self, node_id: str, new_state: AssetState) -> None:
        """更新节点探测状态。"""
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node not found: {node_id}")
        node.state = new_state
        node.last_seen = datetime.now(timezone.utc)

    def update_metadata(self, node_id: str, **fields: Any) -> None:
        """更新节点的 metadata 字段（merge 语义）。"""
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node not found: {node_id}")
        node.metadata.update(fields)
        node.last_seen = datetime.now(timezone.utc)

    def add_evidence_ref(self, node_id: str, handoff_id: str) -> None:
        """为节点关联一个 evidence handoff_id（去重）。"""
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node not found: {node_id}")
        if handoff_id not in node.evidence_refs:
            node.evidence_refs.append(handoff_id)

    def assign_wave(self, node_id: str, wave: str) -> None:
        """标记节点正在被哪个波次处理。"""
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node not found: {node_id}")
        node.assigned_wave = wave

    def remove_subtree(self, node_id: str) -> None:
        """删除以 node_id 为根的子树（含该节点）。

        清理所有内部索引和父节点的 children_ids 列表。
        不允许删除根节点。
        """
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

            # 移除 value index
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
        tree.root_id = root_id

        # 恢复节点
        for nid, n_data in nodes_data.items():
            node = AssetNode.model_validate(n_data)
            tree._nodes[nid] = node
            tree._value_index.setdefault((node.asset_type, node.value), nid)
            tree._by_type.setdefault(node.asset_type, []).append(nid)

        # 恢复边
        tree._edges = {k: list(v) for k, v in edges_data.items()}

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
