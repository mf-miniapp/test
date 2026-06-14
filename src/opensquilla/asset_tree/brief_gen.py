"""
Brief context generation for specialist subagents.

Generates structured context briefs containing only the relevant
subtree from the AssetTree, preventing context overflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import AssetNode, AssetType, AssetState
from .tree import AssetTree
from .routing import WaveRoute


@dataclass(frozen=True)
class BriefContext:
    """A context brief for a specialist subagent."""
    brief_id: str
    wave_id: str
    specialist: str
    target_node_id: str
    target_value: str
    target_type: str
    subtree_summary: str
    ancestor_path: list[str]  # root → parent chain
    sibling_nodes: list[str]  # other children of parent
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dict for JSON/template rendering."""
        return {
            "brief_id": self.brief_id,
            "wave_id": self.wave_id,
            "specialist": self.specialist,
            "target_node_id": self.target_node_id,
            "target_value": self.target_value,
            "target_type": self.target_type,
            "subtree_summary": self.subtree_summary,
            "ancestor_path": self.ancestor_path,
            "sibling_nodes": self.sibling_nodes,
            "metadata": self.metadata,
        }

    def to_text(self) -> str:
        """Human-readable text brief."""
        lines = [
            f"## Brief: {self.brief_id}",
            f"Wave: {self.wave_id}  Specialist: {self.specialist}",
            f"Target: {self.target_value} ({self.target_type})  NodeID: {self.target_node_id}",
            "",
            "### Ancestor Path",
        ]
        if self.ancestor_path:
            lines.append(" → ".join(self.ancestor_path))
        else:
            lines.append("(root)")

        if self.sibling_nodes:
            lines.append("")
            lines.append("### Sibling Nodes")
            for s in self.sibling_nodes:
                lines.append(f"  - {s}")

        lines.append("")
        lines.append("### Subtree Summary")
        lines.append(self.subtree_summary)

        if self.metadata:
            lines.append("")
            lines.append("### Metadata")
            for k, v in self.metadata.items():
                lines.append(f"  {k}: {v}")

        return "\n".join(lines)


class BriefGenerator:
    """Generates BriefContext objects from an AssetTree + routing decision."""

    def __init__(self, tree: AssetTree) -> None:
        self._tree = tree

    def generate(
        self,
        target_node: AssetNode,
        route: WaveRoute,
        *,
        max_siblings: int = 10,
        max_subtree_depth: int = 3,
        include_metadata: bool = True,
    ) -> BriefContext:
        """Generate a brief for dispatching a specialist to a target node.

        Args:
            target_node: The node the specialist will work on.
            route: The routing decision (wave, specialist, etc.).
            max_siblings: Maximum sibling nodes to include.
            max_subtree_depth: Maximum depth of subtree summary.
            include_metadata: Whether to include node metadata.
        """
        brief_id = f"{route.wave_id}.{route.specialist}.{target_node.id[:8]}"

        # Build ancestor path
        ancestor_path = self._build_ancestor_path(target_node)

        # Build sibling list
        sibling_nodes = self._build_sibling_list(target_node, max_siblings)

        # Build subtree summary
        subtree_summary = self._build_subtree_summary(
            target_node, max_subtree_depth
        )

        # Collect metadata
        meta: dict = {}
        if include_metadata:
            meta["assigned_wave"] = target_node.assigned_wave or ""
            meta["state"] = target_node.state.value
            meta["reason"] = route.reason
            if target_node.metadata:
                for k, v in target_node.metadata.items():
                    meta[k] = str(v)

        return BriefContext(
            brief_id=brief_id,
            wave_id=route.wave_id,
            specialist=route.specialist,
            target_node_id=target_node.id,
            target_value=target_node.value,
            target_type=target_node.asset_type.value,
            subtree_summary=subtree_summary,
            ancestor_path=ancestor_path,
            sibling_nodes=sibling_nodes,
            metadata=meta,
        )

    def _build_ancestor_path(self, node: AssetNode) -> list[str]:
        """Build root → node ancestor path (list of "type:value" strings)."""
        path: list[str] = []
        current: Optional[AssetNode] = node
        while current and current.id != self._tree.root_id:
            path.append(f"{current.asset_type.value}:{current.value}")
            parent_node = self._tree.get_parent(current.id)
            parent_id = parent_node.id if parent_node else None
            if parent_id is None:
                break
            current = self._tree.get_node(parent_id)
        # Add root
        root = self._tree.get_node(self._tree.root_id)
        if root:
            path.append(f"{root.asset_type.value}:{root.value}")
        path.reverse()
        return path

    def _build_sibling_list(self, node: AssetNode, max_siblings: int) -> list[str]:
        """List other children of the same parent."""
        parent_node = self._tree.get_parent(node.id)
        if parent_node is None:
            return []
        siblings: list[str] = []
        for child in self._tree.get_children(parent_node.id):
            if child.id == node.id:
                continue
            if len(siblings) < max_siblings:
                siblings.append(f"{child.asset_type.value}:{child.value}")
        return siblings

    def _build_subtree_summary(
        self, node: AssetNode, max_depth: int
    ) -> str:
        """Generate a text summary of the node's subtree."""
        lines: list[str] = []
        self._walk_subtree(node.id, 0, max_depth, lines)
        return "\n".join(lines) if lines else "(no children)"

    def _walk_subtree(
        self,
        node_id: str,
        depth: int,
        max_depth: int,
        lines: list[str],
    ) -> None:
        if depth >= max_depth:
            return
        children = self._tree.get_children(node_id)
        for child in children:
            indent = "  " * depth
            state_marker = {
                AssetState.UNSEEN: "○",
                AssetState.DISCOVERED: "●",
                AssetState.TRIAGED: "◉",
                AssetState.EXPLOITED: "✓",
                AssetState.ABANDONED: "✗",
            }.get(child.state, "?")
            lines.append(
                f"{indent}{state_marker} {child.asset_type.value}: {child.value}"
            )
            self._walk_subtree(child.id, depth + 1, max_depth, lines)
