"""In-memory store for managing multiple AssetTree instances.

Each tree is identified by a unique ID and can be created, listed,
retrieved, and deleted through the web interface.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from opensquilla.asset_tree.models import (
    AssetNode,
    AssetState,
    AssetType,
)
from opensquilla.asset_tree.tree import AssetTree


class TreeStore:
    """Thread-safe (single-worker async) in-memory tree storage.

    Each tree has metadata (created_at, updated_at, description) and
    the actual AssetTree instance.
    """

    def __init__(self) -> None:
        self._trees: dict[str, _TreeEntry] = {}
        self._auto_id_counter = 0

    def list_trees(self) -> list[dict[str, Any]]:
        """Return metadata for all stored trees."""
        results = []
        for tree_id, entry in self._trees.items():
            stats = entry.tree.stats()
            results.append({
                "id": tree_id,
                "root_domain": entry.tree.root_domain,
                "description": entry.description,
                "node_count": stats["total_nodes"],
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            })
        return results

    def create_tree(
        self,
        root_domain: str,
        tree_id: Optional[str] = None,
        description: str = "",
    ) -> dict[str, Any]:
        """Create a new tree and return its metadata."""
        if tree_id is None:
            self._auto_id_counter += 1
            tree_id = f"tree-{self._auto_id_counter}"
        elif tree_id in self._trees:
            raise ValueError(f"Tree '{tree_id}' already exists")

        tree = AssetTree(root_domain)
        now = time.time()
        self._trees[tree_id] = _TreeEntry(tree=tree, description=description, created_at=now, updated_at=now)
        return self._tree_meta(tree_id)

    def get_tree(self, tree_id: str) -> AssetTree:
        """Get the AssetTree instance by ID."""
        if tree_id not in self._trees:
            raise KeyError(f"Tree '{tree_id}' not found")
        return self._trees[tree_id].tree

    def get_tree_meta(self, tree_id: str) -> dict[str, Any]:
        """Get tree metadata by ID."""
        if tree_id not in self._trees:
            raise KeyError(f"Tree '{tree_id}' not found")
        return self._tree_meta(tree_id)

    def delete_tree(self, tree_id: str) -> None:
        """Delete a tree."""
        if tree_id not in self._trees:
            raise KeyError(f"Tree '{tree_id}' not found")
        del self._trees[tree_id]

    def update_tree_meta(self, tree_id: str, **kwargs: Any) -> dict[str, Any]:
        """Update tree metadata (description, etc)."""
        if tree_id not in self._trees:
            raise KeyError(f"Tree '{tree_id}' not found")
        entry = self._trees[tree_id]
        if "description" in kwargs:
            entry.description = kwargs["description"]
        entry.updated_at = time.time()
        return self._tree_meta(tree_id)

    def touch(self, tree_id: str) -> None:
        """Update the updated_at timestamp."""
        if tree_id in self._trees:
            self._trees[tree_id].updated_at = time.time()

    def _tree_meta(self, tree_id: str) -> dict[str, Any]:
        entry = self._trees[tree_id]
        stats = entry.tree.stats()
        return {
            "id": tree_id,
            "root_domain": entry.tree.root_domain,
            "description": entry.description,
            "node_count": stats["total_nodes"],
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }


class _TreeEntry:
    """Internal record for a stored tree."""

    __slots__ = ("tree", "description", "created_at", "updated_at")

    def __init__(self, tree: AssetTree, description: str, created_at: float, updated_at: float) -> None:
        self.tree = tree
        self.description = description
        self.created_at = created_at
        self.updated_at = updated_at
