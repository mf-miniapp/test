"""Regression: AssetTree.from_dict must rebuild node.children_ids from edges.

The original bug was that ``from_dict`` restored ``_edges`` but never
synced each parent's ``children_ids`` list. After round-trip, code that
walked ``node.children_ids`` (e.g. ``is_leaf()`` checks) saw empty lists
and reported false leafs.

Fix: ``from_dict`` now appends missing child ids to each parent.
"""

from __future__ import annotations

from opensquilla.asset_tree.models import AssetState, AssetType
from opensquilla.asset_tree.tree import AssetTree


def _build() -> AssetTree:
    tree = AssetTree("example.com")
    api = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
    admin = tree.add_node(AssetType.SUB_DOMAIN, "admin.example.com", parent_id=tree.root_id)
    ip_api = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=api)
    ip_admin = tree.add_node(AssetType.IP, "5.6.7.8", parent_id=admin)
    tree.add_node(AssetType.PORT, "443", parent_id=ip_api)
    tree.add_node(AssetType.PORT, "80", parent_id=ip_api)
    tree.add_node(AssetType.PORT, "22", parent_id=ip_admin)
    return tree


def test_from_dict_rebuilds_children_ids() -> None:
    tree = _build()
    payload = tree.to_dict()

    # Sanity: in-memory tree has populated children_ids
    root = tree.get_node(tree.root_id)
    assert len(root.children_ids) == 2  # api + admin

    # Mutate the serialized node dicts to strip children_ids (simulating an
    # older serializer / external write). This is what would have masked
    # the bug — the on-disk representation did NOT carry children_ids.
    for n in payload["nodes"].values():
        n["children_ids"] = []

    restored = AssetTree.from_dict(payload)

    # Now the rebuilt tree must reflect the same structure as in-memory
    r_root = restored.get_node(restored.root_id)
    assert len(r_root.children_ids) == 2, (
        f"children_ids not rebuilt from edges: {r_root.children_ids}"
    )

    api = restored.find_nodes_by_value("api.example.com")[0]
    assert len(api.children_ids) == 1  # the one IP

    ip = restored.find_nodes_by_value("1.2.3.4")[0]
    assert len(ip.children_ids) == 2  # port 443 + port 80


def test_from_dict_idempotent_children_ids() -> None:
    """If children_ids is already populated in the payload, from_dict must NOT duplicate."""
    tree = _build()
    payload = tree.to_dict()
    # Children_ids are NOT stripped — simulating a write that includes them.
    restored = AssetTree.from_dict(payload)
    root = restored.get_node(restored.root_id)
    assert len(root.children_ids) == 2  # not 4

    api = restored.find_nodes_by_value("api.example.com")[0]
    assert len(api.children_ids) == 1


def test_round_trip_preserves_tree() -> None:
    """Full round-trip preserves node count, edges, and states."""
    tree = _build()
    api = tree.find_nodes_by_value("api.example.com")[0]
    tree.update_state(api.id, AssetState.DISCOVERED)

    restored = AssetTree.from_dict(tree.to_dict())
    assert len(restored) == len(tree)

    # States survive
    assert restored.get_node(api.id).state == AssetState.DISCOVERED

    # Edges survive
    assert set(restored._edges.keys()) == set(tree._edges.keys())
    for parent_id, child_ids in tree._edges.items():
        assert set(restored._edges[parent_id]) == set(child_ids)


def test_remove_subtree_clears_children_ids() -> None:
    """remove_subtree should also drop removed children from parent.children_ids."""
    tree = _build()
    api = tree.find_nodes_by_value("api.example.com")[0]
    root = tree.get_node(tree.root_id)

    assert len(root.children_ids) == 2  # api + admin
    tree.remove_subtree(api.id)
    # api and its descendants must be gone from root.children_ids
    assert api.id not in root.children_ids
    assert len(root.children_ids) == 1  # only admin remains