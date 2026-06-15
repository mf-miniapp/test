"""Concurrency tests for AssetTree (RLock protection).

The original AssetTree was unsafe under concurrent mutations: two
coroutines adding nodes at the same time could race the internal dict
updates and produce inconsistent state. Phase 1.1 wraps every public
mutator with ``threading.RLock``; this file stress-tests that.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from opensquilla.asset_tree.models import AssetState, AssetType
from opensquilla.asset_tree.tree import AssetTree


def test_concurrent_add_node_threaded() -> None:
    """100 threads each adding a distinct SUB_DOMAIN → 100 nodes, no losses."""
    tree = AssetTree("example.com")
    n_threads = 100

    def add(i: int) -> None:
        tree.add_node(
            AssetType.SUB_DOMAIN,
            f"sub{i}.example.com",
            parent_id=tree.root_id,
        )

    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        list(ex.map(add, range(n_threads)))

    assert len(tree) == 1 + n_threads  # root + 100 subs

    # Each added node must be retrievable
    for i in range(n_threads):
        node = tree.find_nodes_by_value(f"sub{i}.example.com")
        assert len(node) == 1, f"sub{i}.example.com missing or duplicated"


def test_concurrent_add_node_under_different_parents() -> None:
    """Two IPs concurrently added under different sub_domain parents — both must survive."""
    tree = AssetTree("example.com")
    api_id = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
    admin_id = tree.add_node(AssetType.SUB_DOMAIN, "admin.example.com", parent_id=tree.root_id)

    barrier = threading.Barrier(2)

    def add_under(parent_id: str, ip: str) -> None:
        barrier.wait()
        tree.add_node(AssetType.IP, ip, parent_id=parent_id)

    t1 = threading.Thread(target=add_under, args=(api_id, "1.2.3.4"))
    t2 = threading.Thread(target=add_under, args=(admin_id, "5.6.7.8"))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert len(tree) == 5  # root + 2 subs + 2 IPs
    assert tree.find_nodes_by_value("1.2.3.4")[0].parent_id == api_id
    assert tree.find_nodes_by_value("5.6.7.8")[0].parent_id == admin_id


def test_state_update_under_concurrent_adds() -> None:
    """State updates interleaved with adds must not corrupt the tree."""
    tree = AssetTree("example.com")
    sub_id = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)

    def updater() -> None:
        for _ in range(50):
            tree.update_state(sub_id, AssetState.DISCOVERED)

    def adder() -> None:
        for i in range(50):
            tree.add_node(AssetType.IP, f"9.9.9.{i}", parent_id=sub_id)

    t1 = threading.Thread(target=updater)
    t2 = threading.Thread(target=adder)
    t1.start(); t2.start()
    t1.join(); t2.join()

    # Sub state survived all updates
    assert tree.get_node(sub_id).state == AssetState.DISCOVERED
    # All 50 IPs are present
    for i in range(50):
        assert tree.find_nodes_by_value(f"9.9.9.{i}")


def test_remove_subtree_under_concurrent_reads() -> None:
    """Reads must not see a partially-deleted subtree."""
    tree = AssetTree("example.com")
    sub_id = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
    for i in range(20):
        tree.add_node(AssetType.IP, f"1.1.1.{i}", parent_id=sub_id)

    errors: list[str] = []

    def reader() -> None:
        for _ in range(100):
            try:
                node = tree.get_node(sub_id)
                if node is None:
                    # Subtree being deleted — that's fine, just skip
                    continue
                descendants = tree.get_all_descendants(sub_id)
                for d in descendants:
                    if d.parent_id != sub_id:
                        errors.append(f"orphan descendant {d.id} under {d.parent_id}")
            except Exception as exc:
                errors.append(f"reader exc: {exc}")

    def remover() -> None:
        tree.remove_subtree(sub_id)

    t1 = threading.Thread(target=reader)
    t2 = threading.Thread(target=remover)
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert not errors, f"reader saw inconsistencies: {errors}"
    # Subtree gone
    assert tree.get_node(sub_id) is None
    assert len(tree) == 1  # only root remains