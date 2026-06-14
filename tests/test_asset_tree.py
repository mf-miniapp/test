"""AssetTree 核心单元测试 — PR1 验证。

覆盖:
  - 节点创建与去重
  - 父子关系校验
  - 状态流转
  - 路径回溯
  - 查询接口 (unseen_leaves, frontier, siblings, descendants, shared IPs)
  - 统计与序列化 (to_dict / from_dict / to_json / from_json / snapshot)
  - render_tree 调试输出
"""

from __future__ import annotations

import json
import pytest

from opensquilla.asset_tree.models import (
    AssetNode,
    AssetNodeRef,
    AssetPath,
    AssetState,
    AssetType,
    validate_parent_child,
)
from opensquilla.asset_tree.tree import AssetTree


# ══════════════════════════════════════════════════════
# 模型测试
# ══════════════════════════════════════════════════════


class TestAssetNode:
    def test_defaults(self) -> None:
        node = AssetNode(asset_type=AssetType.IP, value="1.2.3.4")
        assert node.id
        assert node.state == AssetState.UNSEEN
        assert node.parent_id is None
        assert node.children_ids == []
        assert node.metadata == {}
        assert node.evidence_refs == []

    def test_is_leaf(self) -> None:
        node = AssetNode(asset_type=AssetType.IP, value="1.2.3.4")
        assert node.is_leaf() is True
        node.children_ids = ["child1"]
        assert node.is_leaf() is False

    def test_to_ref(self) -> None:
        node = AssetNode(asset_type=AssetType.PORT, value="443", state=AssetState.DISCOVERED)
        ref = node.to_ref()
        assert isinstance(ref, AssetNodeRef)
        assert ref.node_id == node.id
        assert ref.state == AssetState.DISCOVERED


class TestAssetPath:
    def test_scope_string(self) -> None:
        path = AssetPath(
            parts=[
                AssetNodeRef(node_id="a", asset_type=AssetType.ROOT_DOMAIN, value="example.com", state=AssetState.UNSEEN),
                AssetNodeRef(node_id="b", asset_type=AssetType.IP, value="1.2.3.4", state=AssetState.DISCOVERED),
            ]
        )
        s = path.to_scope_string()
        assert "root_domain=example.com" in s
        assert "ip=1.2.3.4" in s
        assert "→" in s

    def test_brief_context(self) -> None:
        path = AssetPath(
            parts=[
                AssetNodeRef(node_id="a", asset_type=AssetType.ROOT_DOMAIN, value="example.com", state=AssetState.UNSEEN),
                AssetNodeRef(node_id="b", asset_type=AssetType.IP, value="1.2.3.4", state=AssetState.EXPLOITED),
            ]
        )
        ctx = path.to_brief_context()
        assert "[root_domain] example.com" in ctx
        assert "[ip] 1.2.3.4" in ctx
        assert "state=exploited" in ctx

    def test_depth(self) -> None:
        path = AssetPath(parts=[AssetNodeRef(node_id="a", asset_type=AssetType.IP, value="x", state=AssetState.UNSEEN)])
        assert path.depth() == 1


class TestValidateParentChild:
    def test_valid(self) -> None:
        # 不应抛出异常
        validate_parent_child(AssetType.ROOT_DOMAIN, AssetType.SUB_DOMAIN)
        validate_parent_child(AssetType.SUB_DOMAIN, AssetType.IP)
        validate_parent_child(AssetType.IP, AssetType.PORT)
        validate_parent_child(AssetType.PORT, AssetType.SERVICE)
        validate_parent_child(AssetType.SERVICE, AssetType.ENDPOINT)

    def test_invalid(self) -> None:
        with pytest.raises(ValueError, match="Invalid parent"):
            validate_parent_child(AssetType.IP, AssetType.SUB_DOMAIN)

    def test_generic_accepts_any(self) -> None:
        validate_parent_child(AssetType.GENERIC, AssetType.ROOT_DOMAIN)
        validate_parent_child(AssetType.GENERIC, AssetType.ENDPOINT)


# ══════════════════════════════════════════════════════
# AssetTree 核心功能测试
# ══════════════════════════════════════════════════════


class TestAssetTreeCreation:
    def test_root_created(self) -> None:
        tree = AssetTree("example.com")
        assert tree.root_id is not None
        root = tree.get_node(tree.root_id)
        assert root is not None
        assert root.asset_type == AssetType.ROOT_DOMAIN
        assert root.value == "example.com"
        assert root.state == AssetState.UNSEEN
        assert root.parent_id is None

    def test_empty_tree_repr(self) -> None:
        tree = AssetTree("test.com")
        assert "test.com" in repr(tree)
        assert "nodes=1" in repr(tree)


class TestAssetTreeAddNode:
    def test_add_child(self) -> None:
        tree = AssetTree("example.com")
        sub_id = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        sub = tree.get_node(sub_id)
        assert sub is not None
        assert sub.parent_id == tree.root_id
        assert sub_id in tree.get_node(tree.root_id).children_ids

    def test_dedup_same_parent(self) -> None:
        tree = AssetTree("example.com")
        id1 = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        id2 = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        assert id1 == id2
        # 应该只有 1 个子节点
        assert len(tree.get_children(tree.root_id)) == 1

    def test_dedup_different_parent(self) -> None:
        tree = AssetTree("example.com")
        sub1 = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        sub2 = tree.add_node(AssetType.SUB_DOMAIN, "admin.example.com", parent_id=tree.root_id)
        # 同值但不同父 → 不去重
        ip1 = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub1)
        ip2 = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub2)
        assert ip1 != ip2

    def test_invalid_parent_raises(self) -> None:
        tree = AssetTree("example.com")
        with pytest.raises(ValueError, match="Invalid parent"):
            tree.add_node(AssetType.SERVICE, "nginx", parent_id=tree.root_id)

    def test_nonexistent_parent_raises(self) -> None:
        tree = AssetTree("example.com")
        with pytest.raises(ValueError, match="Parent node not found"):
            tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id="nonexistent")

    def test_id_override(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.SUB_DOMAIN, "x.com", id_override="custom_id")
        assert nid == "custom_id"
        assert tree.get_node("custom_id") is not None

    def test_source_wave_recorded(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.SUB_DOMAIN, "x.com", source_wave="W0.5.1")
        node = tree.get_node(nid)
        assert node.source_wave == "W0.5.1"

    def test_metadata_stored(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.SUB_DOMAIN, "x.com", metadata={"resolver": "dns"})
        node = tree.get_node(nid)
        assert node.metadata == {"resolver": "dns"}


class TestAssetTreeStateTransition:
    def test_update_state(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.SUB_DOMAIN, "x.com")
        tree.update_state(nid, AssetState.DISCOVERED)
        assert tree.get_node(nid).state == AssetState.DISCOVERED

    def test_update_state_nonexistent_raises(self) -> None:
        tree = AssetTree("example.com")
        with pytest.raises(ValueError, match="Node not found"):
            tree.update_state("nope", AssetState.EXPLOITED)

    def test_update_metadata(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.IP, "1.2.3.4", metadata={"asn": "AS1"})
        tree.update_metadata(nid, geo="US", isp="Cloudflare")
        node = tree.get_node(nid)
        assert node.metadata["asn"] == "AS1"
        assert node.metadata["geo"] == "US"

    def test_add_evidence_ref(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.IP, "1.2.3.4")
        tree.add_evidence_ref(nid, "W1.recon.1")
        tree.add_evidence_ref(nid, "W1.recon.1")  # 去重
        tree.add_evidence_ref(nid, "W4.exploit.2")
        refs = tree.get_node(nid).evidence_refs
        assert refs == ["W1.recon.1", "W4.exploit.2"]

    def test_assign_wave(self) -> None:
        tree = AssetTree("example.com")
        nid = tree.add_node(AssetType.IP, "1.2.3.4")
        tree.assign_wave(nid, "W1.recon.1")
        assert tree.get_node(nid).assigned_wave == "W1.recon.1"


class TestAssetTreeQueries:
    def _build_simple_tree(self) -> AssetTree:
        """构建一个简单的测试树::

            root (example.com)
             ├── api.example.com (SUB_DOMAIN)
             │    ├── 1.2.3.4 (IP)
             │    │    ├── 80 (PORT) → HTTP/NGINX (SERVICE)
             │    │    └── 443 (PORT) → HTTPS/NGINX (SERVICE)
             │    └── 5.6.7.8 (IP)
             │         └── 22 (PORT) → SSH (SERVICE)
             └── admin.example.com (SUB_DOMAIN)
                  └── 1.2.3.4 (IP)  ← 共享 IP
                       └── 443 (PORT) → HTTPS/Apache (SERVICE)
        """
        tree = AssetTree("example.com")
        api = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        admin = tree.add_node(AssetType.SUB_DOMAIN, "admin.example.com", parent_id=tree.root_id)

        ip1 = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=api)
        ip2 = tree.add_node(AssetType.IP, "5.6.7.8", parent_id=api)
        ip3 = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=admin)  # 共享

        port80 = tree.add_node(AssetType.PORT, "80", parent_id=ip1)
        port443a = tree.add_node(AssetType.PORT, "443", parent_id=ip1)
        port22 = tree.add_node(AssetType.PORT, "22", parent_id=ip2)
        port443b = tree.add_node(AssetType.PORT, "443", parent_id=ip3)

        svc_http = tree.add_node(AssetType.SERVICE, "HTTP/NGINX", parent_id=port80)
        svc_https_a = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port443a)
        svc_ssh = tree.add_node(AssetType.SERVICE, "SSH", parent_id=port22)
        svc_https_b = tree.add_node(AssetType.SERVICE, "HTTPS/Apache", parent_id=port443b)

        return tree

    def test_children(self) -> None:
        tree = self._build_simple_tree()
        root_children = tree.get_children(tree.root_id)
        assert len(root_children) == 2
        values = {c.value for c in root_children}
        assert "api.example.com" in values
        assert "admin.example.com" in values

    def test_parent(self) -> None:
        tree = self._build_simple_tree()
        api = tree.find_node(AssetType.SUB_DOMAIN, "api.example.com")
        parent = tree.get_parent(api.id)
        assert parent.id == tree.root_id

    def test_path_to_root(self) -> None:
        tree = self._build_simple_tree()
        ssh = tree.find_node(AssetType.SERVICE, "SSH")
        path = tree.get_path_to_root(ssh.id)
        assert len(path.parts) == 5
        assert path.parts[0].asset_type == AssetType.ROOT_DOMAIN
        assert path.parts[-1].asset_type == AssetType.SERVICE
        assert path.parts[-1].value == "SSH"
        scope = path.to_scope_string()
        assert "root_domain=example.com" in scope
        assert "service=SSH" in scope

    def test_siblings(self) -> None:
        tree = self._build_simple_tree()
        api = tree.find_node(AssetType.SUB_DOMAIN, "api.example.com")
        siblings = tree.get_siblings(api.id)
        assert len(siblings) == 1
        assert siblings[0].value == "admin.example.com"

    def test_siblings_root_has_no_siblings(self) -> None:
        tree = self._build_simple_tree()
        assert tree.get_siblings(tree.root_id) == []

    def test_descendants(self) -> None:
        tree = self._build_simple_tree()
        api = tree.find_node(AssetType.SUB_DOMAIN, "api.example.com")
        desc = tree.get_all_descendants(api.id)
        assert len(desc) > 0
        desc_values = {d.value for d in desc}
        assert "1.2.3.4" in desc_values
        assert "HTTP/NGINX" in desc_values

    def test_shared_ips(self) -> None:
        tree = self._build_simple_tree()
        shared = tree.find_shared_ips()
        assert "1.2.3.4" in shared
        assert len(shared["1.2.3.4"]) == 2  # api + admin

    def test_unseen_leaves(self) -> None:
        tree = self._build_simple_tree()
        leaves = tree.unseen_leaves()
        # 所有 SERVICE 节点是叶节点且未探测
        assert len(leaves) == 4
        assert all(n.asset_type == AssetType.SERVICE for n in leaves)

    def test_unseen_leaves_after_state_change(self) -> None:
        tree = self._build_simple_tree()
        ssh = tree.find_node(AssetType.SERVICE, "SSH")
        tree.update_state(ssh.id, AssetState.DISCOVERED)
        leaves = tree.unseen_leaves()
        assert len(leaves) == 3
        assert all(n.value != "SSH" for n in leaves)

    def test_frontier(self) -> None:
        tree = self._build_simple_tree()
        assert tree.frontier() == []
        api = tree.find_node(AssetType.SUB_DOMAIN, "api.example.com")
        tree.update_state(api.id, AssetState.DISCOVERED)
        frontier = tree.frontier()
        assert len(frontier) == 1
        assert frontier[0].value == "api.example.com"

    def test_find_node(self) -> None:
        tree = self._build_simple_tree()
        node = tree.find_node(AssetType.IP, "1.2.3.4")
        assert node is not None
        assert node.asset_type == AssetType.IP

    def test_find_nodes_by_value(self) -> None:
        tree = self._build_simple_tree()
        nodes = tree.find_nodes_by_value("1.2.3.4")
        assert len(nodes) == 2  # 两个不同的 IP 节点（api 和 admin）

    def test_nodes_by_state(self) -> None:
        tree = self._build_simple_tree()
        unseen = tree.nodes_by_state(AssetState.UNSEEN)
        assert len(unseen) == len(tree._nodes)  # 所有节点都是 unseen

    def test_nodes_by_type(self) -> None:
        tree = self._build_simple_tree()
        ips = tree.nodes_by_type(AssetType.IP)
        assert len(ips) == 3

    def test_contains(self) -> None:
        tree = self._build_simple_tree()
        assert tree.root_id in tree
        assert "nonexistent" not in tree


class TestAssetTreeStats:
    def test_stats(self) -> None:
        tree = AssetTree("example.com")
        tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        stats = tree.stats()
        assert stats["total_nodes"] == 2
        assert stats["root_domain"] == "example.com"
        assert stats["depth"] == 1
        assert "by_type" in stats
        assert "by_state" in stats

    def test_max_depth(self) -> None:
        tree = AssetTree("example.com")
        assert tree.max_depth() == 0
        sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        assert tree.max_depth() == 1
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        assert tree.max_depth() == 2
        tree.add_node(AssetType.PORT, "80", parent_id=ip)
        assert tree.max_depth() == 3

    def test_len(self) -> None:
        tree = AssetTree("example.com")
        assert len(tree) == 1
        tree.add_node(AssetType.SUB_DOMAIN, "x.com")
        assert len(tree) == 2


class TestAssetTreeSerialization:
    def test_roundtrip_dict(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", source_wave="W0.5.1")
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        tree.update_metadata(ip, asn="AS12345")

        data = tree.to_dict()
        tree2 = AssetTree.from_dict(data)

        assert tree2.root_id == tree.root_id
        assert len(tree2._nodes) == len(tree._nodes)
        restored_ip = tree2.get_node(ip)
        assert restored_ip is not None
        assert restored_ip.state == AssetState.DISCOVERED
        assert restored_ip.metadata["asn"] == "AS12345"

    def test_roundtrip_json(self) -> None:
        tree = AssetTree("example.com")
        tree.add_node(AssetType.SUB_DOMAIN, "x.com", parent_id=tree.root_id)
        j = tree.to_json()
        tree2 = AssetTree.from_json(j)
        assert len(tree2._nodes) == 2

    def test_snapshot(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "x.com")
        tree.update_state(sub, AssetState.DISCOVERED)
        tree.assign_wave(sub, "W1.1")
        snap = tree.snapshot()
        assert snap[sub]["state"] == "discovered"
        assert snap[sub]["assigned_wave"] == "W1.1"
        assert snap[tree.root_id]["state"] == "unseen"


class TestAssetTreeRender:
    def test_render_tree(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        tree.update_state(ip, AssetState.DISCOVERED)
        tree.add_node(AssetType.PORT, "443", parent_id=ip)

        rendered = tree.render_tree()
        assert "[ROOT] example.com" in rendered
        assert "[sub_domain] api.example.com" in rendered
        assert "[ip] 1.2.3.4 [discovered]" in rendered
        assert "[port] 443" in rendered

    def test_render_empty_tree(self) -> None:
        tree = AssetTree.__new__(AssetTree)
        tree._nodes = {}
        tree._edges = {}
        tree._by_type = {}
        tree._value_index = {}
        tree.root_id = None
        assert tree.render_tree() == "<empty tree>"


class TestAssetTreeRepr:
    def test_repr(self) -> None:
        tree = AssetTree("example.com")
        assert "example.com" in repr(tree)
        assert "nodes=1" in repr(tree)
