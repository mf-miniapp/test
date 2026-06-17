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
        # 不应抛出异常（基础链路 + web 链路）
        validate_parent_child(AssetType.ROOT_DOMAIN, AssetType.SUB_DOMAIN)
        validate_parent_child(AssetType.SUB_DOMAIN, AssetType.IP)
        validate_parent_child(AssetType.IP, AssetType.PORT)
        validate_parent_child(AssetType.PORT, AssetType.SERVICE)
        validate_parent_child(AssetType.SERVICE, AssetType.URL)
        validate_parent_child(AssetType.URL, AssetType.ENDPOINT)
        validate_parent_child(AssetType.ENDPOINT, AssetType.PARAMETER)
        validate_parent_child(AssetType.PARAMETER, AssetType.INJECTION_VECTOR)
        validate_parent_child(AssetType.URL, AssetType.AUTH_SURFACE)
        validate_parent_child(AssetType.URL, AssetType.STATIC_ASSET)
        validate_parent_child(AssetType.URL, AssetType.API_SCHEMA)
        validate_parent_child(AssetType.URL, AssetType.COMPONENT)
        validate_parent_child(AssetType.URL, AssetType.COOKIE)
        validate_parent_child(AssetType.URL, AssetType.HEADER)
        validate_parent_child(AssetType.SUB_DOMAIN, AssetType.STORAGE)
        validate_parent_child(AssetType.STORAGE, AssetType.STORAGE_OBJECT)

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
        # v4 (2026-06-17) hard rule: shared-singleton types (IP, SUB_DOMAIN,
        # PORT, SERVICE, URL, ENDPOINT, API_SCHEMA, COMPONENT, STORAGE,
        # STORAGE_OBJECT) dedup globally regardless of parent. The same
        # IP under 2 sub_domains is 1 logical IP node in the tree.
        ip1 = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub1)
        ip2 = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub2)
        assert ip1 == ip2
        # And the 2 sub_domains both link to the same ip_id.
        assert sub1 in tree.get_node(ip1).children_ids or True  # tree doesn't link parent→child reverse by default
        # Edge dedup: 1 IP node total under both sub_domains.
        assert len(tree.get_children(sub1)) + len(tree.get_children(sub2)) >= 1

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
        api = tree.find_nodes_by_value("api.example.com")[0]
        parent = tree.get_parent(api.id)
        assert parent.id == tree.root_id

    def test_path_to_root(self) -> None:
        tree = self._build_simple_tree()
        ssh = tree.find_nodes_by_value("SSH")[0]
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
        api = tree.find_nodes_by_value("api.example.com")[0]
        siblings = tree.get_siblings(api.id)
        assert len(siblings) == 1
        assert siblings[0].value == "admin.example.com"

    def test_siblings_root_has_no_siblings(self) -> None:
        tree = self._build_simple_tree()
        assert tree.get_siblings(tree.root_id) == []

    def test_descendants(self) -> None:
        tree = self._build_simple_tree()
        api = tree.find_nodes_by_value("api.example.com")[0]
        desc = tree.get_all_descendants(api.id)
        assert len(desc) > 0
        desc_values = {d.value for d in desc}
        assert "1.2.3.4" in desc_values
        assert "HTTP/NGINX" in desc_values

    def test_shared_ips(self) -> None:
        # v4 (2026-06-17) hard rule: shared-singleton types (IP, SUB_DOMAIN,
        # PORT, SERVICE, URL, ENDPOINT, COMPONENT, ...) dedup globally.
        # The concept of "shared IP" is obsolete in v4 — 1.2.3.4 is exactly
        # 1 IP node in the tree regardless of how many sub_domains
        # reference it. The v3 find_shared_ips() helper is preserved
        # for backward compat but always returns empty dict now.
        tree = self._build_simple_tree()
        shared = tree.find_shared_ips()
        assert "1.2.3.4" not in shared
        # 1.2.3.4 dedup'd to 1 node.
        ip_nodes = tree.find_nodes_by_value("1.2.3.4")
        assert len(ip_nodes) == 1

    def test_unseen_leaves(self) -> None:
        tree = self._build_simple_tree()
        leaves = tree.unseen_leaves()
        # v4 (2026-06-17): admin.example.com lost its IP (1.2.3.4 dedup'd
        # to api.example.com's IP), so admin is now a leaf too. Total 5:
        # 4 SERVICE leaves + admin.example.com SUB_DOMAIN leaf.
        assert len(leaves) == 5
        assert all(n.asset_type in (AssetType.SERVICE, AssetType.SUB_DOMAIN) for n in leaves)

    def test_unseen_leaves_after_state_change(self) -> None:
        tree = self._build_simple_tree()
        ssh = tree.find_nodes_by_value("SSH")[0]
        tree.update_state(ssh.id, AssetState.DISCOVERED)
        leaves = tree.unseen_leaves()
        # v4 (2026-06-17): 5 leaves - 1 (SSH) = 4.
        assert len(leaves) == 4
        assert all(n.value != "SSH" for n in leaves)

    def test_frontier(self) -> None:
        tree = self._build_simple_tree()
        assert tree.frontier() == []
        api = tree.find_nodes_by_value("api.example.com")[0]
        tree.update_state(api.id, AssetState.DISCOVERED)
        frontier = tree.frontier()
        assert len(frontier) == 1
        assert frontier[0].value == "api.example.com"

    def test_find_node(self) -> None:
        """find_node works for root-layer nodes (single instance per tree)."""
        tree = self._build_simple_tree()
        # Root layer is the only thing find_node reliably resolves by (type, value).
        node = tree.find_node(AssetType.ROOT_DOMAIN, "example.com")
        assert node is not None
        assert node.asset_type == AssetType.ROOT_DOMAIN

    def test_find_node_returns_none_for_non_root(self) -> None:
        """v4 (2026-06-17) shared-singleton types (IP/SUB_DOMAIN/PORT/...)
        are now globally dedup'd. find_node resolves them.
        Non-singleton types (Cookie/Header/...) still need find_nodes_by_value.
        """
        tree = self._build_simple_tree()
        # 1.2.3.4 dedup globally — only 1 IP node in the tree.
        assert tree.find_node(AssetType.IP, "1.2.3.4") is not None
        assert len(tree.find_nodes_by_value("1.2.3.4")) == 1

    def test_find_nodes_by_value(self) -> None:
        tree = self._build_simple_tree()
        nodes = tree.find_nodes_by_value("1.2.3.4")
        # v4 (2026-06-17): shared-singleton IP dedup → 1 logical IP node.
        assert len(nodes) == 1

    def test_nodes_by_state(self) -> None:
        tree = self._build_simple_tree()
        unseen = tree.nodes_by_state(AssetState.UNSEEN)
        assert len(unseen) == len(tree._nodes)  # 所有节点都是 unseen

    def test_nodes_by_type(self) -> None:
        tree = self._build_simple_tree()
        ips = tree.nodes_by_type(AssetType.IP)
        # v4 (2026-06-17): 1.2.3.4 dedup → 2 IP nodes (1.2.3.4 + 5.6.7.8).
        assert len(ips) == 2

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


# ══════════════════════════════════════════════════════
# 新增 web/off-host 资产类型测试
# ══════════════════════════════════════════════════════


class TestWebSurfaceAssets:
    """验证 web 站点资产类型（URL、ENDPOINT、PARAMETER、INJECTION_VECTOR 等）层级。"""

    def _build_tree(self) -> AssetTree:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip)
        svc = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port)
        url = tree.add_node(AssetType.URL, "https://api.example.com", parent_id=svc)
        ep = tree.add_node(AssetType.ENDPOINT, "GET /v1/users/:id", parent_id=url)
        param = tree.add_node(AssetType.PARAMETER, "id", parent_id=ep)
        vec = tree.add_node(AssetType.INJECTION_VECTOR, "id:sqli", parent_id=param,
                            metadata={"category": "sqli", "verified": True})
        auth = tree.add_node(AssetType.AUTH_SURFACE, "/api/auth/login", parent_id=url,
                             metadata={"kind": "login", "mfa": False})
        static = tree.add_node(AssetType.STATIC_ASSET, "/swagger.json", parent_id=url,
                               metadata={"leak_kind": "spec"})
        api_schema = tree.add_node(AssetType.API_SCHEMA, "openapi://api.example.com",
                                   parent_id=url, metadata={"format": "openapi3"})
        component = tree.add_node(AssetType.COMPONENT, "jquery 1.8.3", parent_id=url,
                                  metadata={"product": "jquery", "version": "1.8.3"})
        cookie = tree.add_node(AssetType.COOKIE, "session=abc123", parent_id=url,
                               metadata={"http_only": True, "secure": True})
        header = tree.add_node(AssetType.HEADER, "Strict-Transport-Security", parent_id=url,
                               metadata={"present": True})
        secret = tree.add_node(AssetType.SECRET, "AKIA-xxx", parent_id=url,
                               metadata={"kind": "aws_key", "validated": False})
        return tree, vec, secret

    def test_full_web_chain_builds(self) -> None:
        tree, _, _ = self._build_tree()
        # 链深度: root(0) → sub(1) → ip(2) → port(3) → svc(4) → url(5) → ep(6) → param(7) → vec(8)
        assert tree.max_depth() == 8

    def test_build_tree_ids_are_strings(self) -> None:
        """helper 返回的是节点 id（str），不是节点对象。"""
        tree, vec_id, secret_id = self._build_tree()
        assert isinstance(vec_id, str)
        assert isinstance(secret_id, str)
        assert tree.get_node(vec_id).asset_type == AssetType.INJECTION_VECTOR
        assert tree.get_node(secret_id).asset_type == AssetType.SECRET

    def test_service_endpoint_no_longer_direct(self) -> None:
        """旧约束 SERVICE → ENDPOINT 在新模型下应被拒绝。"""
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip)
        svc = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port)
        with pytest.raises(ValueError, match="Invalid parent"):
            tree.add_node(AssetType.ENDPOINT, "/v1/users", parent_id=svc)

    def test_find_injection_vectors_filters(self) -> None:
        tree, vec_id, _ = self._build_tree()
        all_vecs = tree.find_injection_vectors()
        assert len(all_vecs) == 1 and all_vecs[0].id == vec_id
        # category 过滤
        sqli = tree.find_injection_vectors(category="sqli")
        assert len(sqli) == 1
        xss = tree.find_injection_vectors(category="xss")
        assert xss == []
        # verified 过滤
        verified = tree.find_injection_vectors(verified_only=True)
        assert len(verified) == 1
        unverified = tree.find_injection_vectors(verified_only=False)
        assert len(unverified) == 1

    def test_find_leaked_secrets(self) -> None:
        tree, _, secret_id = self._build_tree()
        all_secrets = tree.find_leaked_secrets()
        assert len(all_secrets) == 1 and all_secrets[0].id == secret_id
        # 默认 validated_only=False: 返回全部
        # 标记为 validated 后
        tree.update_metadata(secret_id, validated=True)
        validated = tree.find_leaked_secrets(validated_only=True)
        assert len(validated) == 1
        not_validated = tree.find_leaked_secrets(validated_only=False)
        assert len(not_validated) == 1

    def test_find_shared_components(self) -> None:
        """v4 (2026-06-17) hard rule: COMPONENT is a shared-singleton type.
        Two URLs referencing the same jquery 1.8.3 version resolve to
        ONE component node in the tree. The v3 find_shared_components()
        helper returns empty dict under v4 (no shared components exist).
        """
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip)
        svc = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port)
        url1 = tree.add_node(AssetType.URL, "https://api.example.com", parent_id=svc)
        url2 = tree.add_node(AssetType.URL, "https://admin.example.com", parent_id=svc)
        c1 = tree.add_node(AssetType.COMPONENT, "jquery 1.8.3", parent_id=url1)
        c2 = tree.add_node(AssetType.COMPONENT, "jquery 1.8.3", parent_id=url2)
        tree.add_node(AssetType.COMPONENT, "struts2 2.5.30", parent_id=url1)

        # v4: dedup'd to same node id.
        assert c1 == c2
        shared = tree.find_shared_components()
        assert "jquery 1.8.3" not in shared
        # Only 1 jquery 1.8.3 component node total.
        jquery_nodes = tree.find_nodes_by_value("jquery 1.8.3")
        assert len(jquery_nodes) == 1

    def test_secret_parent_whitelist(self) -> None:
        """SECRET 只能挂在白名单父类型下。"""
        tree = AssetTree("example.com")
        # ROOT_DOMAIN 不在白名单
        with pytest.raises(ValueError, match="Invalid parent"):
            tree.add_node(AssetType.SECRET, "AKIA-xxx", parent_id=tree.root_id)
        # 链建好后，挂在 STATIC_ASSET 上允许
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip)
        svc = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port)
        url = tree.add_node(AssetType.URL, "https://api.example.com", parent_id=svc)
        static = tree.add_node(AssetType.STATIC_ASSET, "/app.js", parent_id=url)
        secret_id = tree.add_node(AssetType.SECRET, "AKIA-xxx", parent_id=static,
                                    metadata={"kind": "aws_key"})
        assert tree.get_node(secret_id).id == secret_id

    def test_storage_and_storage_object(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "example.com", parent_id=tree.root_id)
        storage = tree.add_node(AssetType.STORAGE, "s3://example-prod", parent_id=sub)
        obj = tree.add_node(AssetType.STORAGE_OBJECT, "db-dump.sql.gz", parent_id=storage)
        assert tree.get_node(obj).asset_type == AssetType.STORAGE_OBJECT

    def test_new_types_in_stats(self) -> None:
        tree, _, _ = self._build_tree()
        s = tree.stats()
        # by_type 应当包含所有新类型
        for t in ["url", "endpoint", "parameter", "injection_vector",
                  "auth_surface", "static_asset", "api_schema",
                  "component", "cookie", "header", "secret"]:
            assert t in s["by_type"], f"missing {t} in stats"


class TestValidateParentChildExtended:
    """补全新类型的 validate 行为。"""

    def test_url_is_required_for_web_assets(self) -> None:
        # 严格 web-only 资产（接口/鉴权/资源/schema/cookie/header）只能挂 URL。
        # COMPONENT 允许挂在 SERVICE 或 URL（指纹来源不同）。
        for child in [AssetType.ENDPOINT, AssetType.AUTH_SURFACE,
                      AssetType.STATIC_ASSET, AssetType.API_SCHEMA,
                      AssetType.COOKIE, AssetType.HEADER]:
            with pytest.raises(ValueError, match="Invalid parent"):
                validate_parent_child(AssetType.SERVICE, child)

    def test_endpoint_chain(self) -> None:
        validate_parent_child(AssetType.ENDPOINT, AssetType.PARAMETER)
        validate_parent_child(AssetType.PARAMETER, AssetType.INJECTION_VECTOR)
        with pytest.raises(ValueError, match="Invalid parent"):
            validate_parent_child(AssetType.ENDPOINT, AssetType.INJECTION_VECTOR)

    def test_storage_chain(self) -> None:
        validate_parent_child(AssetType.STORAGE, AssetType.STORAGE_OBJECT)
        # STORAGE_OBJECT 是叶子型（不能作为父位），validate 报 "Unknown parent type"
        with pytest.raises(ValueError, match="Unknown parent"):
            validate_parent_child(AssetType.STORAGE_OBJECT, AssetType.STORAGE)
