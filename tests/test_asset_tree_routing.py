"""
Tests for asset_tree routing and brief generation (PR2).
"""
from __future__ import annotations

import pytest

from opensquilla.asset_tree.models import AssetNode, AssetType, AssetState
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.asset_tree.routing import (
    RoutingRules,
    WaveRoute,
    default_routing_rules,
    route_node,
    route_subtree,
)
from opensquilla.asset_tree.brief_gen import BriefContext, BriefGenerator


# ═══════════════════════════════════════════════════════════════════════
#  WaveRoute
# ═══════════════════════════════════════════════════════════════════════

class TestWaveRoute:
    def test_basic_creation(self) -> None:
        r = WaveRoute("W1", "recon", priority=40, reason="test")
        assert r.wave_id == "W1"
        assert r.specialist == "recon"
        assert r.priority == 40

    def test_comparison(self) -> None:
        high = WaveRoute("W4", "exploit", priority=10)
        low = WaveRoute("W1", "recon", priority=50)
        assert high < low
        assert not (low < high)

    def test_frozen(self) -> None:
        r = WaveRoute("W1", "recon")
        with pytest.raises(AttributeError):
            r.wave_id = "W2"  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════
#  RoutingRules
# ═══════════════════════════════════════════════════════════════════════

class TestRoutingRules:
    def test_register_and_match(self) -> None:
        rules = RoutingRules()
        rules.register("HTTP", [WaveRoute("W1", "recon")])
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="HTTP",
            parent_id="root",
        )
        route = rules.match(node)
        assert route is not None
        assert route.wave_id == "W1"

    def test_no_match_for_unknown(self) -> None:
        rules = RoutingRules()
        rules.register("HTTP", [WaveRoute("W1", "recon")])
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="UNKNOWN-SVC",
            parent_id="root",
        )
        assert rules.match(node) is None

    def test_match_port_type(self) -> None:
        rules = RoutingRules()
        rules.register("80", [WaveRoute("W1", "recon")])
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.PORT,
            value="80",
            parent_id="root",
        )
        route = rules.match(node)
        assert route is not None

    def test_no_match_for_ip_type(self) -> None:
        rules = RoutingRules()
        rules.register("1.2.3.4", [WaveRoute("W1", "recon")])
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.IP,
            value="1.2.3.4",
            parent_id="root",
        )
        # IP type not in (SERVICE, PORT), so no match
        assert rules.match(node) is None

    def test_empty_rules(self) -> None:
        rules = RoutingRules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="HTTP",
            parent_id="root",
        )
        assert rules.match(node) is None


# ═══════════════════════════════════════════════════════════════════════
#  default_routing_rules
# ═══════════════════════════════════════════════════════════════════════

class TestDefaultRoutingRules:
    def test_http_routes_to_w1(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="HTTP",
            parent_id="root",
        )
        route = rules.match(node)
        assert route is not None
        assert route.wave_id == "W1"

    def test_tomcat_routes_to_w3(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="TOMCAT",
            parent_id="root",
        )
        route = rules.match(node)
        assert route is not None
        assert route.wave_id == "W3"

    def test_ssh_routes_to_w1(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="SSH",
            parent_id="root",
        )
        route = rules.match(node)
        assert route is not None
        assert route.wave_id == "W1"

    def test_redis_routes_to_w1(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="REDIS",
            parent_id="root",
        )
        route = rules.match(node)
        assert route is not None
        assert route.wave_id == "W1"


# ═══════════════════════════════════════════════════════════════════════
#  route_node
# ═══════════════════════════════════════════════════════════════════════

class TestRouteNode:
    def test_unseen_returns_none(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="HTTP",
            parent_id="root",
            state=AssetState.UNSEEN,
        )
        assert route_node(node, rules) is None

    def test_discovered_service_routes(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SERVICE,
            value="HTTPS",
            parent_id="root",
            state=AssetState.DISCOVERED,
        )
        route = route_node(node, rules)
        assert route is not None
        assert route.wave_id == "W1"

    def test_port_fallback_to_w1(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.PORT,
            value="9999",  # unknown port
            parent_id="root",
            state=AssetState.DISCOVERED,
        )
        route = route_node(node, rules)
        assert route is not None
        assert route.wave_id == "W1"

    def test_ip_node_returns_none(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.IP,
            value="1.2.3.4",
            parent_id="root",
            state=AssetState.DISCOVERED,
        )
        assert route_node(node, rules) is None

    def test_subdomain_node_returns_none(self) -> None:
        rules = default_routing_rules()
        node = AssetNode(
            node_id="n1",
            asset_type=AssetType.SUB_DOMAIN,
            value="api.example.com",
            parent_id="root",
            state=AssetState.DISCOVERED,
        )
        assert route_node(node, rules) is None


# ═══════════════════════════════════════════════════════════════════════
#  route_subtree
# ═══════════════════════════════════════════════════════════════════════

class TestRouteSubtree:
    def _build_tree(self) -> tuple[AssetTree, dict]:
        """Build a small tree and return it + routing data."""
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        p80 = tree.add_node(AssetType.PORT, "80", parent_id=ip)
        svc_http = tree.add_node(AssetType.SERVICE, "HTTP", parent_id=p80)
        p22 = tree.add_node(AssetType.PORT, "22", parent_id=ip)
        svc_ssh = tree.add_node(AssetType.SERVICE, "SSH", parent_id=p22)

        # Mark leaf services as discovered
        tree.update_state(svc_http, AssetState.DISCOVERED)
        tree.update_state(svc_ssh, AssetState.DISCOVERED)

        return tree

    def test_route_subtree_returns_sorted(self) -> None:
        tree = self._build_tree()
        rules = default_routing_rules()
        # Build children_of dict from tree edges
        children_of: dict[str, list[str]] = {}
        for parent_id, child_ids in tree._edges.items():
            children_of[parent_id] = child_ids
        results = route_subtree(
            tree.get_node(tree.root_id),  # type: ignore[arg-type]
            tree._nodes,
            children_of,
            rules,
        )
        # Should find both HTTP and SSH routes
        assert len(results) >= 2
        wave_ids = {r.wave_id for r, _ in results}
        assert "W1" in wave_ids

    def test_route_subtree_respects_state(self) -> None:
        tree = self._build_tree()
        rules = default_routing_rules()
        children_of: dict[str, list[str]] = {}
        for parent_id, child_ids in tree._edges.items():
            children_of[parent_id] = child_ids
        # The IP and PORT nodes are unseen; only SERVICE nodes are discovered
        results = route_subtree(
            tree.get_node(tree.root_id),  # type: ignore[arg-type]
            tree._nodes,
            children_of,
            rules,
        )
        # Only the two discovered services should be routed
        target_types = {n.asset_type for _, n in results}
        assert AssetType.SERVICE in target_types


# ═══════════════════════════════════════════════════════════════════════
#  BriefContext
# ═══════════════════════════════════════════════════════════════════════

class TestBriefContext:
    def test_to_dict(self) -> None:
        bc = BriefContext(
            brief_id="W1.recon.abcd1234",
            wave_id="W1",
            specialist="recon",
            target_node_id="abcd1234-5678",
            target_value="HTTP",
            target_type="service",
            subtree_summary="(no children)",
            ancestor_path=["root:example.com", "sub:api.example.com"],
            sibling_nodes=["port:22"],
            metadata={"state": "discovered"},
        )
        d = bc.to_dict()
        assert d["brief_id"] == "W1.recon.abcd1234"
        assert d["wave_id"] == "W1"
        assert len(d["ancestor_path"]) == 2

    def test_to_text(self) -> None:
        bc = BriefContext(
            brief_id="W1.recon.abcd1234",
            wave_id="W1",
            specialist="recon",
            target_node_id="abcd1234-5678",
            target_value="HTTP",
            target_type="service",
            subtree_summary="○ port:80",
            ancestor_path=["root:example.com"],
            sibling_nodes=[],
            metadata={},
        )
        text = bc.to_text()
        assert "## Brief:" in text
        assert "W1" in text
        assert "HTTP" in text

    def test_frozen(self) -> None:
        bc = BriefContext(
            brief_id="test",
            wave_id="W1",
            specialist="recon",
            target_node_id="n1",
            target_value="v",
            target_type="service",
            subtree_summary="",
            ancestor_path=[],
            sibling_nodes=[],
        )
        with pytest.raises(AttributeError):
            bc.wave_id = "W2"  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════
#  BriefGenerator
# ═══════════════════════════════════════════════════════════════════════

class TestBriefGenerator:
    def _build_tree(self) -> AssetTree:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        p80 = tree.add_node(AssetType.PORT, "80", parent_id=ip)
        svc = tree.add_node(AssetType.SERVICE, "HTTP", parent_id=p80)
        tree.update_state(svc, AssetState.DISCOVERED)
        return tree

    def test_generate_brief(self) -> None:
        tree = self._build_tree()
        gen = BriefGenerator(tree)

        # Find the HTTP service node
        http_node = None
        for nid, node in tree._nodes.items():
            if node.value == "HTTP":
                http_node = node
                break
        assert http_node is not None

        route = WaveRoute("W1", "recon", reason="HTTP recon")
        brief = gen.generate(http_node, route)

        assert brief.wave_id == "W1"
        assert brief.specialist == "recon"
        assert brief.target_value == "HTTP"
        assert brief.target_type == "service"
        assert len(brief.ancestor_path) >= 2
        assert brief.metadata["state"] == "discovered"
        assert brief.metadata["reason"] == "HTTP recon"

    def test_brief_id_format(self) -> None:
        tree = self._build_tree()
        gen = BriefGenerator(tree)

        http_node = None
        for nid, node in tree._nodes.items():
            if node.value == "HTTP":
                http_node = node
                break
        assert http_node is not None

        route = WaveRoute("W3", "web-vuln", reason="test")
        brief = gen.generate(http_node, route)
        assert brief.brief_id.startswith("W3.web-vuln.")

    def test_sibling_list(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        p80 = tree.add_node(AssetType.PORT, "80", parent_id=ip)
        p443 = tree.add_node(AssetType.PORT, "443", parent_id=ip)
        svc80 = tree.add_node(AssetType.SERVICE, "HTTP", parent_id=p80)
        svc8080 = tree.add_node(AssetType.SERVICE, "HTTP-8080", parent_id=p80)
        tree.update_state(svc80, AssetState.DISCOVERED)

        gen = BriefGenerator(tree)
        route = WaveRoute("W1", "recon")
        brief = gen.generate(tree.get_node(svc80), route)

        # 8080 is a sibling service of HTTP under port 80
        assert any("8080" in s for s in brief.sibling_nodes)

    def test_subtree_summary(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        p80 = tree.add_node(AssetType.PORT, "80", parent_id=ip)
        svc = tree.add_node(AssetType.SERVICE, "HTTP", parent_id=p80)
        ep = tree.add_node(AssetType.ENDPOINT, "/login", parent_id=svc)
        tree.update_state(ep, AssetState.DISCOVERED)

        gen = BriefGenerator(tree)
        route = WaveRoute("W1", "recon")
        brief = gen.generate(tree.get_node(svc), route)

        assert "/login" in brief.subtree_summary

    def test_max_siblings_limit(self) -> None:
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
        ip = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub)
        # Create 5 ports
        ports = []
        for i in range(5):
            p = tree.add_node(AssetType.PORT, str(80 + i), parent_id=ip)
            ports.append(p)
        svc = tree.add_node(AssetType.SERVICE, "HTTP", parent_id=ports[0])
        tree.update_state(svc, AssetState.DISCOVERED)

        gen = BriefGenerator(tree)
        route = WaveRoute("W1", "recon")
        brief = gen.generate(tree.get_node(svc), route, max_siblings=2)

        # Should have at most 2 siblings
        assert len(brief.sibling_nodes) <= 2
