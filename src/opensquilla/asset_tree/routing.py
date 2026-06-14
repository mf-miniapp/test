"""
Service routing: maps asset tree nodes → attack wave configurations.

Wave mapping:
  - W0: engagement planning (tree root only)
  - W1: reconnaissance (ports, known HTTP/HTTPS, SSH, FTP, DNS)
  - W2: credential checks (SSH, FTP, SMB, RDP)
  - W3: web vulnerabilities (HTTP, HTTPS, Tomcat, Apache, Nginx)
  - W4: exploitation (service-specific payload dispatch)
  - W5: post-exploitation (if needed)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import AssetType, AssetNode, AssetState


# ── Attack Wave IDs ──────────────────────────────────────────────────────
WAVE_IDS = ("W0", "W1", "W2", "W3", "W4", "W5")


@dataclass(frozen=True)
class WaveRoute:
    """A routing decision for a node."""
    wave_id: str
    specialist: str
    priority: int = 50  # lower = higher priority
    reason: str = ""

    def __lt__(self, other: "WaveRoute") -> bool:
        return self.priority < other.priority


@dataclass
class RoutingRules:
    """Configurable service → wave mapping.

    Each service name pattern maps to a list of WaveRoute entries.
    First matching route wins.
    """
    rules: dict[str, list[WaveRoute]] = field(default_factory=dict)

    def register(self, service_pattern: str, routes: list[WaveRoute]) -> None:
        """Register routes for a service pattern (case-insensitive)."""
        self.rules[service_pattern.upper()] = routes

    def match(self, node: AssetNode) -> Optional[WaveRoute]:
        """Find the first matching route for a node's value (treated as service name)."""
        if node.asset_type not in (AssetType.SERVICE, AssetType.PORT):
            return None
        key = node.value.upper()
        for pattern, routes in self.rules.items():
            if pattern in key or key in pattern:
                if routes:
                    return routes[0]
        return None


def default_routing_rules() -> RoutingRules:
    """Built-in service → wave mapping."""
    r = RoutingRules()

    # ── W1: Reconnaissance ────────────────────────────────────────
    r.register("HTTP", [WaveRoute("W1", "recon", priority=40, reason="HTTP recon")])
    r.register("HTTPS", [WaveRoute("W1", "recon", priority=40, reason="HTTPS recon")])
    r.register("SSH", [WaveRoute("W1", "recon", priority=45, reason="SSH version check")])
    r.register("FTP", [WaveRoute("W1", "recon", priority=45, reason="FTP banner grab")])
    r.register("DNS", [WaveRoute("W1", "recon", priority=50, reason="DNS recon")])
    r.register("SMB", [WaveRoute("W1", "recon", priority=45, reason="SMB enumeration")])
    r.register("RDP", [WaveRoute("W1", "recon", priority=45, reason="RDP probe")])
    r.register("MYSQL", [WaveRoute("W1", "recon", priority=45, reason="MySQL version")])
    r.register("POSTGRES", [WaveRoute("W1", "recon", priority=45, reason="PostgreSQL version")])
    r.register("REDIS", [WaveRoute("W1", "recon", priority=45, reason="Redis info")])

    # ── W2: Credential checks ─────────────────────────────────────
    r.register("SSH-CRED", [WaveRoute("W2", "cred", priority=30, reason="SSH credential check")])
    r.register("FTP-CRED", [WaveRoute("W2", "cred", priority=30, reason="FTP credential check")])
    r.register("SMB-CRED", [WaveRoute("W2", "cred", priority=30, reason="SMB credential check")])
    r.register("RDP-CRED", [WaveRoute("W2", "cred", priority=30, reason="RDP credential check")])

    # ── W3: Web vulnerabilities ───────────────────────────────────
    r.register("TOMCAT", [WaveRoute("W3", "web-vuln", priority=20, reason="Tomcat vuln scan")])
    r.register("APACHE", [WaveRoute("W3", "web-vuln", priority=20, reason="Apache vuln scan")])
    r.register("NGINX", [WaveRoute("W3", "web-vuln", priority=20, reason="Nginx vuln scan")])

    # ── W4: Exploitation (service-specific) ───────────────────────
    r.register("EXPLOIT", [WaveRoute("W4", "exploit", priority=10, reason="Service exploit")])

    return r


# ── Routing API ──────────────────────────────────────────────────────────

def route_node(
    node: AssetNode,
    rules: RoutingRules,
    *,
    ancestor_states: Optional[list[AssetState]] = None,
) -> Optional[WaveRoute]:
    """Route a single node through the rule engine.

    Args:
        node: The asset tree node to route.
        rules: The routing rules to apply.
        ancestor_states: Optional list of ancestor states for context.

    Returns:
        A WaveRoute if the node matches a rule, or None.
    """
    # Skip unseen nodes (ancestors not yet processed)
    if node.state == AssetState.UNSEEN:
        return None

    # Check direct service routing
    route = rules.match(node)
    if route:
        return route

    # For PORT nodes without a direct match, fall back to W1 recon
    if node.asset_type == AssetType.PORT:
        return WaveRoute("W1", "recon", priority=50, reason=f"Port {node.value} → default W1 recon")

    return None


def route_subtree(
    tree_root: AssetNode,
    nodes_by_id: dict[str, AssetNode],
    children_of: dict[str, list[str]],
    rules: RoutingRules,
) -> list[tuple[WaveRoute, AssetNode]]:
    """Walk a subtree and produce routing decisions for all processable nodes.

    Returns list of (route, node) pairs sorted by priority (highest first).
    """
    results: list[tuple[WaveRoute, AssetNode]] = []
    stack: list[str] = [tree_root.id]

    while stack:
        nid = stack.pop()
        node = nodes_by_id[nid]
        route = route_node(node, rules)
        if route:
            results.append((route, node))
        # push children
        for child_id in children_of.get(nid, []):
            stack.append(child_id)

    results.sort(key=lambda x: x[0].priority)
    return results
