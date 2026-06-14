"""Asset Tree — 树状资产记忆与管理系统。

为 hack-deep 波次调度提供结构化的资产发现、关系追踪和状态管理。

树结构::

    RootDomain
     └── SubDomain
          ├── IP
          │    ├── Port → Service
          │    │    └── Endpoint (路径/表/方法)
          │    └── Port → Service
          └── IP
               └── ...

Usage::

    from opensquilla.asset_tree import AssetTree, AssetType, AssetState

    tree = AssetTree("example.com")
    sub_id = tree.add_node(AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id)
    ip_id  = tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub_id)
    port_id = tree.add_node(AssetType.PORT, "443", parent_id=ip_id)
    svc_id = tree.add_node(AssetType.SERVICE, "HTTPS/NGINX", parent_id=port_id)
    tree.update_state(svc_id, AssetState.DISCOVERED)

    for leaf in tree.unseen_leaves():
        print(leaf.value)
"""

from opensquilla.asset_tree.models import (
    AssetNode,
    AssetNodeRef,
    AssetPath,
    AssetState,
    AssetType,
)
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.asset_tree.routing import (
    RoutingRules,
    WaveRoute,
    default_routing_rules,
    route_node,
    route_subtree,
)
from opensquilla.asset_tree.brief_gen import BriefContext, BriefGenerator

__all__ = [
    "AssetNode",
    "AssetNodeRef",
    "AssetPath",
    "AssetState",
    "AssetTree",
    "AssetType",
    "BriefContext",
    "BriefGenerator",
    "RoutingRules",
    "WaveRoute",
    "default_routing_rules",
    "route_node",
    "route_subtree",
]
