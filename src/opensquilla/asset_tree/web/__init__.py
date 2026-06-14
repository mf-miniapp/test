"""Asset Tree Web — 树桩资产管理与查看的 Web 模块。

提供 REST API 和可视化界面，用于浏览和管理 AssetTree 中的资产数据。

Usage::

    from opensquilla.asset_tree.web import create_asset_tree_routes
    from starlette.routing import Mount

    app = Starlette(routes=[Mount("/asset-tree", create_asset_tree_routes(...))])
"""

from opensquilla.asset_tree.web.routes import create_asset_tree_routes  # noqa: F401

__all__ = ["create_asset_tree_routes"]
