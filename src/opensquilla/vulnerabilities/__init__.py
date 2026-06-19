"""vulnerabilities — v6 漏洞模块 (2026-06-19)。

v6 重构新增。包含:
  - ``vulnerabilities.web``  : 漏洞列表 / 详情 Web UI (Starlette 路由)
  - ``vulnerabilities.db``   : 与 asset_tree 共用 SQLAlchemy backend

数据全部存在 ``vulnerabilities`` / ``vuln_path_vulns`` / ``vuln_node_vulns``
/ ``vuln_attack_paths`` 4 张表 (定义在 ``opensquilla.asset_tree.db.schema``),
共享 asset_tree 的 MySQL 连接池与事务。
"""
from opensquilla.vulnerabilities.web import create_vulnerability_routes

__all__ = ["create_vulnerability_routes"]
