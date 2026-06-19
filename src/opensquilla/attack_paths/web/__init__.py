"""Web routes for the attack-paths dashboard module (v6, 2026-06-19).

Renders a graphic dashboard of every L0..L7 attack path in a tree,
shows execution status, edge chain, input/output envelopes, evidence
discovered by hack-deep, and which tree nodes got re-fed with
vulnerability links.

Public surface
==============

- :func:`create_attack_path_routes` — Starlette route factory
- :class:`AttackPathStore` — read API on top of ``AssetTreeBackend``
"""
from opensquilla.attack_paths.web.routes import create_attack_path_routes
from opensquilla.attack_paths.web.store import AttackPathStore

__all__ = ["create_attack_path_routes", "AttackPathStore"]
