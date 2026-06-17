"""hack-deep-find specialist subagent packages.

Each specialist is a separate subpackage with its own SOUL_BODY.md and
``__init__.py`` that loads the markdown body. The clone script
(``scripts/clone_hack_deep_find_specialists.py``) imports ``SOUL_BODY``
from each to register the agent in ``~/.opensquilla/config.toml``.

v4.5 (2026-06-18) refactor: 13 v4 specialists -> 13 active (1 rename
+ 1 removal + 1 field cleanup). Positioning fix: hack-deep-find is
"discover every asset and verify it is real", not "rank attack
surfaces". v4.5 specifically:

  - DROP: vuln-prioritizer          (越界: 主动 nuclei 扫描是攻击侧工作)
  - RENAME: surface-aggregator ->
            tree-finalizer            (去 attack-priority-v1 攻击打分,
                                       改为 asset-tree-v1 覆盖度+存活复核)
  - CLEAN: secret-scanner            (去 blast_radius 字段, 仅做识别)

The 13 active specialists are organized by 5 tiers:

  Tier 1 (network surface, 5):
    - domain-expander       (v4 merge: subdomain-discoverer + ip-resolver
                             + seed-expander)
    - port-scanner          (v3 retained)
    - service-fingerprint   (v3 retained)
    - endpoint-crawler      (v3 retained)
    - storage-discoverer    (v4 rename: cloud-storage)

  Tier 2 (web surface, 4):
    - webapp-discoverer     (v3 retained)
    - component-detector    (v4 rename: service-detailed)
    - api-surface-mapper    (v4 merge: api-surface + parameter-extract)
    - content-classifier    (v4 merge: static-asset + auth-mapper +
                             cookie-header)

  Tier 3 (horizontal / cross-layer, 2):
    - osint-collector       (v4 NEW: external-source breadth)
    - secret-scanner        (v3 retained; v4.5 去掉 blast_radius)

  Tier 4 (synthesis, 1):
    - tree-finalizer        (v4.5 RENAME: surface-aggregator ->
                             asset-tree-v1, 去攻击打分)

  Tier 5 (terminal, 1):
    - leaf-verifier         (v3 retained)

  Total: 13 specialists (v4.5: -vuln-prioritizer, -surface-aggregator,
  +tree-finalizer, -blast_radius 字段).

Backward compat:
  - 8 v3 retired names (subdomain-discoverer, ip-resolver, seed-expander,
    api-surface, parameter-extract, static-asset, auth-mapper,
    cookie-header) directories were physically removed in v4.4.
  - 1 v4 retired name (vuln-prioritizer) directory removed in v4.5.
  - 1 v4 renamed name (surface-aggregator -> tree-finalizer);
    surface-aggregator directory removed in v4.5.

v3 -> v4 -> v4.5 wave count delta:
  - F0 (root_domain):  v3 2 -> v4 2 -> v4.5 2 (no change)
  - F1 (sub_domain):   v3 2 -> v4 2 -> v4.5 2 (no change)
  - F2.5 cross-owner: unchanged
  - F6 (url):          v3 4 -> v4 2 -> v4.5 2 (no change)
  - F7 (endpoint):     v3 1 -> v4 0 -> v4.5 0 (no change)
  - F-final:           v3 1 -> v4 2 -> v4.5 2 (no change;
                         surface-aggregator -> tree-finalizer is
                         only a schema rename, same wave count)
  Net: 8 waves unchanged.

v4.5 定位 contract (replace v4 "给 hack-deep 找出可打的面" 错位定位):
  hack-deep-find = 全部资产 + 真实验证
    -> 输出 raw AssetTree + asset-tree-v1 (覆盖度报告 + 存活复核)
    -> 不做: exploitability_score / CVE 关联 / specialist 推荐
    -> 不做: nuclei 主动漏洞扫描 (那是 hack-deep W2 的工作)
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = (
    # Module names use hyphens to match the directory names
    # (Python 3 allows hyphens in module names via importlib only;
    # we use import_module to import them and expose them as
    # attributes for the clone script's convenience).
    #
    # v4.5 (2026-06-18): 13 specialists across 5 tiers.
    # The 10 retired names (8 v3 + 1 v4 vuln-prioritizer +
    # 1 v4 surface-aggregator renamed) are NOT in this tuple.
    # Tier 1 - network surface (5)
    "domain-expander",        # v4 merge
    "port-scanner",           # v3 retained
    "service-fingerprint",    # v3 retained
    "endpoint-crawler",       # v3 retained
    "storage-discoverer",     # v4 rename
    # Tier 2 - web surface (4)
    "webapp-discoverer",      # v3 retained
    "component-detector",     # v4 rename
    "api-surface-mapper",     # v4 merge
    "content-classifier",     # v4 merge
    # Tier 3 - horizontal / cross-layer (2)
    "osint-collector",        # v4 NEW
    "secret-scanner",         # v3 retained (v4.5: -blast_radius)
    # Tier 4 - synthesis (1)
    "tree-finalizer",         # v4.5 RENAME from surface-aggregator
    # Tier 5 - terminal (1)
    "leaf-verifier",          # v3 retained
)

# Alias map: hyphenated import name -> snake_case attribute (kept for
# backward compat with the clone script which historically imported
# them as from opensquilla.agents.hack-deep-find.specialists
# import endpoint_crawler). The clone script is migrated to use
# the hyphenated names in 2026-06-15.
_ALIAS = {
    "domain-expander": "domain_expander",
    "port-scanner": "port_scanner",
    "service-fingerprint": "service_fingerprint",
    "endpoint-crawler": "endpoint_crawler",
    "storage-discoverer": "storage_discoverer",
    "webapp-discoverer": "webapp_discoverer",
    "component-detector": "component_detector",
    "api-surface-mapper": "api_surface_mapper",
    "content-classifier": "content_classifier",
    "osint-collector": "osint_collector",
    "secret-scanner": "secret_scanner",
    "tree-finalizer": "tree_finalizer",
    "leaf-verifier": "leaf_verifier",
}

# Retired specialist names. v4.4: the 8 v3 directories were physically
# removed from disk. v4.5: vuln-prioritizer + surface-aggregator also
# removed. This constant is kept for historical documentation and for
# any audit log that references the v3/v4 names.
_RETIRED_V3_SPECIALISTS: tuple[str, ...] = (
    "subdomain-discoverer",  # v4 merged into domain-expander
    "ip-resolver",           # v4 merged into domain-expander
    "seed-expander",         # v4 merged into domain-expander
    "api-surface",           # v4 merged into api-surface-mapper
    "parameter-extract",     # v4 merged into api-surface-mapper
    "static-asset",          # v4 merged into content-classifier
    "auth-mapper",           # v4 merged into content-classifier
    "cookie-header",         # v4 merged into content-classifier
    "cloud-storage",         # v4 renamed to storage-discoverer
    "service-detailed",      # v4 renamed to component-detector
)

_RETIRED_V4_SPECIALISTS: tuple[str, ...] = (
    "vuln-prioritizer",      # v4.5 removed (越界: 主动 nuclei 扫描)
    "surface-aggregator",    # v4.5 renamed to tree-finalizer
)

# Eagerly import each so SOUL_BODY is hot-loaded when the clone script
# runs `from opensquilla.agents.hack-deep-find.specialists import X`.
_modules = {
    name: import_module(f"{__name__}.{name}") for name in _SUBMODULES
}
# Expose both the hyphenated and snake_case attribute names so the
# clone script can keep its historical from ... import
# endpoint_crawler style working. 2026-06-15 unifies the
# directory names to hyphens; the alias keeps old import sites
# from breaking.
for _hyphen, _snake in _ALIAS.items():
    globals()[_snake] = _modules[_hyphen]

__all__ = list(_SUBMODULES)
