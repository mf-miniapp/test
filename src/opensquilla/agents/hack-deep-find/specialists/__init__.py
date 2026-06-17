"""hack-deep-find specialist subagent packages.

Each specialist is a separate subpackage with its own SOUL_BODY.md and
``__init__.py`` that loads the markdown body. The clone script
(``scripts/clone_hack_deep_find_specialists.py``) imports ``SOUL_BODY``
from each to register the agent in ``~/.opensquilla/config.toml``.

v4 (2026-06-17) refactor: 16 specialists -> 13 by consolidating
3 v3 splits and adding 1 new aggregator. The 13 specialists are
organized by 5 tiers:

  Tier 1 (network surface, 5):
    - domain-expander       (replaces subdomain-discoverer + ip-resolver
                             + seed-expander; v4 merge of F0 horizontal)
    - port-scanner          (v3 retained)
    - service-fingerprint   (v3 retained)
    - endpoint-crawler      (v3 retained)
    - storage-discoverer    (renamed from cloud-storage for v4 clarity)

  Tier 2 (web surface, 4):
    - webapp-discoverer     (v3 retained)
    - component-detector    (renamed from service-detailed)
    - api-surface-mapper    (replaces api-surface + parameter-extract;
                             v4 merge for schema_id link in one agent)
    - content-classifier    (replaces static-asset + auth-mapper +
                             cookie-header; v4 merge for one HTTP-pass
                             of all 4 cross-cutting signals)

  Tier 3 (horizontal / cross-layer, 2):
    - osint-collector       (NEW in v4: external-source breadth from
                             legacy intel-collection, with the
                             hack-deep-find specialist contract)
    - secret-scanner        (v3 retained)

  Tier 4 (synthesis, 1):
    - surface-aggregator    (NEW in v4: produces attack-priority-v1
                             evidence from the AssetTree, replacing
                             legacy attack-surface-enumeration's
                             free-text output)

  Tier 5 (terminal, 1):
    - leaf-verifier         (v3 retained)

  Total: 13 specialists (down from 16 v3 by 3-way merge, +2 new).

Backward compat: the 8 retired v3 specialist names
(subdomain-discoverer, ip-resolver, seed-expander, api-surface,
parameter-extract, static-asset, auth-mapper, cookie-header) remain
in the directory as DEPRECATED packages. They are NOT registered in
``_SUBMODULES`` and NOT cloned by ``clone_hack_deep_find_specialists``.
The clone script's ``SPECIALIST_AGENTS`` list also drops them.
The v3 SOUL files stay on disk for historical reference but the
runtime does not invoke them.

v3 -> v4 wave count delta:
  - F0 (root_domain):  v3 2 specialists (subdomain-discoverer + seed-expander) -> v4 2 specialists
    (domain-expander + osint-collector). Same count, no IPC overhead.
  - F1 (sub_domain):   v3 2 specialists (ip-resolver + cloud-storage) -> v4 2 specialists
    (port-scanner is downstream of F1's IP, not F1; storage-discoverer
    is unchanged from cloud-storage). Same.
  - F2.5 cross-owner: unchanged
  - F6 (url):          v3 4 specialists (api-surface + static-asset +
    auth-mapper + cookie-header) -> v4 2 specialists
    (api-surface-mapper + content-classifier). -2 wave.
  - F7 (endpoint):     v3 1 specialist (parameter-extract) -> v4 0
    (folded into api-surface-mapper). -1 wave.
  - F-final:           v3 1 step -> v4 2 steps
    (surface-aggregator + handoff). +1 wave.
  Net: -2 waves, +1 wave = -1 wave. Total F0-F-final waves: 7+1 = 8.
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = (
    # Module names use hyphens to match the directory names
    # (Python 3 allows hyphens in module names via importlib only;
    # we use import_module to import them and expose them as
    # attributes for the clone script's convenience).
    #
    # v4 (2026-06-17): 13 specialists across 5 tiers. The 8 retired
    # v3 names (subdomain-discoverer, ip-resolver, seed-expander,
    # api-surface, parameter-extract, static-asset, auth-mapper,
    # cookie-header) are NOT in this tuple; their SOUL_BODY.md
    # files remain on disk for reference but the clone script
    # does not register them in config.toml.
    #
    # Tier 1 - network surface (5)
    "domain-expander",        # v4 merge: subdomain-discoverer + ip-resolver + seed-expander
    "port-scanner",           # v3 retained
    "service-fingerprint",    # v3 retained
    "endpoint-crawler",       # v3 retained
    "storage-discoverer",     # v4 rename: cloud-storage -> storage-discoverer
    # Tier 2 - web surface (4)
    "webapp-discoverer",      # v3 retained
    "component-detector",     # v4 rename: service-detailed -> component-detector
    "api-surface-mapper",     # v4 merge: api-surface + parameter-extract
    "content-classifier",     # v4 merge: static-asset + auth-mapper + cookie-header
    # Tier 3 - horizontal / cross-layer (2)
    "osint-collector",        # v4 NEW: external-source breadth (Shodan/Censys/...)
    "secret-scanner",         # v3 retained
    # Tier 4 - synthesis (1)
    "surface-aggregator",     # v4 NEW: AssetTree -> attack-priority-v1
    # Tier 5 - terminal (1)
    "leaf-verifier",          # v3 retained
)

# Alias map: hyphenated import name -> snake_case attribute (kept for
# backward compat with the clone script which historically imported
# them as from opensquilla.agents.hack-deep-find.specialists
# import endpoint_crawler). The clone script is migrated to use
# the hyphenated names in 2026-06-15.
_ALIAS = {
    # v4 active specialists (13). ONLY these names have a matching
    # entry in _SUBMODULES; importing via these names works.
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
    "surface-aggregator": "surface_aggregator",
    "leaf-verifier": "leaf_verifier",
}

# v3 retired specialist names (kept on disk for reference but NOT
# imported or aliased). Importing these via the package raises
# ModuleNotFoundError by design — the v3 SOUL_BODY.md files remain
# readable from disk (e.g. via scripts/clone_hack_deep_find.py's
# importlib) but no Python attribute is exposed.
_RETIRED_V3_SPECIALISTS: tuple[str, ...] = (
    "subdomain-discoverer",
    "ip-resolver",
    "seed-expander",
    "api-surface",
    "parameter-extract",
    "static-asset",
    "auth-mapper",
    "cookie-header",
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
