"""hack-deep-find specialist subagent packages.

Each specialist is a separate subpackage with its own SOUL_BODY.md and
``__init__.py`` that loads the markdown body. The clone script
(``scripts/clone_hack_deep_find_specialists.py``) imports ``SOUL_BODY``
from each to register the agent in ``~/.opensquilla/config.toml``.

Phase 2 (2026-06-14) shipped 6:
  - subdomain-discoverer
  - ip-resolver
  - port-scanner
  - service-fingerprint
  - endpoint-crawler
  - leaf-verifier

Batch 1 (2026-06-15) added 5:
  - service-detailed
  - webapp-discoverer
  - api-surface
  - parameter-extract
  - static-asset

Batch 2 (2026-06-15) added 2:
  - auth-mapper
  - cookie-header

Batch 3 (2026-06-15) added 2:
  - cloud-storage
  - secret-scanner

Batch 4 (2026-06-15) added 1:
  - seed-expander

Total: 16 specialists.
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = (
    # Module names use hyphens to match the directory names
    # (Python 3 allows hyphens in module names via importlib only;
    # we use import_module to import them and expose them as
    # attributes for the clone script's convenience).
    # Phase 2 (network surface)
    "subdomain-discoverer",
    "ip-resolver",
    "port-scanner",
    "service-fingerprint",
    "endpoint-crawler",
    "leaf-verifier",
    # Batch 1 (web surface depth + component-level CVE view)
    "service-detailed",
    "webapp-discoverer",
    "api-surface",
    "parameter-extract",
    "static-asset",
    # Batch 2 (auth + cookie/header security posture)
    "auth-mapper",
    "cookie-header",
    # Batch 3 (cloud storage + cross-layer secret scanner)
    "cloud-storage",
    "secret-scanner",
    # Batch 4 (horizontal seed expansion)
    "seed-expander",
)

# Alias map: hyphenated import name -> snake_case attribute (kept for
# backward compat with the clone script which historically imported
# them as from opensquilla.agents.hack-deep-find.specialists
# import endpoint_crawler). The clone script is migrated to use
# the hyphenated names in 2026-06-15.
_ALIAS = {
    "subdomain-discoverer": "subdomain_discoverer",
    "ip-resolver": "ip_resolver",
    "port-scanner": "port_scanner",
    "service-fingerprint": "service_fingerprint",
    "endpoint-crawler": "endpoint_crawler",
    "leaf-verifier": "leaf_verifier",
    # Batch 1
    "service-detailed": "service_detailed",
    "webapp-discoverer": "webapp_discoverer",
    "api-surface": "api_surface",
    "parameter-extract": "parameter_extract",
    "static-asset": "static_asset",
    # Batch 2
    "auth-mapper": "auth_mapper",
    "cookie-header": "cookie_header",
    # Batch 3
    "cloud-storage": "cloud_storage",
    "secret-scanner": "secret_scanner",
    # Batch 4
    "seed-expander": "seed_expander",
}

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
