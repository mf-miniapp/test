"""Recon tools for hack-deep-find specialists.

These tools are policy-gated under ``group:recon:*`` namespaces
(see ``opensquilla.tools.policy_config``). Only recon specialists
and the ``hack-deep-find`` LLM-coordinator (for endpoint reachability
verification only) are allowed to call them.

Implementation note (v4, 2026-06-17): tools prefer mature industry-
standard binaries (naabu / httpx / subfinder / katana / nuclei / nmap)
for speed and depth. The stdlib path (asyncio.open_connection +
urllib.request) is the FALLBACK used when a binary is not on PATH.

The previous v3 design said "prefer stdlib over shelling out to
curl/nmap" — that constraint is reversed. Reason: 51ifind.com run
on 2026-06-17 had 13% port coverage (14/84 ports) because stdlib
per-port probes were too slow for the LLM to wait. naabu scans 65k
ports in 10 seconds. Speed matters; stdlib is the fallback.

The binary wrappers are safe: they pass argv as a literal list
(no shell), use ``capture_output=True``, and parse JSON. The
binary does the network I/O; the tool is a thin wrapper.

Submodule registration: importing this package triggers each submodule's
``@tool`` decorator, which registers the tool with the default
``ToolRegistry``. Mirrors the pattern used by ``opensquilla.tools.builtin``
itself.

Phase 2 (2026-06-14) shipped 5 submodules:
  - dns           (group:recon:dns)
  - port_scan     (group:recon:portscan)
  - http_probe    (group:recon:http)
  - dir_bust      (group:recon:http)
  - js_extract    (group:recon:http)

Batch 1 (2026-06-15) added 4 submodules:
  - webapp        (group:recon:webapp)
  - api           (group:recon:api)
  - component     (group:recon:component)
  - sensitive     (group:recon:sensitive)
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = (
    # Internal: not a tool, but a binary detector that the other
    # submodules import. Must be loaded first so detect_all() is
    # populated before any @tool runs.
    "_binaries",
    # Phase 2
    "dns", "port_scan", "http_probe", "dir_bust", "js_extract",
    # Batch 1
    "webapp", "api", "component", "sensitive",
    # Batch 2
    "auth", "header",
    # Batch 3
    "storage", "secret",
    # Batch 4
    "seed",
    # Batch 5
    "diff",
    # v4 (2026-06-17): batch port/subdomain/crawl/CVE tools that
    # prefer mature binaries (naabu/httpx/subfinder/katana/nuclei)
    # over single-step stdlib probes. These close the 51ifind.com
    # '13% port coverage' bug (84 ports reported, 14 ingested).
    "port_batch", "subdomain_enum", "katana_crawl", "nuclei_scan",
)

for _name in _SUBMODULES:
    import_module(f"{__name__}.{_name}")

__all__ = list(_SUBMODULES)
