"""Recon tools for hack-deep-find specialists.

These tools are policy-gated under ``group:recon:*`` namespaces
(see ``opensquilla.tools.policy_config``). Only recon specialists
and the ``hack-deep-find`` LLM-coordinator (for endpoint reachability
verification only) are allowed to call them.

Implementation note: tools prefer Python stdlib (``asyncio.open_connection``,
``asyncio.getaddrinfo``) over shelling out to ``curl`` / ``nmap`` so they
remain pure data-plane calls and avoid the sandbox approval pipeline.

Submodule registration: importing this package triggers each submodule's
``@tool`` decorator, which registers the tool with the default
``ToolRegistry``. Mirrors the pattern used by ``opensquilla.tools.builtin``
itself.
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = ("dns", "port_scan", "http_probe", "dir_bust", "js_extract")

for _name in _SUBMODULES:
    import_module(f"{__name__}.{_name}")

__all__ = list(_SUBMODULES)