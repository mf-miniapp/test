"""AssetTree tools for the hack-deep-find LLM-coordinator.

These tools are policy-gated under ``group:asset_tree`` (see
``opensquilla.tools.policy_config``). Only the ``hack-deep-find`` agent
should be allowed to call them — recon specialists are NOT given this
group. Specialists return their findings via HANDOFF envelopes; the
LLM-coordinator uses these tools to mutate the persistent AssetTree.

Persistence: every mutating tool reads → mutates → writes back the tree
to ``~/.opensquilla/state/asset_trees/<tree_id>.json`` so the tree
survives LLM context eviction and concurrent specialist sessions.
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = ("tree",)

for _name in _SUBMODULES:
    import_module(f"{__name__}.{_name}")

__all__ = list(_SUBMODULES)