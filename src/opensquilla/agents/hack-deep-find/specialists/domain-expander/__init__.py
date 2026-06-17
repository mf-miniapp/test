"""domain-expander specialist (v4, 2026-06-17).

Consolidates the v3 split between subdomain-discoverer / ip-resolver /
seed-expander into a single agent that takes a ROOT_DOMAIN node and
produces (a) subdomains, (b) IPs, and (c) extra seed hints in one
sessions_spawn call. The v3 trio had the same parent type, the same
tool groups (group:recon:dns + group:recon:seed), and a feedback loop
that was non-trivially hard to coordinate across three wave barriers.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
