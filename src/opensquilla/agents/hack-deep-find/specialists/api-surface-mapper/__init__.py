"""api-surface-mapper specialist (v4, 2026-06-17).

Consolidates api-surface + parameter-extract into a single agent that
takes one URL and produces (a) API_SCHEMA nodes, (b) ENDPOINT nodes,
and (c) PARAMETER nodes in one wave barrier. The v3 split forced
parameter-extract to wait for api-surface to write API_SCHEMA nodes
back to the AssetTree (so the schema_id could be linked on each
endpoint), which added an extra wave barrier for a read-only
continuation.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
