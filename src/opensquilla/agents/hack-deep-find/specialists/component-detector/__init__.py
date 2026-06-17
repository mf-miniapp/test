"""component-detector specialist (v4, 2026-06-17).

Renamed from service-detailed. v4 keeps the same scope (SERVICE ->
COMPONENT) but uses a v4-canonical name (component-detector focuses
on the output type). The v3 service-detailed/ directory stays on
disk for reference; the clone script does not register it in
config.toml.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
