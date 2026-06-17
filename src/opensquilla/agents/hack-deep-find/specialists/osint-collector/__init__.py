"""osint-collector specialist (v4, 2026-06-17).

Preserves the v3 intel-collection agent's external-source breadth
(Shodan / Censys / FOFA / ZoomEye / Hunter / VirusTotal) that the
in-tree 16 specialists did not cover. v4 unifies it under the
hack-deep-find specialist contract so the asset tree can record
osint-v1 evidence natively. The legacy intel-collection agent
remains installed for backward compat (Tier 2 fallback).
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
