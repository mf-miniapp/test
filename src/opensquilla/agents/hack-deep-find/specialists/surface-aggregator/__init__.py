"""surface-aggregator specialist (v4, 2026-06-17).

New specialist that closes the gap between asset discovery and the
attack phase. Reads the AssetTree at F-final and produces an
attack-priority-v1 evidence: a sorted list of "exploitable surfaces"
that the hack-deep W2 vulnerability-triage specialist consumes
directly. The v3 attack-surface-enumeration legacy agent produced
free-text "attack surface" prose; v4 produces a typed evidence that
matches the WaveSpec contract.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
