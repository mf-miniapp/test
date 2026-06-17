"""vuln-prioritizer specialist (v4.4, 2026-06-18).

Active CVE / vulnerability scan orchestrator. v4.4-NEW: prior to v4.4,
the nuclei binary was installed but had no specialist actively invoking
it. The recon_nuclei_scan tool was defined but never called from any
wave. This specialist gives nuclei a home in the F-final phase, so
discovered assets get an active vulnerability scan before the asset
tree is handed off to hack-deep.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
