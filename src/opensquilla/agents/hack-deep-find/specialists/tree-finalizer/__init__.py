"""tree-finalizer specialist (v4.5 rename, 2026-06-18).

v4 -> v4.5 rename: surface-aggregator -> tree-finalizer.

Rationale: surface-aggregator produced attack-priority-v1 evidence with
exploitability_score / CVE linkage / specialist recommendations. That
crossed the line — hack-deep-find's contract is "discover every asset
and verify it is real", not "rank attack surfaces". The v4.5 rename
narrows the output to asset-tree-v1 (coverage report + URL liveness
recheck). Nuclei, CVE correlation, and priority ranking are explicitly
left to hack-deep W2 (vulnerability-triage).

v3 -> v4 -> v4.5 lineage:
  - v3 attack-surface-enumeration (legacy, free-text prose, in tree)
  - v4 surface-aggregator    (typed evidence, but with attack scoring)
  - v4.5 tree-finalizer       (typed evidence, no attack scoring)
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
