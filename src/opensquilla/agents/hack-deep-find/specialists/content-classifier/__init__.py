"""content-classifier specialist (v4, 2026-06-17).

Consolidates static-asset + auth-mapper + cookie-header into a single
agent that takes one URL and returns all four cross-cutting concerns
(sensitive static files, auth surfaces, cookies, security headers)
in one HTTP-pass. The v3 trio all called recon_http_probe on the
same URL — fusing them eliminates 2 redundant HTTP round-trips per
URL and gives the LLM a single coherent view of one URL's posture.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
