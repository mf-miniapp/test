"""hack-deep-ex runtime contract templates.

v1.0 (2026-06-15): the SOUL.md and ATTRIBUTION.md content for the
hack-deep-ex agent. hack-deep-ex is the **post-exploitation** owner
in the 3-harness split (see ``opensquilla.attack_dispatch.waves``):

  hack-deep-find : asset discovery only (W0.5 W1 W1.5 W1.5c W2.5 W3.5)
  hack-deep      : attack only          (W0 W1.6* W2 W3 W4 W4.5*)
  hack-deep-ex   : post-exploitation    (W5 W6 W6.5* W7 W8)

This subpackage moves the hack-deep-ex contract to first-class
``.md`` files and re-exports them as Python strings so the clone
script keeps its current import shape. The .md files are the source
of truth — edit those, not the strings here.

Public surface
--------------

  ``SOUL_BODY``  — full markdown body written to
                    ``~/.opensquilla/agents/hack-deep-ex/SOUL.md`` by
                    the clone script.
  ``ATTRIBUTION_BODY`` — full markdown body written to
                    ``~/.opensquilla/agents/hack-deep-ex/ATTRIBUTION.md``.
  ``reload()``    — re-read both files; used by tests.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent

SOUL_BODY: str = ""
ATTRIBUTION_BODY: str = ""


def _load() -> None:
    """One-shot load of the two contract .md files."""
    global SOUL_BODY, ATTRIBUTION_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")
    ATTRIBUTION_BODY = (_HERE / "ATTRIBUTION_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    """Re-read both files; used by tests."""
    _load()


# Eagerly load at import time.
_load()


__all__ = ["SOUL_BODY", "ATTRIBUTION_BODY", "reload"]
