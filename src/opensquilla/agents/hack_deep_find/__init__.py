"""hack-deep-find runtime contract templates.

v1.0 (2026-06-14): the SOUL.md and ATTRIBUTION.md content for the
hack-deep-find agent.

This subpackage moves both contracts to first-class ``.md`` files
and re-exports them as Python strings so the clone script keeps its
current import shape. The .md files are the source of truth — edit
those, not the strings here.

Loading is one-shot at module import: ``SOUL_BODY`` and
``ATTRIBUTION_BODY`` are read from the sibling ``.md`` files and
cached as module-level constants. If you need to hot-reload during
development, call :func:`reload` explicitly.

Public surface
--------------

  ``SOUL_BODY``  — full markdown body written to
                    ``~/.opensquilla/agents/hack-deep-find/SOUL.md`` by
                    the clone script.
  ``ATTRIBUTION_BODY`` — full markdown body written to
                    ``~/.opensquilla/agents/hack-deep-find/ATTRIBUTION.md``.
  ``reload()``    — re-read both files; used by tests
                    (``tests/agents/test_hack_deep_find_contracts.py``).
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

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
