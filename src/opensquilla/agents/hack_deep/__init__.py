"""hack-deep runtime contract templates.

v3.2 (2026-06-07): the SOUL.md and ATTRIBUTION.md content for the
hack-deep agent used to live as 230+60 line triple-quoted strings inline
in ``scripts/clone_cyberstrike_to_hack_deep.py``. That made the
contract:

  - impossible to syntax-highlight as markdown in editors
  - polluting the diff when a single sentence changed
  - un-lintable (no markdown linter could run on it)
  - locked into a Python-source layout that other consumers
    (e.g. a future ``opensquilla doctor`` tool, or a runtime
    contract verifier) couldn't read

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
                    ``~/.opensquilla/agents/hack-deep/SOUL.md`` by
                    the clone script.
  ``ATTRIBUTION_BODY`` — full markdown body written to
                    ``~/.opensquilla/agents/hack-deep/ATTRIBUTION.md``.
  ``reload()``    — re-read both files; used by tests and the
                    ``opensquilla doctor`` tool.

Layout
------

  ``SOUL_BODY.md``         — hack-deep persona + serial mode + W4
                              sub-track contract (v3.2)
  ``ATTRIBUTION_BODY.md``  — 13 evidence_schema reference table +
                              7 fix markers + v3.1/v3.2 modification
                              log
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name: str) -> str:
    """Read a sibling ``.md`` file as UTF-8 text.

    Trailing whitespace is normalized to a single newline (POSIX
    text-file convention) so the clone script's ``write_text`` call
    doesn't introduce CRLF artifacts on the runtime file.
    """
    path = _HERE / name
    return path.read_text(encoding="utf-8").rstrip("\n") + "\n"


# Module-level constants. These are the public surface — callers should
# import them like ``from opensquilla.agents.hack_deep import SOUL_BODY``.
SOUL_BODY: str = _load("SOUL_BODY.md")
ATTRIBUTION_BODY: str = _load("ATTRIBUTION_BODY.md")


def reload() -> None:
    """Re-read both .md files into the module-level constants.

    Mostly useful in tests and during development; production code
    does not need this — the strings are immutable for the
    process's lifetime.
    """
    global SOUL_BODY, ATTRIBUTION_BODY
    SOUL_BODY = _load("SOUL_BODY.md")
    ATTRIBUTION_BODY = _load("ATTRIBUTION_BODY.md")


__all__ = ["SOUL_BODY", "ATTRIBUTION_BODY", "reload"]
