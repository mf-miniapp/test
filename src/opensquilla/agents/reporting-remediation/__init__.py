"""reporting-remediation specialist — loads SOUL_BODY / ATTRIBUTION_BODY for the clone script.

The 13 specialist packages under ``opensquilla.agents`` are the *templates*
shipped with the repo; the runtime artifacts (memory/, evidence dumps,
ad-hoc notes) live under ``~/.opensquilla/agents/<name>/`` and are
generated/refreshed by the clone scripts (``scripts/clone_*.py``).

Loading is one-shot at module import: ``SOUL_BODY`` and ``ATTRIBUTION_BODY``
are read from sibling ``.md`` files.

Why split SOUL_BODY.md (template) from SOUL.md (runtime):
  - editors can syntax-highlight and linters can validate the template
  - diffs stay small when only runtime evidence is updated
  - the clone script can selectively refresh either layer

Public API:
  ``SOUL_BODY``          — full markdown body for the LLM system prompt
  ``ATTRIBUTION_BODY``   — evidence_schema + provenance for the orchestrator
  ``reload()``           — re-read both .md files from disk (for tests)

Use like:
    from opensquilla.agents.reporting-remediation import SOUL_BODY
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(filename: str) -> str:
    return (_HERE / filename).read_text(encoding="utf-8")


SOUL_BODY: str = _load("SOUL_BODY.md")
ATTRIBUTION_BODY: str = _load("ATTRIBUTION_BODY.md")


def reload() -> None:
    """Re-read SOUL_BODY.md / ATTRIBUTION_BODY.md from disk."""
    global SOUL_BODY, ATTRIBUTION_BODY
    SOUL_BODY = _load("SOUL_BODY.md")
    ATTRIBUTION_BODY = _load("ATTRIBUTION_BODY.md")


__all__ = ["SOUL_BODY", "ATTRIBUTION_BODY", "reload"]
