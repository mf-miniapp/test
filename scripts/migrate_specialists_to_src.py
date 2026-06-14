"""Migrate specialist SOUL/ATTRIBUTION from runtime workspace to src package.

Source : ~/.opensquilla/agents/<name>/{SOUL,ATTRIBUTION}.md
Target : src/opensquilla/agents/<name>/{SOUL_BODY,ATTRIBUTION_BODY}.md + __init__.py

Mirrors the hack-deep/hack-deep-find/hack-deep-ex loader pattern:
  __init__.py exposes SOUL_BODY / ATTRIBUTION_BODY constants loaded one-shot
  at import time. Hyphen vs underscore: specialist names use underscores
  (no Python syntax conflict), so the package dir keeps the underscore form
  (recon, intel-collection, ...).

Idempotent: overwrites SOUL_BODY.md and ATTRIBUTION_BODY.md; aborts on
__init__.py conflict (--force to overwrite).
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# REPO_ROOT: --repo-root arg or cwd (so script can live in /tmp)
import os
REPO_ROOT = Path(os.environ.get("MIGRATE_REPO_ROOT", os.getcwd())).resolve()
SRC_BASE = REPO_ROOT / "src" / "opensquilla" / "agents"
RUNTIME_BASE = Path(os.environ.get("MIGRATE_RUNTIME_BASE", str(Path.home() / ".opensquilla" / "agents"))).resolve()

SPECIALISTS = (
    "recon",
    "intel-collection",
    "attack-surface-enumeration",
    "vulnerability-triage",
    "opsec-evasion",
    "penetration",
    "privilege-escalation",
    "lateral-movement",
    "persistence-maintenance",
    "impact-exfiltration",
    "cleanup-rollback",
    "reporting-remediation",
    "engagement-planning",
)

INIT_TEMPLATE = '''"""{name} specialist — loads SOUL_BODY / ATTRIBUTION_BODY for the clone script.

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
    from opensquilla.agents.{name} import SOUL_BODY
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
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="overwrite existing __init__.py if present")
    parser.add_argument("--dry-run", action="store_true",
                        help="print actions without touching the filesystem")
    parser.add_argument("--only", metavar="NAME",
                        help="migrate a single specialist (default: all 13)")
    args = parser.parse_args(argv)

    targets = [args.only] if args.only else list(SPECIALISTS)
    if args.only and args.only not in SPECIALISTS:
        print(f"ERROR: {args.only!r} is not in the 13-specialist list", file=sys.stderr)
        return 1

    for name in targets:
        runtime = RUNTIME_BASE / name
        src_pkg = SRC_BASE / name
        if not runtime.is_dir():
            print(f"  ! skip {name}: {runtime} not found")
            continue
        if not src_pkg.is_dir():
            print(f"  ! skip {name}: {src_pkg} missing — create it first")
            continue

        soul_src = runtime / "SOUL.md"
        attr_src = runtime / "ATTRIBUTION.md"
        soul_dst = src_pkg / "SOUL_BODY.md"
        attr_dst = src_pkg / "ATTRIBUTION_BODY.md"
        init_dst = src_pkg / "__init__.py"

        if not soul_src.exists() or not attr_src.exists():
            print(f"  ! skip {name}: runtime missing SOUL.md/ATTRIBUTION.md")
            continue

        if args.dry_run:
            print(f"  dry-run {name}:")
            print(f"    copy {soul_src} -> {soul_dst}")
            print(f"    copy {attr_src} -> {attr_dst}")
            if not init_dst.exists() or args.force:
                print(f"    write {init_dst}")
            else:
                print(f"    keep existing {init_dst}")
            continue

        shutil.copy2(soul_src, soul_dst)
        shutil.copy2(attr_src, attr_dst)
        print(f"  + {name}/SOUL_BODY.md  ({soul_dst.stat().st_size} bytes)")
        print(f"  + {name}/ATTRIBUTION_BODY.md  ({attr_dst.stat().st_size} bytes)")

        if not init_dst.exists() or args.force:
            init_dst.write_text(INIT_TEMPLATE.format(name=name), encoding="utf-8")
            print(f"  + {name}/__init__.py  (loader template)")
        else:
            print(f"  = {name}/__init__.py  (preserved; use --force to overwrite)")

    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
