"""Restart.sh must auto-detect libomp from common locations and export
``DYLD_LIBRARY_PATH`` so lightgbm (and any other OpenMP consumer) can
load ``@rpath/libomp.dylib`` without requiring the user to ``brew
install libomp`` first.

Tested shape:

  * The script declares a candidate list of libomp directories
    (caller override, project-level symlink, sklearn bundled,
    /opt/homebrew, /usr/local, /opt/local).
  * It walks the list and exports the first directory that contains
    ``libomp.dylib``.
  * It logs a clear ``libomp resolved from ...`` line at startup so
    operators can confirm the resolution.
  * It logs a graceful ``libomp not found`` warning when nothing
    matches (better than a silent fallback that lets lightgbm
    spam tracebacks).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

RESTART_SH = Path("restart.sh")


def _read_restart_sh() -> str:
    return RESTART_SH.read_text(encoding="utf-8")


def test_restart_sh_declares_libomp_candidate_list() -> None:
    src = _read_restart_sh()
    # Must include the standard system locations so a brew/MacPorts
    # install is picked up automatically.
    for path in (
        "/opt/homebrew/opt/libomp/lib",
        "/usr/local/opt/libomp/lib",
        "/opt/local/lib/libomp",
    ):
        assert path in src, f"missing libomp candidate: {path}"


def test_restart_sh_includes_sklearn_bundled_libomp() -> None:
    """The most reliable out-of-the-box source is the libomp that
    sklearn's wheel bundles — available even on a fresh machine with
    no system package manager.  The script must probe for it."""
    src = _read_restart_sh()
    assert "sklearn/.dylibs" in src


def test_restart_sh_exports_dyld_library_path() -> None:
    src = _read_restart_sh()
    # Must set the env var so the spawned python inherits it.
    assert "DYLD_LIBRARY_PATH" in src
    assert re.search(r"export\s+DYLD_LIBRARY_PATH=", src) is not None


def test_restart_sh_logs_libomp_resolution() -> None:
    src = _read_restart_sh()
    # Operator must be able to confirm at a glance which libomp got
    # picked, otherwise diagnosing a wrong-arch or stale install is
    # painful.
    assert "libomp resolved from" in src
    assert "libomp not found" in src


def test_restart_sh_is_still_valid_bash() -> None:
    """Bash syntax check (catches stray quotes / unclosed blocks)."""
    proc = subprocess.run(
        ["bash", "-n", str(RESTART_SH)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"bash -n failed: {proc.stderr.strip() or proc.stdout.strip()}"
    )


# ── lightgbm rpath self-heal ──────────────────────────────────


def test_restart_sh_documents_libomp_install_paths() -> None:
    """lib_lightgbm.dylib's hard-coded LC_RPATH entries point at
    /opt/homebrew/opt/libomp/lib and /opt/local/lib/libomp.  If those
    directories don't contain libomp.dylib, the gateway prints a
    warning on every boot.  The install is one of:

      1. ``brew install libomp``  (or any package manager equivalent)
         — this populates one of the rpath entries directly.
      2. The DYLD_LIBRARY_PATH probe in restart.sh — a fallback for
         binaries that don't have a matching rpath.

    restart.sh must mention both paths so the operator knows what to
    do when the warning appears.
    """
    src = _read_restart_sh()
    # Both system libomp locations are documented as candidates.
    assert "/opt/homebrew/opt/libomp/lib" in src
    assert "/opt/local/lib/libomp" in src
    # DYLD_LIBRARY_PATH is the fallback probe.
    assert "DYLD_LIBRARY_PATH" in src
