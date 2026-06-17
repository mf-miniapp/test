"""Centralized management of external recon binaries.

v4 (2026-06-17) hardening: recon tools prefer mature industry-standard
binaries (naabu, httpx, subfinder, katana, nuclei, nmap) over
single-step stdlib probes. The stdlib path is the FALLBACK only.

This module exposes:
  - BinaryPath namedtuple (path / version / available)
  - detect_all() -> dict[str, BinaryPath]
  - prefer(binary_name, stdlib_fn, *args, **kwargs) -> result
    Runs the binary if available, otherwise the stdlib function.

v3 era constraint (see ``__init__.py``): "tools prefer Python stdlib
(``asyncio.open_connection``, ``asyncio.getaddrinfo``, ``urllib.request``)
over shelling out to ``curl`` / ``nmap`` so they remain pure data-plane
calls and avoid the sandbox approval pipeline."

v4 reverses this constraint. The reason: 51ifind.com run on
2026-06-17 showed the stdlib path produced 13% port coverage
(14/84 ports ingested) because stdlib's per-port asyncio probe
was too slow for the LLM to wait for. naabu binary scans 65k
ports in 10 seconds. Speed matters; stdlib is the fallback.

Sandbox safety: the tools invoking these binaries pass
``capture_output=True`` and parse JSON. No shell, no eval, no
network from the tool itself — the binary does the network.
The tool is a thin wrapper.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


@dataclass(frozen=True)
class BinaryPath:
    """Resolved path + availability + version of a recon binary."""
    name: str
    path: str | None  # absolute path or None
    version: str | None  # `binary --version` first line, or None
    available: bool  # True iff shutil.which() found it AND --version worked

    def __bool__(self) -> bool:  # truthy when available
        return self.available


def _safe_version(binary: str, version_flag: str = "--version") -> str | None:
    """Run ``binary --version`` and return first non-empty line, or None.

    Never raises — always returns None on failure. Use this to test
    that a binary actually runs (some hosts have stale PATH entries
    pointing to non-functional binaries).
    """
    try:
        result = subprocess.run(
            [binary, version_flag],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        out = (result.stdout or result.stderr or "").strip()
        return out.splitlines()[0] if out else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


# Each binary: (name, version_flag)
# version_flag is what the binary accepts to print a version line.
_TRACKED_BINARIES: tuple[tuple[str, str], ...] = (
    ("naabu", "-version"),       # naabu uses -version not --version
    ("httpx", "-version"),
    ("subfinder", "-version"),
    ("katana", "-version"),
    ("nuclei", "-version"),
    ("nmap", "-version"),
    ("masscan", "--version"),
    ("ffuf", "-version"),
    ("dnsx", "-version"),
    ("asnmap", "-version"),
    ("tlsx", "-version"),
    ("cdncheck", "-version"),
)


_BINARY_CACHE: dict[str, BinaryPath] | None = None


def detect_all(refresh: bool = False) -> dict[str, BinaryPath]:
    """Detect all tracked recon binaries on PATH.

    Returns a dict keyed by binary name. Cached after first call;
    pass ``refresh=True`` to re-detect.
    """
    global _BINARY_CACHE
    if _BINARY_CACHE is not None and not refresh:
        return _BINARY_CACHE
    out: dict[str, BinaryPath] = {}
    for name, vflag in _TRACKED_BINARIES:
        path = shutil.which(name)
        version = _safe_version(name, vflag) if path else None
        out[name] = BinaryPath(
            name=name,
            path=path,
            version=version,
            available=path is not None and version is not None,
        )
    _BINARY_CACHE = out
    return out


def detect(name: str, refresh: bool = False) -> BinaryPath:
    """Detect a single binary. Convenience wrapper around detect_all."""
    return detect_all(refresh).get(name) or BinaryPath(
        name=name, path=None, version=None, available=False,
    )


async def _run_binary(
    argv: list[str],
    timeout_s: float = 60.0,
) -> tuple[int, str, str]:
    """Run a binary asynchronously. Returns (returncode, stdout, stderr).

    Uses asyncio subprocess so we don't block the event loop. We do
    NOT use shell=True — argv is a literal list.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return (
        proc.returncode or 0,
        stdout_b.decode("utf-8", errors="ignore"),
        stderr_b.decode("utf-8", errors="ignore"),
    )


async def prefer(
    binary_name: str,
    stdlib_fn: Callable[..., Awaitable[Any]],
    binary_argv_builder: Callable[[], list[str]],
    *,
    timeout_s: float = 60.0,
    parse_binary_output: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Run binary if available, else fall back to stdlib.

    Returns a dict with:
      - "source": "binary" | "stdlib"
      - "binary_path": str | None
      - "binary_version": str | None
      - "data": the result (parsed from binary stdout, or stdlib result)

    Args:
        binary_name: name of the binary (must be in _TRACKED_BINARIES).
        stdlib_fn: zero-arg async callable to run on fallback.
        binary_argv_builder: zero-arg callable that returns argv list.
        timeout_s: subprocess timeout.
        parse_binary_output: optional callable to parse binary stdout
            into a structured value. If None, returns raw stdout string.
    """
    bp = detect(binary_name)
    if bp.available:
        try:
            rc, stdout, stderr = await _run_binary(
                binary_argv_builder(), timeout_s=timeout_s,
            )
            if rc != 0:
                # Binary failed; fall back.
                data = await stdlib_fn()
                return {
                    "source": "stdlib",
                    "binary_path": bp.path,
                    "binary_version": bp.version,
                    "binary_error": stderr.strip().splitlines()[0] if stderr else None,
                    "data": data,
                }
            data = parse_binary_output(stdout) if parse_binary_output else stdout
            return {
                "source": "binary",
                "binary_path": bp.path,
                "binary_version": bp.version,
                "data": data,
            }
        except (asyncio.TimeoutError, OSError) as exc:
            data = await stdlib_fn()
            return {
                "source": "stdlib",
                "binary_path": bp.path,
                "binary_version": bp.version,
                "binary_error": f"{type(exc).__name__}: {exc}",
                "data": data,
            }
    else:
        data = await stdlib_fn()
        return {
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "binary_error": f"{binary_name!r} not on PATH",
            "data": data,
        }
