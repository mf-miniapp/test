"""Unified .env file loader — single source of truth for API keys.

Precedence (highest to lowest):
1. os.environ (already set by shell / CI)
2. .env in current working directory
3. ~/.opensquilla/.env (global user config)
4. Built-in defaults (BUILTIN_DEFAULTS) — hardcoded in this module

Existing environment variables are NEVER overridden.

Any module that needs its own hardcoded fallback can call
``register_default(key, value)`` at import time; the value will
be applied on the next ``load_env()`` call. Built-in defaults
make sure the install is usable out-of-the-box (e.g. ``ASSET_TREE_DB_URL``
points at the bundled local MySQL), while the override paths above
let power users rewire the connection string without editing source.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import MutableMapping

import structlog

from opensquilla.paths import default_opensquilla_home

log = structlog.get_logger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}
_PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")


# ── Built-in defaults ──────────────────────────────────────────────────
# These are the last-resort fallback. Anything in the .env files or
# os.environ overrides them. To change at runtime without editing
# source, set ASSET_TREE_DB_URL in ~/.opensquilla/.env.
#
# The MySQL URL matches the local Docker container started via the
# recipe in .env.example / docs (host port 3307 to avoid clashing
# with the common pre-existing MySQL on 3306).
_BUILTIN_DEFAULTS: MutableMapping[str, str] = {
    # AssetTree DB — points at the local MySQL container created by:
    #   docker run -d --name opensquilla-mysql -e MYSQL_ROOT_PASSWORD=opensquilla \
    #     -e MYSQL_DATABASE=opensquilla -e MYSQL_USER=opensquilla \
    #     -e MYSQL_PASSWORD=opensquilla -p 127.0.0.1:3307:3306 mysql:8.0
    "ASSET_TREE_DB_URL": "mysql+aiomysql://opensquilla:opensquilla@127.0.0.1:3307/opensquilla",
}

_defaults_lock = threading.Lock()


def register_default(key: str, value: str) -> None:
    """Register / overwrite a built-in default at runtime.

    Safe to call from any module's import-time code. Later calls win
    within the same process; the first ``load_env()`` after registration
    picks the value up.
    """
    with _defaults_lock:
        _BUILTIN_DEFAULTS[key] = value


def get_default(key: str) -> str | None:
    """Return the built-in default for ``key`` (or None)."""
    with _defaults_lock:
        return _BUILTIN_DEFAULTS.get(key)


def list_defaults() -> dict[str, str]:
    """Snapshot of the current built-in defaults (for ``opensquilla config``)."""
    with _defaults_lock:
        return dict(_BUILTIN_DEFAULTS)


def trust_env() -> bool:
    """Return True when opensquilla's httpx clients should honor env proxy/TLS vars.

    Gated by ``OPENSQUILLA_TRUST_ENV``. Off by default — opensquilla defaults to
    deterministic, env-isolated networking so a stray HTTP_PROXY in a parent
    shell cannot silently reroute agent traffic. Set ``OPENSQUILLA_TRUST_ENV=1``
    (e.g. in ~/.opensquilla/.env) to opt in; required on WSL2 / corporate networks
    where the only route to external APIs is a shell-exported proxy.
    """
    return os.environ.get("OPENSQUILLA_TRUST_ENV", "").strip().lower() in _TRUTHY


def warn_if_proxy_ignored() -> None:
    """Log a one-time hint if env has HTTP(S)_PROXY but trust_env is off."""
    if trust_env():
        return
    present = [v for v in _PROXY_ENV_VARS if os.environ.get(v)]
    if present:
        log.warning(
            "env.proxy_ignored",
            vars=present,
            hint="Set OPENSQUILLA_TRUST_ENV=1 to let opensquilla honor env proxy settings.",
        )


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file into a dict. Skips comments and blank lines."""
    if not path.is_file():
        return {}
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            entries[key] = value
    return entries


def load_env(cwd: str | Path | None = None) -> int:
    """Load .env files + built-in defaults into os.environ.

    Precedence (highest wins):
      1. os.environ (already set by shell / CI)
      2. cwd/.env
      3. cwd/.env.test
      4. ~/.opensquilla/.env
      5. Built-in defaults (BUILTIN_DEFAULTS)

    Returns the number of new variables injected.
    """
    candidates = []

    # 1. cwd/.env (or cwd/.env.test as alias for dev)
    work_dir = Path(cwd) if cwd else Path.cwd()
    for name in (".env", ".env.test"):
        candidates.append(work_dir / name)

    # 2. ~/.opensquilla/.env (global)
    candidates.append(default_opensquilla_home() / ".env")

    # Merge: first file wins per key, but os.environ always wins
    merged: dict[str, str] = {}
    sources: dict[str, str] = {}
    for path in candidates:
        for key, value in _parse_env_file(path).items():
            if key not in merged:
                merged[key] = value
                sources[key] = str(path)
                log.debug("env.loaded", key=key, source=str(path))

    # 3. Built-in defaults (lowest priority)
    with _defaults_lock:
        builtin_snapshot = dict(_BUILTIN_DEFAULTS)
    for key, value in builtin_snapshot.items():
        if key not in merged:
            merged[key] = value
            sources[key] = "<builtin default>"

    # Inject into os.environ — never override existing
    injected = 0
    for key, value in merged.items():
        if key not in os.environ:
            os.environ[key] = value
            log.info(
                "env.default_applied",
                key=key,
                source=sources.get(key, "<unknown>"),
            )
            injected += 1
        else:
            log.debug(
                "env.kept_existing",
                key=key,
                source=sources.get(key, "<unknown>"),
            )

    if injected:
        log.info("env.injected", count=injected)

    return injected
