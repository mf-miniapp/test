"""Tests for the built-in env defaults registered in opensquilla.env.

These lock in the contract:
- Defaults are injected when no shell / .env / ~/.opensquilla/.env value exists.
- Higher-priority sources always win.
- load_env() is idempotent across simulated restarts.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _scrub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make sure no test process inherits ASSET_TREE_DB_URL."""
    monkeypatch.delenv("ASSET_TREE_DB_URL", raising=False)


def test_builtin_defaults_registered() -> None:
    from opensquilla.env import get_default, list_defaults

    defaults = list_defaults()
    assert "ASSET_TREE_DB_URL" in defaults
    assert defaults["ASSET_TREE_DB_URL"].startswith("mysql+aiomysql://")
    assert get_default("ASSET_TREE_DB_URL") == defaults["ASSET_TREE_DB_URL"]


def test_load_env_applies_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    from opensquilla.env import load_env

    assert "ASSET_TREE_DB_URL" not in os.environ
    n = load_env()
    assert n >= 1
    assert os.environ.get("ASSET_TREE_DB_URL", "").startswith("mysql+aiomysql://")


def test_shell_export_wins_over_builtin(monkeypatch: pytest.MonkeyPatch) -> None:
    from opensquilla.env import load_env

    shell_value = "mysql+aiomysql://shell:test@db.example:3306/squilla"
    monkeypatch.setenv("ASSET_TREE_DB_URL", shell_value)
    load_env()
    assert os.environ["ASSET_TREE_DB_URL"] == shell_value


def test_user_env_file_wins_over_builtin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from opensquilla import env as env_mod
    from opensquilla.env import load_env

    user_home = tmp_path / "opensquilla"
    user_home.mkdir()
    user_env = user_home / ".env"
    user_env.write_text(
        "ASSET_TREE_DB_URL=mysql+aiomysql://userfile:pw@10.0.0.5:3306/prod\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(env_mod, "default_opensquilla_home", lambda: user_home)

    load_env()
    assert os.environ["ASSET_TREE_DB_URL"] == "mysql+aiomysql://userfile:pw@10.0.0.5:3306/prod"


def test_load_env_is_idempotent_across_restarts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate the process exiting and re-launching: default must fire again."""
    from opensquilla.env import load_env

    for _ in range(3):
        monkeypatch.delenv("ASSET_TREE_DB_URL", raising=False)
        load_env()
        assert os.environ.get("ASSET_TREE_DB_URL", "").startswith("mysql+aiomysql://")


def test_register_default_extends_builtin(monkeypatch: pytest.MonkeyPatch) -> None:
    from opensquilla import env as env_mod

    env_mod.register_default("OPENSQUILLA_TEST_FAKE", "v1")
    assert env_mod.get_default("OPENSQUILLA_TEST_FAKE") == "v1"
    env_mod.load_env()
    assert os.environ.get("OPENSQUILLA_TEST_FAKE") == "v1"


def test_register_default_override(monkeypatch: pytest.MonkeyPatch) -> None:
    from opensquilla import env as env_mod

    original = env_mod.get_default("ASSET_TREE_DB_URL")
    env_mod.register_default("ASSET_TREE_DB_URL", "mysql+aiomysql://override:o@h:3306/x")
    assert env_mod.get_default("ASSET_TREE_DB_URL") == "mysql+aiomysql://override:o@h:3306/x"
    env_mod.load_env()
    assert os.environ["ASSET_TREE_DB_URL"] == "mysql+aiomysql://override:o@h:3306/x"
    # restore so other tests see the original
    env_mod.register_default("ASSET_TREE_DB_URL", original)
