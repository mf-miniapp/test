"""`opensquilla config env` — manage the built-in env defaults.

These are the last-resort fallback values that `load_env()` applies when
no shell var, no `.env` file, and no `~/.opensquilla/.env` set the key.
The defaults are hardcoded in ``opensquilla.env._BUILTIN_DEFAULTS`` so
the install is usable out-of-the-box; ``config env`` lets you see them
and write an override into ``~/.opensquilla/.env`` without editing
source.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from opensquilla.cli.ui import ACCENT_HEADER, ACCENT_MARKUP, console
from opensquilla.paths import default_opensquilla_home

app = typer.Typer(help="Manage built-in environment defaults (auto-loaded on every restart).")


def _user_env_path() -> Path:
    return default_opensquilla_home() / ".env"


def _read_user_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        if k:
            out[k] = v
    return out


@app.command("list")
def config_env_list() -> None:
    """Show every built-in default + the live value the running process sees."""
    from opensquilla.env import list_defaults

    defaults = list_defaults()
    user_env = _read_user_env(_user_env_path())
    table = Table(title="Built-in env defaults", show_header=True, header_style=ACCENT_HEADER)
    table.add_column("Key")
    table.add_column("Builtin default")
    table.add_column("Live value (this process)")
    table.add_column("Override path")
    for key, default in defaults.items():
        live = __import__("os").environ.get(key, "<unset>")
        override = user_env.get(key, "")
        src = "shell" if key in __import__("os").environ else (
            "~/.opensquilla/.env" if override else "(builtin)"
        )
        table.add_row(escape(key), escape(default), escape(live), escape(src))
    console.print(table)


@app.command("show")
def config_env_show(
    key: str = typer.Argument(..., help="Env var name, e.g. ASSET_TREE_DB_URL"),
) -> None:
    """Show one default: builtin value, live value, and override hint."""
    from opensquilla.env import get_default

    default = get_default(key)
    if default is None:
        console.print(f"[red]No built-in default for {escape(key)}[/red]")
        raise typer.Exit(1)
    import os as _os
    live = _os.environ.get(key, "<unset>")
    console.print(f"[{ACCENT_MARKUP}]{escape(key)}[/]")
    console.print(f"  builtin: [green]{escape(default)}[/green]")
    console.print(f"  live:    [bold]{escape(live)}[/bold]")


@app.command("set")
def config_env_set(
    key: str = typer.Argument(..., help="Env var name, e.g. ASSET_TREE_DB_URL"),
    value: str = typer.Argument(..., help="Value to write into ~/.opensquilla/.env"),
) -> None:
    """Persist an override into ``~/.opensquilla/.env`` (takes effect on next restart)."""
    path = _user_env_path()
    existing = _read_user_env(path)
    existing[key] = value
    lines = [f"{k}={v}" for k, v in existing.items()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[{ACCENT_MARKUP}]Wrote:[/] {path}")
    console.print(f"  [bold]{escape(key)}={escape(value)}[/bold]")
    console.print("[yellow]Restart the CLI / gateway to apply.[/yellow]")


@app.command("unset")
def config_env_unset(
    key: str = typer.Argument(..., help="Env var name to drop from ~/.opensquilla/.env"),
) -> None:
    """Remove a user override — built-in default takes over again."""
    path = _user_env_path()
    if not path.is_file():
        console.print(f"[dim]No {path} — nothing to unset.[/dim]")
        return
    existing = _read_user_env(path)
    if key not in existing:
        console.print(f"[dim]{escape(key)} is not in {path}.[/dim]")
        return
    existing.pop(key)
    if existing:
        path.write_text("\n".join(f"{k}={v}" for k, v in existing.items()) + "\n", encoding="utf-8")
    else:
        path.unlink()
    console.print(f"[{ACCENT_MARKUP}]Removed override for {escape(key)}.[/]")
    console.print("[yellow]Restart to fall back to the built-in default.[/yellow]")
