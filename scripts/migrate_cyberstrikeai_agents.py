#!/usr/bin/env python3
"""Migrate CyberStrikeAI's agent personas (agents/*.md) to OpenSquilla durable agents.

Source : /Users/zlpc/data/zspace/hack/CyberStrikeAI/agents/<id>.md
        Frontmatter: id, name, description, tools, max_iterations
        Body:        persona system prompt (Chinese)
Target : ~/.opensquilla/agents/<id>/
          SOUL.md                — persona body
          ATTRIBUTION.md         — provenance
        ~/.opensquilla/config.toml
          [agents]               — registered via AgentRegistry

Each specialist becomes a durable agent that can be invoked by
``sessions_spawn(agent_id="<id>", task="...")``.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SRC_ROOT = Path("/Users/zlpc/data/zspace/hack/CyberStrikeAI/agents")
DST_ROOT = Path.home() / ".opensquilla" / "agents"
UPSTREAM = "https://github.com/CyberStrikeAI/CyberStrikeAI"


@dataclass(frozen=True)
class Agent:
    source_file: str
    agent_id: str
    name: str
    description: str
    tools_yaml: str  # raw YAML value of the `tools` frontmatter field


def split_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    header = text[3:end].strip()
    body = text[end + 4 :].lstrip("\n")
    fm: dict[str, str] = {}
    for line in header.splitlines():
        m = re.match(r"^([\w-]+)\s*:\s*(.*)$", line)
        if not m:
            continue
        fm[m.group(1)] = m.group(2).strip()
    return fm, body


def main() -> None:
    DST_ROOT.mkdir(parents=True, exist_ok=True)

    # Discover source files (skip sync-conflict duplicates)
    sources = sorted(
        p for p in SRC_ROOT.glob("*.md")
        if ".sync-conflict-" not in p.name
    )
    print(f"Found {len(sources)} source agent files")

    # Late imports (the registry needs the gateway config / paths)
    from opensquilla.agents.registry import AgentRegistry
    from opensquilla.onboarding.config_store import default_config_path, load_config, persist_config

    config_path = default_config_path()
    cfg = load_config(config_path)
    registry = AgentRegistry(cfg, config_path=config_path, persist_changes=False)

    written: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    for src in sources:
        text = src.read_text(encoding="utf-8")
        fm, body = split_frontmatter(text)
        agent_id = (fm.get("id") or src.stem).strip()
        name = (fm.get("name") or agent_id).strip()
        description = (fm.get("description") or "").strip()
        tools_yaml = (fm.get("tools") or "").strip()

        # The CyberStrikeAI `tools: []` means "no restriction" — keep empty.
        # If the source actually had a non-empty tools list, leave it as YAML.
        if tools_yaml in ("", "[]"):
            tools_value: Any = None
        else:
            tools_value = tools_yaml  # registry accepts str/list/dict

        workspace_dir = DST_ROOT / agent_id
        workspace_dir.mkdir(parents=True, exist_ok=True)

        # Build a SOUL.md that is the agent body verbatim, with a tiny header
        # pointing to the attribution and frontmatter summary.
        soul_body = body.rstrip() + "\n"
        soul_header = (
            f"# SOUL.md — {name} (agent_id={agent_id})\n\n"
            f"Persona ported from CyberStrikeAI on 2026-06-04.\n"
            f"Original frontmatter: id={agent_id!r} name={name!r}\n"
            f"Description: {description}\n"
            f"Source: {UPSTREAM}\n"
            f"See `ATTRIBUTION.md` for license + provenance.\n\n"
            f"---\n\n"
        )
        (workspace_dir / "SOUL.md").write_text(soul_header + soul_body, encoding="utf-8")
        (workspace_dir / "ATTRIBUTION.md").write_text(
            f"# Attribution — {agent_id}\n\n"
            f"Ported from [CyberStrikeAI]({UPSTREAM}) on 2026-06-04.\n\n"
            f"## Original frontmatter\n\n"
            f"```yaml\n"
            f"id: {agent_id}\n"
            f"name: {name}\n"
            f"description: {description}\n"
            f"tools: {tools_yaml or '[]'}\n"
            f"```\n\n"
            f"## Mapping\n\n"
            f"- `id` -> `AgentEntryConfig.id`\n"
            f"- `name` -> `AgentEntryConfig.name`\n"
            f"- `description` -> `AgentEntryConfig.description`\n"
            f"- `tools` -> `AgentEntryConfig.tools` (kept empty = no restriction)\n"
            f"- body -> `~/.opensquilla/agents/{agent_id}/SOUL.md` "
            f"AND `AgentEntryConfig.system_prompt`\n",
            encoding="utf-8",
        )

        # Register the agent. Skip if it already exists.
        try:
            async def _register() -> None:
                # Check existing
                agents = await registry.list_agents(include_builtin=False)
                existing_ids = {a.get("id") for a in agents}
                if agent_id in existing_ids:
                    raise ValueError("already exists")
                await registry.create_agent(
                    agent_id=agent_id,
                    name=name,
                    description=description or None,
                    workspace=str(workspace_dir),
                    tools=tools_value,
                    enabled=True,
                    system_prompt=soul_body,
                )

            asyncio.run(_register())
            written.append(agent_id)
            print(f"  + {agent_id:<30s}  {name}")
        except ValueError as exc:
            if "already exists" in str(exc):
                skipped.append(agent_id)
                print(f"  = {agent_id:<30s}  (already exists, skipped)")
            else:
                errors.append(f"{agent_id}: {exc}")
                print(f"  ! {agent_id:<30s}  ERROR: {exc}")
        except Exception as exc:
            errors.append(f"{agent_id}: {exc}")
            print(f"  ! {agent_id:<30s}  ERROR: {exc}")

    # Persist config
    print(f"\nPersisting config to {config_path}")
    persist_config(cfg, path=config_path, restart_required=True)
    print("Persisted.")

    # Final summary
    print(f"\n=== Summary ===")
    print(f"written : {len(written)}")
    print(f"skipped : {len(skipped)} (already existed)")
    if errors:
        print(f"errors  : {len(errors)}")
        for e in errors:
            print(f"  - {e}")


if __name__ == "__main__":
    main()
