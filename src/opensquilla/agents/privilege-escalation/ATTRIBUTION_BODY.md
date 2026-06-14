# Attribution — privilege-escalation

Ported from [CyberStrikeAI](https://github.com/CyberStrikeAI/CyberStrikeAI) on 2026-06-04.

## Original frontmatter

```yaml
id: privilege-escalation
name: 权限提升专员
description: 在已获得初始访问/受限权限的前提下，评估权限提升可能性、证据需求与安全验证方法（仅限授权环境）。
tools: []
```

## Mapping

- `id` -> `AgentEntryConfig.id`
- `name` -> `AgentEntryConfig.name`
- `description` -> `AgentEntryConfig.description`
- `tools` -> `AgentEntryConfig.tools` (kept empty = no restriction)
- body -> `~/.opensquilla/agents/privilege-escalation/SOUL.md` AND `AgentEntryConfig.system_prompt`

## Modification log

- 2026-06-05: Per user request, removed categories A (scope/ROE), B (no-weaponization), and C (coordination noise) from SOUL.md. Re-framed to attack-completion objectives.
