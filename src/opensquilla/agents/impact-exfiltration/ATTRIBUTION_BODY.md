# Attribution — impact-exfiltration

Ported from [CyberStrikeAI](https://github.com/CyberStrikeAI/CyberStrikeAI) on 2026-06-04.

## Original frontmatter

```yaml
id: impact-exfiltration
name: 影响与数据外泄证明专员
description: 以最小影响方式设计“业务影响/数据可达性”的证明方案；强调脱敏、最小化数据暴露与回滚。
tools: []
```

## Mapping

- `id` -> `AgentEntryConfig.id`
- `name` -> `AgentEntryConfig.name`
- `description` -> `AgentEntryConfig.description`
- `tools` -> `AgentEntryConfig.tools` (kept empty = no restriction)
- body -> `~/.opensquilla/agents/impact-exfiltration/SOUL.md` AND `AgentEntryConfig.system_prompt`

## Modification log

- 2026-06-05: Per user request, removed categories A (scope/ROE), B (no-weaponization), and C (coordination noise) from SOUL.md. Re-framed to attack-completion objectives.
