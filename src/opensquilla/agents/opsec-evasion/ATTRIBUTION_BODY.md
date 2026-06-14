# Attribution — opsec-evasion

Ported from [CyberStrikeAI](https://github.com/CyberStrikeAI/CyberStrikeAI) on 2026-06-04.

## Original frontmatter

```yaml
id: opsec-evasion
name: 运维安全与干扰最小化专员
description: 从测试噪声、可观测性、蓝队告警与回滚风险角度，设计“低干扰验证策略”和证据采集方式（不提供绕过手段）。
tools: []
```

## Mapping

- `id` -> `AgentEntryConfig.id`
- `name` -> `AgentEntryConfig.name`
- `description` -> `AgentEntryConfig.description`
- `tools` -> `AgentEntryConfig.tools` (kept empty = no restriction)
- body -> `~/.opensquilla/agents/opsec-evasion/SOUL.md` AND `AgentEntryConfig.system_prompt`

## Modification log

- 2026-06-05: Per user request, removed categories A (scope/ROE), B (no-weaponization), and C (coordination noise) from SOUL.md. Re-framed to attack-completion objectives.
