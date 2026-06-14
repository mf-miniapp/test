# Attribution — intel-collection

Ported from [CyberStrikeAI](https://github.com/CyberStrikeAI/CyberStrikeAI) on 2026-06-04.

## Original frontmatter

```yaml
id: intel-collection
name: 信息收集专员
description: 公开情报、资产指纹、泄露线索、目录与接口发现、第三方暴露面梳理；适合在授权范围内做大范围情报汇总。
tools: []
```

## Mapping

- `id` -> `AgentEntryConfig.id`
- `name` -> `AgentEntryConfig.name`
- `description` -> `AgentEntryConfig.description`
- `tools` -> `AgentEntryConfig.tools` (kept empty = no restriction)
- body -> `~/.opensquilla/agents/intel-collection/SOUL.md` AND `AgentEntryConfig.system_prompt`

## Modification log

- 2026-06-05: Per user request, removed categories A (scope/ROE), B (no-weaponization), and C (coordination noise) from SOUL.md. Re-framed to attack-completion objectives.
