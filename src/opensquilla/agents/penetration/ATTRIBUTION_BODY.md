# Attribution — penetration

Ported from [CyberStrikeAI](https://github.com/CyberStrikeAI/CyberStrikeAI) on 2026-06-04.

## Original frontmatter

```yaml
id: penetration
name: 渗透测试专员
description: 授权范围内的漏洞验证、利用链构造、权限提升与影响证明；在得到侦察/情报输入后做深度利用与复现。
tools: []
```

## Mapping

- `id` -> `AgentEntryConfig.id`
- `name` -> `AgentEntryConfig.name`
- `description` -> `AgentEntryConfig.description`
- `tools` -> `AgentEntryConfig.tools` (kept empty = no restriction)
- body -> `~/.opensquilla/agents/penetration/SOUL.md` AND `AgentEntryConfig.system_prompt`

## Modification log

- 2026-06-05: Per user request, removed categories A (scope/ROE), B (no-weaponization), and C (coordination noise) from SOUL.md. Re-framed to attack-completion objectives.
- 2026-06-15: penetration now consumes the consolidated `hunt-skill` (bundled at `src/opensquilla/skills/bundled/hunt-skill/SKILL.md`, replaces 5 prior hunt-sqli / hunt-ssrf / hunt-csrf / hunt-idor / hunt-business-logic skills + the hunt-skill-map index). The skill supplies: 5-class Crown Jewel + Attack Surface + Marker Sweep + Bypass Tables + Pattern Library rows that map directly into `TriageEvidence.disclosed_report_patterns[]` (W2) and `PentrationFinding.classification` + `ReproduceStep.command` (W4). The W4 specialist **MUST** read this skill before any PoC construction; it carries the canonical marker discipline (12-class sweep per class), the WAF/filter bypass tables, and the anti-patterns that the pentest contract forbids (first-class-stop, no-body-analysis, etc.). Owned by hack-deep (W4 attack chain); NOT callable from hack-deep-find (asset discovery) or hack-deep-ex (post-exploit) — those owners have their own skill sets (subdomain-discoverer / port-scanner / privesc / lateral etc.) and reference the same hunt-skill only via the post-exploit-complete-v1 handoff if a hunt is needed inside exfil.
