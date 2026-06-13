# hack-deep — Deep Attack Orchestrator

`hack-deep` is OpenSquilla's 4-layer × 11-wave attack-DAG coordinator
co-resident with the legacy `cyberstrike-deep`. It is materialised by
[`scripts/clone_cyberstrike_to_hack_deep.py`](../scripts/clone_cyberstrike_to_hack_deep.py)
and lives at `~/.opensquilla/agents/hack-deep/`.

This document is the top-level entry point. Detailed contracts live in
the agent's own `SOUL.md` and `ATTRIBUTION.md` (in the cloned workspace);
the Python dispatch implementation lives in
[`src/opensquilla/attack_dispatch/`](../src/opensquilla/attack_dispatch/).

---

## 1. Identity

| Field | Value |
| --- | --- |
| agent_id | `hack-deep` |
| Name | `Hack Orchestrator` |
| Workspace | `~/.opensquilla/agents/hack-deep/` |
| Co-coordinator | `cyberstrike-deep` (peer; never spawned) |
| Subordinate agents | 13 specialists (see §3) |
| Mandatory watchdog | `[subagent_supervisor] enabled = true` (auto-patched by clone script) |
| Source | Cloned from `cyberstrike-deep` on 2026-06-05; v3.1 frame on top |

## 2. 4-Layer × 15-Wave DAG (v4.0, 2026-06-11)

```
广度层 (Breadth) — "Find more doors + plan + crawl"
  W0    engagement-planning                                 single
  W0.5  target-expansion  (NEW 2026-06-07)                  static_fanout (3)
  W0.6  resource-checkpoint  (NEW 2026-06-10 R3, fail-open) static_fanout (3)
  W1    recon ‖ intel-collection ‖ attack-surface-enum      PARALLEL-3 (v4.0 default)
  W1.5  per-subdomain fan-out  (NEW 2026-06-07)             dynamic_fanout
  W1.5c expand scan  (NEW 2026-06-10 R1, conditional)       single
  W2    vulnerability-triage                                single
  W2.5  port attack plan  (NEW v4.0 R3, per-port + vector 拆) dynamic_fanout (bucket=6)
  W3    opsec-evasion                                       single
        (allows 2 in-wave sub-calls; no new wave name)
  W3.5  web crawl  (NEW v4.0 R4, 全 web service 并发爬虫)    dynamic_fanout (bucket=4)
  ↓ barrier
深度层 (Depth) — "Open the doors" (GATED)
  W4    penetration (sub-tracks DYNAMIC, count ≈ entry / 8) dynamic_fanout
  W5    privilege-escalation                                GATED — single
  W6    lateral-movement                                    GATED — single
  W7    persistence-maintenance ‖ impact-exfiltration       GATED — PARALLEL-2
  ↓ barrier
收口层 (Synthesis) — "Close + report"
  W8    cleanup-rollback ‖ reporting-remediation             PARALLEL-2
```

### 2.1 What's new in v4.0 (2026-06-11)

- **Parallel Mode default**: `DispatchMode.PARALLEL` is the new default
  (override of v3.2 SERIAL). Same wave 内允许一次 assistant message 发 N 个
  `sessions_spawn` 调用。SERIAL 保留为 opt-in (operator 显式 `mode=SERIAL`)
  给超大目标省 context window。
- **W2.5 port attack plan** (R3): dynamic_fanout bucket=6. 读
  `ReconEvidence.services` 生成 `PortAttackPlanEvidence`, 每个
  `PortAttackPlanEntry` 含 1+ `AttackVectorPlan` (per-port + vector 拆高复杂度,
  复用 `ExploitationTechnique` Literal 让 W4 sub-track 不用翻译)。fail-fast
  跳 W3 如果 services 为空。
- **W3.5 web crawl** (R4): dynamic_fanout bucket=4. 全部 web service 端口
  (vector_class=='web' 或 service in {http,https,http-alt,http-proxy}) 并发跑
  `katana + waybackurls + subjs + jsluice + feroxbuster` 递归。产出
  `WebCrawlEvidence` (hidden_paths / extracted_endpoints / auth_required_paths
  分别喂 W4 不同 vector_class)。fail-fast 跳 W4 如果无 web service。
- **Post-Exploitation Gate** (R5): W4 `PenetrationEvidence.footholds` 为空
  或全 ephemeral → executor 跳过 W5/W6/W7, 写 `gate_skipped=True` 占位 evidence,
  直跳 W8 reporting。W8 报告读 `gate_skipped` 渲染 "未入侵 → 仅暴露面总结" 分支。
  Gate 是 final 决定, 不允许 specialist 自己 retry W4。
- 2 new evidence schemas: `port-attack-plan-v1` + `web-crawl-v1` (EVIDENCE_SCHEMAS 16 → 18)
- 2 new waves: W2.5 + W3.5 (WAVES 13 → 15)
- Layer BREADTH 收纳 W3.5; COVERT 层清空 (W3 → BREADTH)

### 2.1 What's new in v3.1 (2026-06-07)

- **W0.5 target-expansion** — static fan-out of recon / intel / attack-surface
  against the *main* domain; produces a list of `SubTargetHandle` records
  (`sub_target_handle-v1` schema) keyed by subdomain. The executor flattens
  these into `state.target_queue` for W1.5.
- **W1.5 per-subdomain fan-out** — dynamic fan-out; bucket size = 8. W1.5
  re-runs the recon/intel/attack-surface triple *per subdomain*, so a domain
  with 16 subdomains spawns 2 recon sub-tracks.
- **Feedback loop** — W4 / W5 / W6 can declare newly-discovered subdomains /
  hidden services / pivots in their `emit_new_target: list[str]` field. The
  executor pushes these back to `state.target_queue` and records an
  `emit_new_target` drill-in spec for audit. The orchestrator (LLM) then
  re-spawns W1.5 against the new targets.
- **drill-in 4th reason class** — `emit_new_target` joins `swap_vector` /
  `swap_entry` / `expand_scan`. W1's drill-in slot names shifted to `W1.6a/b/c`
  (W1.5 is now a real wave).
- **drill-in merge semantics** — drill-in raws no longer overwrite the
  parent's evidence. They shallow-merge into `state.drill_in_overlay[parent_wave]`
  so the orchestrator can read what the drill-in found without losing the
  parent's record.
- **Peer attach** — on entry, `run()` calls `_try_attach_to_peer_deep(target)`.
  If `cyberstrike-deep` is already running the same target, the W0 evidence
  bundle is attached to `state.evidence["W0_peer_attach"]` so we don't redo
  ROE planning from scratch.
- **Rate-limit visibility** — `ReconEvidence.rate_limit_hits` and
  `PenetrationEvidence.rate_limit_hits` let the orchestrator see when a
  specialist hit a 429 / WAF and throttle the next wave.
- **Global finding view** — `ReportEvidence.global_finding_index: list[GlobalFinding]`
  cross-references the same vuln across multiple subdomains / ports. Fields:
  `entry_id / cvss / cve / affected_targets / fix_priority (P0|P1|P2|P3)`.
- **subagent_supervisor auto-enabled** — the clone script patches
  `[subagent_supervisor] enabled = true` so the watchdog cron is installed.
  See §5.

## 3. 13 specialists (subordinate)

| agent_id | evidence_schema | v3.1 fields |
| --- | --- | --- |
| `engagement-planning` | `roe-v1` | + `success_unit: per-port \| per-host \| per-domain` |
| `recon` | `recon-v1` | + `parent_domain`, `infra_sharing`, `rate_limit_hits` |
| `intel-collection` | `intel-v1` | (unchanged) |
| `attack-surface-enumeration` | `surface-v1` | (unchanged) |
| `vulnerability-triage` | `triage-v1` | (unchanged) |
| `opsec-evasion` | `opsec-v1` | + `per_target_group: [{group_id, strategy, stop_signal}]` |
| `penetration` | `pentest-v1` | + `rate_limit_hits`; dynamic sub-tracks |
| `privilege-escalation` | `privesc-v1` | (unchanged) |
| `lateral-movement` | `lateral-v1` | (reads `recon.infra_sharing` for cross-subdomain) |
| `persistence-maintenance` | `persist-v1` | (unchanged) |
| `impact-exfiltration` | `impact-v1` | (unchanged) |
| `cleanup-rollback` | `cleanup-v1` | (unchanged) |
| `reporting-remediation` | `report-v1` | + `per_target_finding`, `global_finding_index` |

`cyberstrike-deep` is **explicitly excluded** from the
`subagents.allow_agents` list.

## 4. Typed Task Envelope

Every `sessions_spawn(agent_id=<specialist>, task=<typed-envelope>)` call
**must** start with the 4-field header:

```
HANDOFF <handoff_id> | deps=<csv-or-"empty"> | schema=<evidence_schema> | eta=<seconds>

<natural-language brief>
```

| Field | Example | Validation |
| --- | --- | --- |
| `handoff_id` | `W1.recon.1` / `W4.5a` / `W0.5.recon.2` | regex `^\S+$` |
| `input_dependencies` | `W0.engagement-planning.1,W1.recon.1` or `empty` | csv |
| `evidence_schema` | `recon-v1` | must exist in `EVIDENCE_SCHEMAS` |
| `expected_runtime_s` | `180` | positive int |

Implementation: `src/opensquilla/attack_dispatch/envelope.py`.

## 5. subagent_supervisor (watchdog)

The 2026-06-05 hack-deep incident exposed a gap: when the primary announce
path's dedup set had been tripped by an earlier sibling, a terminal event
could be dropped on the floor. The supervisor is a 60-second cron that
scans every open spawn group and replays the announce for any child whose
terminal event was dropped. It reuses `_send_parent_wake` so dedup state
is shared with the primary path.

**Default state in OpenSquilla core**: `enabled = false` (opt-in).  
**hack-deep default**: `enabled = true` (auto-patched by clone).

To verify after a clone:
```bash
grep -A 1 "subagent_supervisor" ~/.opensquilla/config.toml
# expect: enabled = true
```

## 5.5 Serial Mode (v3.2, 2026-06-07) — 节省 LLM 上下文窗口

**问题**：v3.1 的 SOUL 合约写"同 wave 内:一次 assistant message 内多
`sessions_spawn` 调用 (fan-out)"。LLM 在 spawn 收口前必须把多个 specialist
的 raw 同时放在上下文里——大目标 (50+ subdomains, 200+ services) 会让
上下文窗口爆。

**v3.2 解决方案**：默认改用 **Serial Mode**——同一时间只有 1 个 specialist
在飞；每个 specialist 的 raw 在 executor 端**立刻落盘**到
`<artifact_root>/<wave>/<handoff_id>.json`，并通过
`context_reduction` 回调通知 LLM 把 raw 从上下文释放。

### 5.5.1 SOUL 合约变化

| 维度 | v3.1 (parallel) | v3.2 (serial, **默认**) |
| --- | --- | --- |
| 同 wave 内 sessions_spawn 数量 | N 个 (一次 assistant message) | **1 个** (发完立即 `sessions_yield`) |
| Wave 1 (3 specialist) 调用 | 三并行 | 三串行 (recon → intel → attack-surface) |
| Per-specialist 落盘 | 无 (合并 wave 末尾 1 个 JSON) | **有** (每个 specialist 1 个 JSON,合并 wave 末尾还有 1 个 `*.combined.json`) |
| LLM 上下文 raw 占用 | N 个 specialist 的 raw 同时在飞 | **1 个** specialist 的 raw 在飞,其余释放 |
| Drill-in (`.5a/b/c`) 落盘 | 仅内存 `state.raw_calls` | **每槽 1 个 JSON** under `<wave>.drill_in/` |

### 5.5.2 合约内容 (写到 hack-deep SOUL.md)

```
## Serial Mode (v3.2, 2026-06-07) — 默认
- 同 wave 内:一次 assistant message 只发 1 个 sessions_spawn 调用
  (W1 三并行 / W7 双并行 / W8 双并行都拆成 N 个 sequential spawn)
- 发完立即 sessions_yield() 等该 specialist 收口,再开下一个
- 每个 specialist 的 raw 在 executor 端立刻落盘到
  ~/.opensquilla/agents/hack-deep/memory/waves/<wave>/<handoff_id>.json
- context 释放:raw 落盘后,LLM 上下文只需保留 artifact_path + 一句话
  summary,原始 raw 释放
- 严禁:一次发 N 个 spawn (即使是 W1 三并行)
```

### 5.5.3 Python executor API

```python
from opensquilla.attack_dispatch import DispatchExecutor, DispatchMode

# 默认 (PARALLEL, 旧行为) — 不变,既有测试全过
ex = DispatchExecutor(specialist_fn=my_fn)

# Serial mode (v3.2 默认) — per-specialist 落盘 + context_reduction 回调
ex = DispatchExecutor(
    specialist_fn=my_fn,
    mode=DispatchMode.SERIAL,
    context_reduction=lambda wave, handoff, path, raw: release_from_ctx(raw),
)
```

### 5.5.4 on-disk 布局对比

```text
PARALLEL mode (v3.1):
  <root>/W1/W1.recon.1.json     # 合并 evidence (1 文件)

SERIAL mode (v3.2):
  <root>/W1/W1.recon.1.json                 # per-specialist (raw)
  <root>/W1/W1.intel-collection.2.json      # per-specialist (raw)
  <root>/W1/W1.attack-surface-enumeration.3.json  # per-specialist (raw)
  <root>/W1/W1.combined.json                # 合并 evidence + per_specialist_artifacts map
  <root>/W1.drill_in/W1.6a.json             # drill-in 槽 (若触发)
  <root>/W1.drill_in/W1.6b.json
  <root>/W1.drill_in/W1.6c.json
```

### 5.5.5 实测效果 (51ifind.com 压力测试)

- **Breadth 层 (W1)**:上下文窗口 raw 占用从 ~12000 tokens 降到 ~3500 tokens
  (3× 节省)
- **Depth 层 (W4)**:dynamic_fanout 从 6-8 个 penetration sub-tracks 减到
  1 个 in-flight;raw 占用线性下降
- **总开销**:每 wave 多 1-3 个小 JSON 文件 (5-50 KB each),对磁盘 IO
  不敏感
- **证据保真**:无丢失;每个 specialist 的 raw 都持久化,LLM 任何时候
  都可以 `cat <path>` 拉回

## 6. Tooling bundle (2026-06-07)

`hack-deep`'s recon and penetration specialists can call 9 + 23 = 32
modern attack tools via OpenSquilla's MANAGED skills layer. Skills live in
`~/.opensquilla/skills/<name>/SKILL.md`.

**Subdomain enumeration (9)**: `subfinder`, `assetfinder`, `chaos`,
`shuffledns`, `dnsx`, `httpx`, `subjack`, `cero`, `github-subdomains`.

**Web attack surface (23)**: `katana`, `jsluice`, `linkfinder`,
`xnLinkFinder`, `subjs`, `arjun`, `paramspider`, `x8`, `kiterunner`,
`graphql-introspector`, `clairvoyance`, `batchql`, `wsrepl`, `nomore403`,
`bypass-403`, `smuggler`, `h2csmuggler`, `wpscan`, `droopescan`, `xsstricky`,
`evilginx2`, `mobsf`, `objection`.

Bootstrap:
```bash
python scripts/add_subdomain_enum_skills.py
python scripts/add_web_attack_skills.py
```

Both scripts are idempotent. They write `SKILL.md` + `ATTRIBUTION.md` per
skill using the same schema as `scripts/migrate_cyberstrikeai_skills.py`.

## 7. Out of scope (intentional)

- **ROE enforcement** is not added; `ROEEvidence.success_unit` is a hint to
  the orchestrator, not a contract.
- **No nuclei** — no cve-mapping, no takeover template, no nuclei-based
  skills. `nuclei` is referenced only as a transitive bin in a small
  number of legacy ports (CyberStrikeAI migration).
- **`cyberstrike-deep` is never modified** by the clone script; it is
  verified to be byte-identical after the clone (see
  `test_cyberstrike_deep_entry_unchanged` in `test_hack_deep_clone.py`).
- **`subagent_contract.py` public API** is unchanged.

## 8. Files

| Path | Purpose |
| --- | --- |
| `~/.opensquilla/agents/hack-deep/SOUL.md` | Agent persona (full contract) |
| `~/.opensquilla/agents/hack-deep/ATTRIBUTION.md` | Provenance + 7 fix markers + modification log |
| `~/.opensquilla/agents/hack-deep/{AGENTS,IDENTITY,HEARTBEAT,MEMORY,TOOLS,USER}.md` | Pass-through from cyberstrike-deep with id / name substitution |
| `src/opensquilla/attack_dispatch/waves.py` | 11-wave DAG registry + drill-in slot table |
| `src/opensquilla/attack_dispatch/evidence.py` | 14 Pydantic v2 evidence schemas |
| `src/opensquilla/attack_dispatch/drill_in.py` | Thinness-driven decision + 4 reason classes |
| `src/opensquilla/attack_dispatch/executor.py` | Sync, testable, barrier-enforcing executor |
| `src/opensquilla/attack_dispatch/envelope.py` | Typed Task Envelope parser / renderer |
| `tests/test_attack_dispatch.py` | 78 unit tests; T1–T14 + T22 |
| `tests/test_hack_deep_clone.py` | Clone contract; T18 / T19 |
| `tests/test_hack_deep_soul_contract.py` | SOUL.md content pins |
| `scripts/clone_cyberstrike_to_hack_deep.py` | Bootstrap the agent |
| `scripts/add_subdomain_enum_skills.py` | 9 subdomain-enum skills |
| `scripts/add_web_attack_skills.py` | 23 web-attack skills |
| `docs/hack-deep.md` | This document |
