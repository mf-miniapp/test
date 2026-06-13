# Delivery Todo: hack-deep 全面优化（10 项，跳过 ROE + nuclei）

## 1. Metadata
| Field | Value |
| --- | --- |
| Topic | hack-deep 全面优化（10 项，跳过 ROE + nuclei） |
| Derived From | [hack-deep-comprehensive-optimization.delivery-solution.md](./hack-deep-comprehensive-optimization.delivery-solution.md) |
| Execution Gate | ready-for-execution |
| Execution Mode | parallel-active（Round 2 启用 3 线程；Round 1 / Round 3 串行） |
| Thread Budget | 3 |
| Last Updated | 2026-06-07 |

## 2. Todo Rows

| Todo ID | Solution ID | Task | Implementation Notes | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1 | waves.py: 注册 W0.5 target-expansion（static_fanout, evidence_schema=sub_target_handle-v1, deps=("W0",)） | 加 `WaveSpec` 字典项；`is_drill_in_allowed` 不变；`DRILL_IN_SLOTS` 不变 | tests/test_attack_dispatch.py::TestWaves::test_w0_5_registered | pending |
| T2 | S2 | waves.py: 注册 W1.5 per-subdomain fan-out（dynamic_fanout, deps=("W0.5",)） | 同上；fanout_agents 复用 recon/intel/attack-surface | tests/test_attack_dispatch.py::TestWaves::test_w1_5_registered | pending |
| T3 | S3 | evidence.py: ReconEvidence 加 `parent_domain: Optional[str] = None` 字段 | 兜底默认 None | tests/test_attack_dispatch.py::TestEvidence::test_recon_has_parent_domain | pending |
| T4 | S4 | evidence.py: 新增 SubTargetHandle schema | 字段：subdomain / parent_domain / status / discovered_at | tests/test_attack_dispatch.py::TestEvidence::test_sub_target_handle_construct | pending |
| T5 | S5 | evidence.py: ReconEvidence / PenetrationEvidence 加 `rate_limit_hits: int = 0` | 兜底默认 0 | tests/test_attack_dispatch.py::TestEvidence::test_rate_limit_hits_default | pending |
| T6 | S6 | evidence.py: ReportEvidence 加 `global_finding_index: list = []` | 兜底默认 [] | tests/test_attack_dispatch.py::TestEvidence::test_report_has_global_finding_index | pending |
| T7 | S7 | evidence.py: 新增 GlobalFinding schema | 字段：entry_id / cvss / cve / affected_targets / fix_priority | tests/test_attack_dispatch.py::TestEvidence::test_global_finding_construct | pending |
| T8 | S8 | drill_in.py: DrillInReason 加 EMIT_NEW_TARGET + reason_class 名 | 复用现有 enum 模式 | tests/test_attack_dispatch.py::TestDrillIn::test_emit_new_target_reason | pending |
| T9 | S9 | executor.py: DispatchState 加 drill_in_overlay + target_queue 字段 | `field(default_factory=dict)` / `field(default_factory=list)` | tests/test_attack_dispatch.py::TestExecutor::test_state_has_overlay_and_queue | pending |
| T10 | S10 | executor.py: WaveResult 加 drill_in_merged + drill_in_overlay 字段 | 同上 | tests/test_attack_dispatch.py::TestExecutor::test_wave_result_has_drill_in_merged | pending |
| T11 | S11 | executor.py: `_run_drill_slot` 末尾浅合并 raw 到 `state.drill_in_overlay[parent_wave]`，**不**覆盖父 evidence | dict.update 浅合并；保留父 evidence | tests/test_attack_dispatch.py::TestExecutor::test_drill_in_does_not_overwrite_parent | pending |
| T12 | S12 | executor.py: `_scan_emit_new_target(raw)` helper；raw 含 `emit_new_target: list[str]` 时把 target 推回 `state.target_queue` | helper 是 static method | tests/test_attack_dispatch.py::TestExecutor::test_scan_emit_new_target_pushes_to_queue | pending |
| T13 | S13 | executor.py: `_try_attach_to_peer_deep(target)` helper；查 `cyberstrike-deep` 同 target 跑（通过 session_manager.list_sessions + storage.get_agent_task） | 存在则读 peer evidence bundle | tests/test_attack_dispatch.py::TestExecutor::test_attach_to_peer_deep_when_running | pending |
| T14 | S14 | executor.py: `run()` 入口调 `_try_attach_to_peer_deep(target)`，结果写到 `state.evidence["W0_peer_attach"]` | barrier 之前 | tests/test_attack_dispatch.py::TestExecutor::test_run_attaches_peer_evidence_to_w0 | pending |
| T15 | S15 | scripts/add_subdomain_enum_skills.py：9 个 skill（subfinder / assetfinder / chaos / shuffledns / dnsx / httpx / subjack / cero / github-subdomains） | 沿用 `scripts/migrate_cyberstrikeai_skills.py` 的 schema；幂等；落 `~/.opensquilla/skills/<name>/` | 脚本可独立运行 + 落盘 9 个 SKILL.md | pending |
| T16 | S16 | scripts/add_web_attack_skills.py：22 个 skill（katana / jsluice / linkfinder / xnLinkFinder / subjs / arjun / paramspider / x8 / kiterunner / graphql-introspector / clairvoyance / batchql / wsrepl / nomore403 / bypass-403 / smuggler / h2csmuggler / wpscan / droopescan / xsstricky / evilginx2 / mobsf / objection） | 同 T15 schema | 脚本可独立运行 + 落盘 22 个 SKILL.md | pending |
| T17 | S17 | recon / penetration specialist SOUL.md 工具清单追加新 bins（运行时写 `~/.opensquilla/agents/<id>/SOUL.md`） | append-only，不覆盖既有内容 | tests/test_hack_deep_*.py 验证 SOUL.md 含新 bins | pending |
| T18 | S18 | scripts/clone_cyberstrike_to_hack_deep.py: `_register_in_config` 末尾自动 patch `~/.opensquilla/config.toml` 的 `[subagent_supervisor] enabled = true` | 用 tomli/tomli-w 或 toml 读写；找不到段就追加 | tests/test_hack_deep_clone.py 加断言 | pending |
| T19 | S19 | hack-deep ATTRIBUTION.md 记录 S18 自动开启 | append modification log | tests/test_hack_deep_clone.py 加断言 | pending |
| T20 | S20 | docs/hack-deep.md：4 层 9 波示意图、Typed Envelope、drill-in、supervisor、timeline、新波 W0.5/W1.5 + 反馈环 | 新建文件 | 文件存在 + 内容完整 | pending |
| T21 | S21 | 主 README.md 加一行 + 链接到 docs/hack-deep.md | 追加单行 + 链接 | grep README.md 含 "hack-deep" | pending |
| T22 | S22 | tests/test_attack_dispatch.py 全部单测通过（含 T1-T14 新增） | 全部 23 项 | `pytest tests/test_attack_dispatch.py -v` 全绿 | pending |
| T23 | S23 | tests/test_hack_deep_*.py / test_subagent_result_marker.py / test_routing_fix.py / test_subagent_supervisor.py / test_architecture_import_contracts.py 全部通过 | 回归 | `pytest tests/test_hack_deep_*.py tests/test_subagent_result_marker.py tests/test_routing_fix.py tests/test_gateway/test_subagent_supervisor.py tests/test_ci/test_architecture_import_contracts.py -v` 全绿 | pending |

## 3. Execution Loop Rules
1. Round 1 (Foundation): T1-T14 全部在 `waves.py` / `evidence.py` / `drill_in.py` / `executor.py` 改，**串行**；完成一个 T 就跑对应单测，not 留到 Round 3。
2. Round 2 (Parallel): 拆 3 线程。Thread A 跑 T15-T17；Thread B 跑 T18-T21；Thread C 跑 T22。各自本地验证。
3. Round 3 (Merge Gate): T23 全量回归测试。
4. 任何线程发现共享文件冲突 → 立刻退回串行。
5. 每个 T 完成后立即把 normalized todo 的 Status 从 `pending` 改为 `completed` 再开始下一个 T。

## 4. Current Execution Snapshot
| Field | Value |
| --- | --- |
| Active Todo | none（Round 0 等待开始） |
| Active Threads | none |
| Approval Status | confirmed（用户已说"开始"） |
| Last Verified By | none |
| Step Review | pending |
| Global Audit | pending |
| Remaining Before Stop | 23 个 todo（T1-T23）全部待完成 |

## 5. Parallel Threads Plan

| Thread | Scope | Candidate Todos | Parallel Safety | Current Status |
| --- | --- | --- | --- | --- |
| Thread A | scripts/add_*.py + recon/penetration SOUL.md | T15 T16 T17 | high（不与 B/C 共享文件） | idle |
| Thread B | scripts/clone_*.py + docs/ + README.md | T18 T19 T20 T21 | high（不与 A/C 共享文件） | idle |
| Thread C | tests/test_attack_dispatch.py 跑全 23 项单测 | T22 | high（只读 + 跑 pytest） | idle |

**Round 1 串行地基（pre-parallel）**：T1-T14 全部在 `waves.py` / `evidence.py` / `drill_in.py` / `executor.py` 改，单线程串行。

**Round 2 并行启用条件**：
1. Round 1 全部 14 个 T 状态都是 `completed`。
2. `pytest tests/test_attack_dispatch.py -v` 全绿。
3. 三个线程无文件竞争：Thread A 改 `scripts/add_*.py` + `~/.opensquilla/agents/recon/SOUL.md` + `~/.opensquilla/agents/penetration/SOUL.md` + `~/.opensquilla/skills/<name>/`；Thread B 改 `scripts/clone_cyberstrike_to_hack_deep.py` + `docs/hack-deep.md` + `README.md` + 运行时 `~/.opensquilla/config.toml` + `~/.opensquilla/agents/hack-deep/ATTRIBUTION.md`；Thread C 只读 + 跑 pytest。三方无交集。
4. 任意线程发现冲突 → 退回串行。

**Merge gate（Round 3 串行）**：T23 全量回归测试。

## 6. Todo Cards

### T1. waves.py: 注册 W0.5 target-expansion
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/waves.py |
| Current Slice | 加 WaveSpec 注册项 W0.5 |
| Definition of Done | WAVES["W0.5"] 可读 + is_drill_in_allowed(W0.5) == False + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestWaves::test_w0_5_registered -v` |
| Step Review Focus | deps 拓扑不破坏 W1..W8 既有 deps |
| Remaining Gap | none |

### T2. waves.py: 注册 W1.5 per-subdomain fan-out
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/waves.py |
| Current Slice | 加 WaveSpec 注册项 W1.5（dynamic_fanout） |
| Definition of Done | WAVES["W1.5"] 可读 + fanout == "dynamic_fanout" + deps=("W0.5",) + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestWaves::test_w1_5_registered -v` |
| Step Review Focus | dynamic_fanout 走 SUB_TRACK_BUCKET_SIZE 同款逻辑 |
| Remaining Gap | none |

### T3. evidence.py: ReconEvidence 加 parent_domain
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/evidence.py |
| Current Slice | 在 ReconEvidence 加 Optional[str] 字段 |
| Definition of Done | 字段存在 + 兜底 None + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestEvidence::test_recon_has_parent_domain -v` |
| Step Review Focus | extra=forbid 仍兼容 |
| Remaining Gap | none |

### T4. evidence.py: 新增 SubTargetHandle schema
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/evidence.py |
| Current Slice | 新增 Pydantic BaseModel |
| Definition of Done | SubTargetHandle 可构造 + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestEvidence::test_sub_target_handle_construct -v` |
| Step Review Focus | 字段命名与 recon-v1 一致 |
| Remaining Gap | none |

### T5. evidence.py: 加 rate_limit_hits
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/evidence.py |
| Current Slice | ReconEvidence + PenetrationEvidence 各加 int 字段 |
| Definition of Done | 字段存在 + 兜底 0 + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestEvidence::test_rate_limit_hits_default -v` |
| Step Review Focus | 默认值是 0 不让既有测试爆 |
| Remaining Gap | none |

### T6. evidence.py: ReportEvidence 加 global_finding_index
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/evidence.py |
| Current Slice | 加 list 字段 |
| Definition of Done | 字段存在 + 兜底 [] + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestEvidence::test_report_has_global_finding_index -v` |
| Step Review Focus | 默认空 list |
| Remaining Gap | none |

### T7. evidence.py: 新增 GlobalFinding schema
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/evidence.py |
| Current Slice | 新增 Pydantic BaseModel |
| Definition of Done | GlobalFinding 可构造 + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestEvidence::test_global_finding_construct -v` |
| Step Review Focus | fix_priority 用 Literal["P0","P1","P2","P3"] |
| Remaining Gap | none |

### T8. drill_in.py: DrillInReason 加 EMIT_NEW_TARGET
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 1） |
| Scope | src/opensquilla/attack_dispatch/drill_in.py |
| Current Slice | DrillInReason enum 加新值；DRILL_IN_REASONS 同步 |
| Definition of Done | EMIT_NEW_TARGET 可用 + 单测过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestDrillIn::test_emit_new_target_reason -v` |
| Step Review Focus | 不破坏现有 a/b/c 决策路径 |
| Remaining Gap | none |

### T9-T14. executor.py 改动
T9-T14 全部改 executor.py，串行做：
- T9: DispatchState 加新字段
- T10: WaveResult 加新字段
- T11: `_run_drill_slot` 浅合并
- T12: `_scan_emit_new_target` helper
- T13: `_try_attach_to_peer_deep` helper
- T14: `run()` 入口调 attach

每个 T 完成 → 跑对应单测 → 状态 completed → 进下一个。

### T15. scripts/add_subdomain_enum_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread A（Round 2 并行） |
| Scope | scripts/add_subdomain_enum_skills.py + ~/.opensquilla/skills/<9 names>/ |
| Current Slice | 9 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 9 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_subdomain_enum_skills.py` 跑通 + ls `~/.opensquilla/skills/` |
| Step Review Focus | 沿用 migrate_cyberstrikeai_skills.py 同 schema |
| Remaining Gap | none |

### T16. scripts/add_web_attack_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread A（Round 2 并行） |
| Scope | scripts/add_web_attack_skills.py + ~/.opensquilla/skills/<22 names>/ |
| Current Slice | 22 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 22 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_web_attack_skills.py` 跑通 |
| Step Review Focus | 同 T15 |
| Remaining Gap | none |

### T17. recon / penetration SOUL.md 工具清单追加
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread A（Round 2 并行） |
| Scope | ~/.opensquilla/agents/recon/SOUL.md + ~/.opensquilla/agents/penetration/SOUL.md |
| Current Slice | 找"工具清单"段 append 新 bins 列表 |
| Definition of Done | SOUL.md 包含新 bins + 不破坏既有内容 |
| Required Validation | tests/test_hack_deep_*.py 新断言 |
| Step Review Focus | append-only 不覆盖 |
| Remaining Gap | none |

### T18-T19. scripts/clone_cyberstrike_to_hack_deep.py 改动 + ATTRIBUTION
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread B（Round 2 并行） |
| Scope | scripts/clone_cyberstrike_to_hack_deep.py + ~/.opensquilla/config.toml + ~/.opensquilla/agents/hack-deep/ATTRIBUTION.md |
| Current Slice | T18 patch [subagent_supervisor] enabled；T19 append modification log |
| Definition of Done | 跑脚本后 enabled=true + ATTRIBUTION.md 含 modification log + 单测过 |
| Required Validation | tests/test_hack_deep_clone.py 新断言 |
| Step Review Focus | 不影响 cyberstrike-deep |
| Remaining Gap | none |

### T20. docs/hack-deep.md
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread B（Round 2 并行） |
| Scope | docs/hack-deep.md |
| Current Slice | 4 层 9 波示意图、Typed Envelope、drill-in、supervisor、timeline、W0.5/W1.5 + 反馈环 |
| Definition of Done | 文件存在 + 含必要章节 |
| Required Validation | 文件存在 + grep hack-deep 关键词 |
| Step Review Focus | 文档与代码一致 |
| Remaining Gap | none |

### T21. README.md 加链接
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread B（Round 2 并行） |
| Scope | README.md |
| Current Slice | 找合适位置插一行 + 链接到 docs/hack-deep.md |
| Definition of Done | README.md 含 hack-deep 链接 |
| Required Validation | grep README.md "hack-deep" |
| Step Review Focus | 不破坏 README 现有结构 |
| Remaining Gap | none |

### T22. tests/test_attack_dispatch.py 跑全 23 项
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread C（Round 2 并行） |
| Scope | tests/test_attack_dispatch.py |
| Current Slice | 跑 pytest -v |
| Definition of Done | 全绿 |
| Required Validation | `pytest tests/test_attack_dispatch.py -v` |
| Step Review Focus | 新增单测全部通过 |
| Remaining Gap | none |

### T23. 全量回归
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial（Round 3 merge gate） |
| Scope | tests/test_hack_deep_*.py + tests/test_subagent_result_marker.py + tests/test_routing_fix.py + tests/test_gateway/test_subagent_supervisor.py + tests/test_ci/test_architecture_import_contracts.py |
| Current Slice | 跑全套 pytest |
| Definition of Done | 全绿 |
| Required Validation | `pytest tests/test_hack_deep_*.py tests/test_subagent_result_marker.py tests/test_routing_fix.py tests/test_gateway/test_subagent_supervisor.py tests/test_ci/test_architecture_import_contracts.py -v` |
| Step Review Focus | 不破坏既有契约 |
| Remaining Gap | none |

## 7. Round Order
1. **Round 1（串行地基）**：T1-T14。改 waves/evidence/drill_in/executor 同一组文件；每个 T 完成后单测过、状态 completed。
2. **Round 2（3 线程并行）**：
   - Thread A：T15 → T16 → T17（先 skill 脚本，再 SOUL.md）
   - Thread B：T18 → T19 → T20 → T21（clone 脚本 → 文档）
   - Thread C：T22（test_attack_dispatch 跑全）
3. **Round 3（合闸串行）**：T23 全量回归。
4. **Final Review**：T22 T23 全绿 → `decision=close` → 写入 delivery-state.json。

## 8. Validation Rules
- 每改一个文件就 grep 确认 import / 命名一致
- 每个 T 完成即跑对应单测，不堆到 Round 3
- 任何新加 Pydantic 字段必须 Optional / 兜底默认
- 任何新加 Wave 必须不破坏既有 W0-W8 deps 拓扑
- Round 3 合闸必须全绿才能 final-review

## 9. Risks / Watchpoints
- **R1**：extra=forbid 的 EvidenceBase，新加字段必须用 Optional + 默认值，否则既有测试爆
- **R2**：dispatch_executor 的 `WAVES` 是 dict-like，新加波需保证 deps 拓扑正确
- **R3**：hack-deep SOUL.md / config.toml / skills/ 是运行时文件，测试要读真路径 → 需要 Round 3 前先跑过 clone 脚本 + add_skill 脚本
- **R4**：executor.py 改 _run_drill_slot 不破坏现有 drill-in 单测（test_drill_in_does_not_overwrite_parent 需新增）
- **R5**：Thread A 写 SOUL.md 是运行时 IO，测试需要 tolerant（路径不存在时 skip）

## 10. Termination Checklist
- [ ] Round 1 全部 14 个 T 状态 `completed`
- [ ] Round 2 全部 9 个 T 状态 `completed`
- [ ] Round 3 全部 1 个 T 状态 `completed`
- [ ] tests/test_attack_dispatch.py 全绿
- [ ] tests/test_hack_deep_*.py / test_subagent_result_marker.py / test_routing_fix.py / test_subagent_supervisor.py / test_architecture_import_contracts.py 全绿
- [ ] scripts/add_subdomain_enum_skills.py 可独立运行
- [ ] scripts/add_web_attack_skills.py 可独立运行
- [ ] scripts/clone_cyberstrike_to_hack_deep.py 跑过后 config.toml 含 `subagent_supervisor.enabled = true`
- [ ] docs/hack-deep.md 存在
- [ ] README.md 含 hack-deep 链接
- [ ] 规范化 todo 全部 `completed`
- [ ] delivery-state.json current_status=complete + final_audit_status=passed
