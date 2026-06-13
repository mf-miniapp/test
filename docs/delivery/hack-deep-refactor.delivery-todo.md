# Delivery Todo: hack-deep 流程重构（默认并行 + 端口攻击计划 + Web 爬虫 + 后渗透条件跳过）

## 0. Requirement Log
| Req ID | Captured At | Source | Description | Round | Status | Origin File |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | 2026-06-11 | user: "默认并行模式" | hack-deep DispatchMode 默认 PARALLEL | 1 | in-progress | — |
| R2 | 2026-06-11 | user: "资产搜集阶段要做最全的资产收集" | W1 调全部 59 skill | 1 | in-progress | — |
| R3 | 2026-06-11 | user: "针对端口制定专业的攻击计划" | W2.5 per-port + vector 拆 | 1 | in-progress | — |
| R4 | 2026-06-11 | user: "针对web类端口或者web要使用爬虫技术发现路径" | W3.5 全 web port 爬虫 | 1 | in-progress | — |
| R5 | 2026-06-11 | user: "入侵成功后才进入后渗透阶段" | W4 gate 跳 W5/W6/W7 | 1 | in-progress | — |
| R6 | 2026-06-11 | user: "每个阶段都要做到最专业，最大限度的并发" | max concurrency fanout | 1 | in-progress | — |

## 0. Round Log
| Round | Theme | Captured At | Closed At | Validation | Worktree Δ | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | hack-deep 流程重构 (并行 + W2.5 + W3.5 + gate) | 2026-06-11 | — | TBD | TBD | in-progress |

## 1. Metadata
| Field | Value |
| --- | --- |
| Topic | hack-deep 流程重构 |
| Derived From | [hack-deep-refactor.delivery-solution.md](./hack-deep-refactor.delivery-solution.md) |
| Active Req IDs | R1, R2, R3, R4, R5, R6 |
| Execution Gate | ready-for-execution |
| Execution Mode | serial(Round 1: 5 T) → parallel(Round 2: 3 threads) → serial(Round 3 合闸) |
| Thread Budget | 3 |
| Last Updated | 2026-06-11 |

## 2. Todo Rows
| Todo ID | Solution ID | Task | Implementation Notes | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1 | executor.py: DispatchExecutor 默认 mode 改 PARALLEL | 改 `mode: DispatchMode = DispatchMode.PARALLEL` | test_default_mode_is_parallel | pending |
| T2 | S2 | waves.py: 注册 W2.5 wave + evidence.py: PortAttackPlanEvidence + AttackVectorPlan | deps=("W2","W1.5c"), fanout=dynamic_fanout | test_w2_5_registered + test_port_attack_plan_schema | pending |
| T3 | S3 | waves.py: 注册 W3.5 wave + evidence.py: WebCrawlEvidence + 改 LAYERS[BREADTH] | deps=("W2.5",), fanout=dynamic_fanout | test_w3_5_registered + test_web_crawl_evidence_schema | pending |
| T4 | S4 | executor.py: _check_foothold_gate + WaveResult.status 加 "skipped" + evidence.py PrivescEvidence/LateralEvidence/PersistEvidence/ImpactEvidence 加 gate_skipped 字段 | 兜底默认 False | test_post_exploit_gate_skip_when_no_foothold + test_post_exploit_gate_run_when_owned_foothold | pending |
| T5 | S5 | hack-deep SOUL.md: §Serial Mode → §Parallel Mode v4.0 + 加 W2.5/W3.5/Post-Exploitation Gate 4 段 | append-only | SOUL content pin test | pending |
| T6 | S6 | tests/test_attack_dispatch.py + test_hack_deep_soul_contract.py 增量 12 断言 + TestWaves.test_<N>_waves 更新 13→15 | 新增 12 个 test_ 函数 | pytest tests/test_attack_dispatch.py tests/test_hack_deep_soul_contract.py tests/test_recon_coverage.py -v | pending |
| T7 | S7 | docs/hack-deep.md §2 升级到 4-Layer × 15-Wave DAG + §2.1 What's new in v4.0 + §2.2 Post-Exploitation Gate | 沿用现有 markdown 风格 | grep "15-Wave" docs/hack-deep.md | pending |
| T8 | S8 | README.md Key Features 加 hack-deep v4.0 行: PARALLEL 默认 + W2.5 + W3.5 + gate | append-only | grep "hack-deep v4.0" README.md | pending |

## 3. Execution Loop Rules
1. **Round 1 (Serial Foundation)**: T1 → T2 → T3 → T4 → T5 (5 个 T 串行, 改 waves.py / evidence.py / executor.py 顺序敏感)
2. **Round 2 (Parallel 3-Thread)**:
   - **Thread A**: T6 tests 增量
   - **Thread B**: T7 docs/hack-deep.md 升级
   - **Thread C**: T8 README.md 增量
3. **Round 3 (Merge Gate)**: 全量回归 + final-review → decision=close
4. 任何线程发现共享文件冲突 → 立刻退回串行
5. 每个 T 完成后立即把 normalized todo 的 Status 从 `pending` 改为 `completed` 再开始下一个 T

## 4. Current Execution Snapshot
| Field | Value |
| --- | --- |
| Active Todo | T1 (Round 1 in-progress) |
| Active Req IDs | R1, R2, R3, R4, R5, R6 |
| Active Threads | serial |
| Approval Status | confirmed (用户已答 AskUserQuestion + 说"开干,一步到位") |
| Last Verified By | none (round 1 未开始) |
| Step Review | pending |
| Global Audit | pending |
| Remaining Before Stop | 8 个 todo (T1-T8) 全部待完成 |

## 5. Parallel Threads Plan

| Thread | Scope | Candidate Todos | Parallel Safety | Current Status |
| --- | --- | --- | --- | --- |
| Thread A | tests/test_attack_dispatch.py + test_hack_deep_soul_contract.py | T6 | high (新增函数,不冲突) | idle |
| Thread B | docs/hack-deep.md | T7 | high (独立文档) | idle |
| Thread C | README.md | T8 | high (独立段,append-only) | idle |

**Round 1 串行地基 (pre-parallel)**: T1-T5 — 改 executor.py + waves.py + evidence.py + SOUL.md (单线程串行, 顺序敏感)

**Round 2 并行启用条件**:
1. Round 1 全部 5 个 T 状态都是 `completed`
2. waves.py WAVES 字典含 15 个 entry
3. evidence.py EVIDENCE_SCHEMAS registry 含 18 个 schema
4. executor.py 默认 mode = DispatchMode.PARALLEL
5. hack-deep SOUL.md 含 "Parallel Mode (v4.0" + "W2.5 Port Attack Plan" + "W3.5 Web Crawl" + "Post-Exploitation Gate" 4 段
6. 任意线程发现冲突 → 退回串行

**Merge gate (Round 3 串行)**: 全量回归 (pytest tests/test_attack_dispatch.py tests/test_hack_deep_soul_contract.py tests/test_recon_coverage.py tests/test_engine/turn_runner/) + final-review。

## 6. Todo Cards

### T1. executor.py: DispatchExecutor 默认 PARALLEL
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 1) |
| Scope | src/opensquilla/attack_dispatch/executor.py |
| Current Slice | `def __init__(self, ..., mode: DispatchMode = DispatchMode.PARALLEL, ...)` |
| Definition of Done | 默认 mode 改 PARALLEL + 保留 SERIAL opt-in + 既有测试不破 |
| Required Validation | pytest tests/test_attack_dispatch.py -v (含 test_default_mode_is_parallel 新断言) |
| Step Review Focus | 不破坏既有 178 个 test_attack_dispatch 断言;SERIAL opt-in 路径仍 work |
| Remaining Gap | none |

### T2. waves.py + evidence.py: W2.5 + PortAttackPlanEvidence + AttackVectorPlan
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 1) |
| Scope | src/opensquilla/attack_dispatch/waves.py + evidence.py |
| Current Slice | (a) waves.py 加 W2.5 注册 + LAYERS[BREADTH] 加 "W2.5"; (b) evidence.py 加 AttackVectorPlan + PortAttackPlanEvidence + EVIDENCE_SCHEMAS 注册 "port-attack-plan-v1" |
| Definition of Done | W2.5 wave 在 WAVES 字典 + PortAttackPlanEvidence 可构造 + 既有测试不破 |
| Required Validation | pytest tests/test_attack_dispatch.py -v (含 test_w2_5_registered + test_port_attack_plan_schema 新断言) |
| Step Review Focus | AttackVectorPlan 复用 ExploitationTechnique Literal 不重复定义;PortAttackPlanEvidence evidence_schema Literal 加 "port-attack-plan-v1" |
| Remaining Gap | none |

### T3. waves.py + evidence.py: W3.5 + WebCrawlEvidence
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 1) |
| Scope | src/opensquilla/attack_dispatch/waves.py + evidence.py |
| Current Slice | (a) waves.py 加 W3.5 注册 + LAYERS[BREADTH] 加 "W3.5"; (b) evidence.py 加 WebCrawlEvidence + EVIDENCE_SCHEMAS 注册 "web-crawl-v1" |
| Definition of Done | W3.5 wave 在 WAVES 字典 + WebCrawlEvidence 可构造 + 既有测试不破 |
| Required Validation | pytest tests/test_attack_dispatch.py -v (含 test_w3_5_registered + test_web_crawl_evidence_schema 新断言) |
| Step Review Focus | crawl_tool_results: dict[str, list[str]] 不是 dict[str, Any];hidden_paths 字段上限 (LLM 取前 100) |
| Remaining Gap | none |

### T4. executor.py + evidence.py: W4 gate 跳过逻辑
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 1) |
| Scope | src/opensquilla/attack_dispatch/executor.py + evidence.py |
| Current Slice | (a) executor.py 加 _check_foothold_gate + WaveResult.status 加 "skipped" Literal + _run_wave 末尾检查; (b) evidence.py PrivescEvidence / LateralEvidence / PersistEvidence / ImpactEvidence 加 `gate_skipped: bool = False` |
| Definition of Done | W4 无 foothold → W5/W6/W7 标 skipped + gate_skipped=True + WaveResult.status="skipped" + state.errors 不增 |
| Required Validation | pytest tests/test_attack_dispatch.py -v (含 test_post_exploit_gate_skip_when_no_foothold + test_post_exploit_gate_run_when_owned_foothold) |
| Step Review Focus | 兜底默认 gate_skipped=False;executor 的 skipped 占位 evidence 用最小字段 (target + schema) |
| Remaining Gap | none |

### T5. hack-deep SOUL.md: Parallel Mode v4.0 + W2.5/W3.5/Gate 4 段
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 1) |
| Scope | ~/.opensquilla/agents/hack-deep/SOUL.md |
| Current Slice | (a) §Serial Mode v3.2 → §Parallel Mode v4.0; (b) §Attack Path → 4-Layer × 15-Wave DAG; (c) 加 §W2.5 Port Attack Plan + §W3.5 Web Crawl + §Post-Exploitation Gate 3 个新段 |
| Definition of Done | SOUL.md 含 4 段新内容 (grep 验证) + 不破坏既有内容 |
| Required Validation | grep -E "Parallel Mode \(v4.0|W2.5 Port Attack Plan|W3.5 Web Crawl|Post-Exploitation Gate" ~/.opensquilla/agents/hack-deep/SOUL.md |
| Step Review Focus | append-only,不覆盖既有 v3.2 段 (保留向后兼容);Post-Exploitation Gate 段明确 "无 foothold → 跳 W5/W6/W7" |
| Remaining Gap | none |

### T6. tests 增量 12 断言 + wave count 更新
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread A (Round 2 并行) |
| Scope | tests/test_attack_dispatch.py + tests/test_hack_deep_soul_contract.py |
| Current Slice | (a) test_default_mode_is_parallel + test_w2_5_registered + test_w3_5_registered + test_post_exploit_gate_skip_when_no_foothold + test_post_exploit_gate_run_when_owned_foothold + test_port_attack_plan_schema + test_web_crawl_evidence_schema (test_attack_dispatch.py); (b) SOUL content pins (test_hack_deep_soul_contract.py); (c) TestWaves.test_<N>_waves 13→15 |
| Definition of Done | 全部 12 新断言过 + wave count 断言更新 + 既有测试不破 |
| Required Validation | pytest tests/test_attack_dispatch.py tests/test_hack_deep_soul_contract.py -v |
| Step Review Focus | 容错:SOUL.md 不存在时 skip;容错:waves 数量断言取 R1+R3+新合并集合 |
| Remaining Gap | none |

### T7. docs/hack-deep.md §2 升级
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread B (Round 2 并行) |
| Scope | docs/hack-deep.md |
| Current Slice | (a) §2 "4-Layer × 11-Wave DAG" → "4-Layer × 15-Wave DAG (v4.0)"; (b) 加 §2.1 "What's new in v4.0" 段; (c) 加 §2.2 "Post-Exploitation Gate" 段 |
| Definition of Done | docs/hack-deep.md 含 15-Wave + v4.0 + Gate 段 |
| Required Validation | grep -E "15-Wave|v4.0|Post-Exploitation Gate" docs/hack-deep.md |
| Step Review Focus | 不破坏现有 markdown 结构;不动 §5 subagent_supervisor / §6 tooling / §7 out-of-scope / §8 files |
| Remaining Gap | none |

### T8. README.md Key Features 加 hack-deep v4.0 行
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread C (Round 2 并行) |
| Scope | README.md |
| Current Slice | 找 Key Features 段, 加一行: "hack-deep v4.0: PARALLEL 默认 + W2.5 端口攻击计划 + W3.5 Web 爬虫 + 后渗透条件跳过" |
| Definition of Done | README.md 含 hack-deep v4.0 行 |
| Required Validation | grep -E "hack-deep v4.0\|PARALLEL 默认\|W2.5\|W3.5" README.md |
| Step Review Focus | append-only, 不破坏现有 README 结构; 不动 SECURITY.md |
| Remaining Gap | none |

## 7. Round Order
1. **Round 1 (串行地基)**: T1 → T2 → T3 → T4 → T5 (改 executor.py + waves.py + evidence.py + SOUL.md 5 个核心代码文件)
2. **Round 2 (3 线程并行)**:
   - Thread A: T6 tests 增量
   - Thread B: T7 docs/hack-deep.md
   - Thread C: T8 README.md
3. **Round 3 (合闸串行)**: 全量回归 + final-review → decision=close

## 8. Validation Rules
- 每改一个文件就 grep 确认 import / 命名一致
- 每个 T 完成即跑对应单测, 不堆到 Round 3
- 任何新加 Pydantic 字段必须 Optional / 兜底默认
- 任何新加 Wave 必须不破坏既有 W0-W8 deps 拓扑 (含 W0.5 + W0.6 + W1.5 + W1.5c)
- Round 3 合闸必须全绿才能 final-review

## 9. Risks / Watchpoints
- **R4-R1**: PARALLEL 默认可能让大目标 context 溢出 → 保留 SERIAL opt-in (operator 显式设 mode)
- **R4-R2**: W2.5 per-port + vector 拆可能 fanout 暴涨 → bucket=6 限上限, 单 wave max 20 sub-track
- **R4-R3**: W3.5 web crawl 对 50+ web port 慢 → bucket=4 + per-sub-track timeout 300s
- **R4-R4**: W4 gate 跳 W5/W6/W7 时 specialist 不调, 但 LLM brief 已写 → brief 里加 `if gate_skip: return skipped` 兜底
- **R4-R5**: PortAttackPlanEvidence.success_probability LLM 估, 不准 → 只用于排序, 不作强制 gate
- **R4-R6**: WebCrawlEvidence.hidden_paths 量大 → LLM 取前 100 + 关键词过滤
- **R4-R7**: hack-deep SOUL.md v3.2 → v4.0 改名, cyberstrike-deep 不动 → 两个 agent 共存
- **R4-R8**: TestWaves.test_<N>_waves 断言 12→13→15 多次更新容易漏 → 在 T6 一次性更新到 15

## 10. Termination Checklist
- [ ] R1-R6 全部 completed
- [ ] Round 1 5 个 T 状态 `completed`
- [ ] Round 2 3 线程状态 `completed`
- [ ] Round 3 全量回归全绿 (test_attack_dispatch + test_hack_deep_soul_contract + test_recon_coverage)
- [ ] waves.py 含 15 wave
- [ ] evidence.py 含 18 schema (16 R1+R3 + 2 新: PortAttackPlanEvidence + WebCrawlEvidence)
- [ ] executor.py 默认 mode=PARALLEL
- [ ] hack-deep SOUL.md 含 Parallel Mode v4.0 + W2.5 + W3.5 + Post-Exploitation Gate 4 段
- [ ] docs/hack-deep.md §2 升级到 15-Wave + v4.0 段
- [ ] README.md Key Features 含 hack-deep v4.0 行
- [ ] 规范化 todo 全部 `completed`
- [ ] delivery-state.json current_status=complete + final_audit_status=passed