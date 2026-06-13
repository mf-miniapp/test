# Delivery Todo: hack-deep 串行模式重构 (v3.2, 2026-06-07)

## 1. Metadata
| Field | Value |
| --- | --- |
| Topic | hack-deep 串行模式重构 (v3.2) |
| Derived From | [hack-deep-serial-mode.delivery-solution.md](./hack-deep-serial-mode.delivery-solution.md) |
| Execution Gate | ready-for-execution |
| Execution Mode | serial-foundation (Round 1) → parallel-3-thread (Round 2) → merge-gate-serial (Round 3) |
| Thread Budget | 3 |
| Last Updated | 2026-06-07 |

## 2. Todo Rows

| Todo ID | Solution ID | Task | Implementation Notes | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1 | executor.py: `class DispatchMode(str, Enum)` (`PARALLEL` | `SERIAL`) | enum + docstring | import + `TestSerialMode` 全过 | completed |
| T2 | S2 | executor.py: `__init__` 加 `mode` / `context_reduction` 参数 | 默认值保持兼容 | 既有测试全过 | completed |
| T3 | S3 | executor.py: `DispatchState` 加 `released_handoff_ids` / `specialist_artifacts` | `field(default_factory=...)` | `test_serial_mode_state_records_released_handoff_ids` | completed |
| T4 | S4 | executor.py: `WaveResult` 加 `mode` / `specialist_artifacts` | 默认 PARALLEL | 既有 20 测试不破 | completed |
| T5 | S5 | executor.py: `run_wave` 拆为 `_run_wave_parallel` + `_run_wave_serial` | 顶部 mode 分流 | 既有 + 新测试 | completed |
| T6 | S6 | executor.py: `_run_wave_serial` 主循环 per-specialist 落盘 | specialist_fn → 写 JSON → callback | 7 个 TestSerialMode | completed |
| T7 | S7 | executor.py: `_write_specialist_artifact` helper | 形状对齐合并文件但 `specialist_calls=1` | 同 T6 | completed |
| T8 | S8 | executor.py: `_write_artifact` 加 `per_specialist_artifacts` / `mode` 参数 | SERIAL 模式合并文件改名 `<wave>.combined.json` | `test_serial_mode_combined_artifact_references_per_specialist` | completed |
| T9 | S9 | executor.py: `_artifact_path_for` 加 drill-in slot 名检测 | DRILL_IN_SLOTS 检测；legacy ".5" 子串兜底 | `test_serial_mode_drill_in_persists_per_slot_artifact` | completed |
| T10 | S10 | executor.py: `_run_drill_slot` SERIAL 模式 per-slot 落盘 | callback + state.specialist_artifacts | 同 T9 | completed |
| T11 | S11 | `__init__.py` 导出 `DispatchMode` | import + __all__ | import 成功 | completed |
| T12 | S12 | `clone_*.py`: SOUL_BODY 改 "Serial Mode (v3.2)" 段 | 替换 Parallel Logic 段 | `test_soul_documents_serial_mode_section` | completed |
| T13 | S13 | `clone_*.py`: ATTRIBUTION_BODY 加 v3.2 modification log | 末尾追加 | `test_attribution_documents_serial_mode_modification` | completed |
| T14 | S14 | `docs/hack-deep.md` 加 §5.5 "Serial Mode (v3.2)" | 5 子节：问题/SOUL 合约/Python API/on-disk 布局/实测 | 文件存在 + grep "Serial Mode" | completed |
| T15 | S15 | `tests/test_attack_dispatch.py` 加 `TestSerialMode` (8 测试) | 8 测试在 `tmp_path` 下 | `pytest tests/test_attack_dispatch.py::TestSerialMode -v` 全绿 (8/8) | completed |
| T16 | S16 | `tests/test_hack_deep_soul_contract.py` 加 4 测试 | SOUL/ATTRIBUTION 子串断言 | `pytest tests/test_hack_deep_soul_contract.py -v` 全绿 (67/67) | completed |
| T17 | S17 | `README.md` Key Features 行加 v3.2 描述 | 1 行替换 | grep README.md "v3.2" | completed |

## 3. Execution Loop Rules
1. Round 1 全部 4 个 T 状态都 `completed`。
2. `pytest tests/test_attack_dispatch.py -v` 全绿 (96/96)。
3. 三个 Round 2 线程无文件竞争：tests 不动 shared lib；clone 脚本只动 SOUL_BODY/ATTRIBUTION_BODY；docs/README/soul-contract-test 互不干扰。
4. 任何线程发现共享文件冲突 → 立刻退回串行。
5. 每个 T 完成后立即把状态从 `pending` 改为 `completed` 再开始下一个。

## 4. Current Execution Snapshot
| Field | Value |
| --- | --- |
| Active Todo | none (全部 17 个 T 已完成) |
| Active Threads | none |
| Approval Status | confirmed |
| Last Verified By | Round 3 T12-T15 |
| Step Review | passed |
| Global Audit | passed |
| Remaining Before Stop | none — 全部 17 个 T 状态 `completed` |

## 5. Parallel Threads Plan

| Thread | Scope | Candidate Todos | Parallel Safety | Current Status |
| --- | --- | --- | --- | --- |
| Thread A | tests | T15 T16 | high (tests 不动 lib/clone/docs) | completed |
| Thread B | SOUL 合约 | T12 T13 | high (clone 脚本 inline 字符串) | completed |
| Thread C | 文档 | T14 T17 | high (docs/ + README/ + test 互不干扰) | completed |

**Round 1 串行地基**：T1-T11 全部在 `executor.py` / `__init__.py` 改，单线程串行。

**Round 2 并行启用条件**：1. Round 1 全部 11 个 T 状态 `completed`。2. `pytest tests/test_attack_dispatch.py -v` 全绿 (96/96)。3. 三线程无文件竞争。

**Merge gate (Round 3 串行)**：T12-T15 全量回归测试 + clone 落盘验证 + 手工核查清单。

## 6. Todo Cards

### T1. executor.py: DispatchMode 枚举
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | serial (Round 1) |
| Scope | src/opensquilla/attack_dispatch/executor.py |
| Current Slice | enum + module-level 导出 |
| Definition of Done | enum 可导入 + 既有 88 测试全过 |
| Required Validation | `pytest tests/test_attack_dispatch.py -v` |
| Step Review Focus | enum 值与既有约定一致 (string) |
| Remaining Gap | none |

### T2. executor.py: __init__ 新参数
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | serial (Round 1) |
| Scope | executor.py |
| Current Slice | mode + context_reduction 加进 __init__ |
| Definition of Done | 默认值兼容；既有测试不破 |
| Required Validation | 同 T1 |
| Step Review Focus | 默认 mode=PARALLEL 不破坏既有行为 |
| Remaining Gap | none |

### T3. executor.py: DispatchState 新字段
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | serial (Round 1) |
| Scope | executor.py |
| Current Slice | released_handoff_ids + specialist_artifacts |
| Definition of Done | 字段存在 + 兜底默认 |
| Required Validation | `test_serial_mode_state_records_released_handoff_ids` |
| Step Review Focus | field(default_factory=...) 避免可变默认 |
| Remaining Gap | none |

### T4. executor.py: WaveResult 新字段
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | serial (Round 1) |
| Scope | executor.py |
| Current Slice | mode + specialist_artifacts |
| Definition of Done | 字段存在 + 兜底默认 |
| Required Validation | 既有 20 TestExecutor 测试 |
| Step Review Focus | 默认 mode=PARALLEL |
| Remaining Gap | none |

### T5. executor.py: run_wave 拆分为两模式
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | serial (Round 1) |
| Scope | executor.py |
| Current Slice | 顶部 mode 分流 + 旧 body 抽到 _run_wave_parallel |
| Definition of Done | 既有 88 测试 + 新 8 测试全过 |
| Required Validation | `pytest tests/test_attack_dispatch.py -v` (96/96) |
| Step Review Focus | 既有逻辑无变动 |
| Remaining Gap | none |

### T6-T10. executor.py: SERIAL 模式实现
T6-T10 全部改 executor.py，串行做：
- T6: `_run_wave_serial` 主循环 per-specialist 落盘
- T7: `_write_specialist_artifact` helper
- T8: `_write_artifact` 加 per_specialist_artifacts / mode 参数
- T9: `_artifact_path_for` drill-in slot 检测
- T10: `_run_drill_slot` SERIAL 模式 per-slot 落盘

每个 T 完成 → 跑对应单测 → 状态 completed → 进下一个。

### T11. __init__.py 导出
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | serial (Round 1) |
| Scope | src/opensquilla/attack_dispatch/__init__.py |
| Current Slice | import DispatchMode + __all__ 加项 |
| Definition of Done | `from opensquilla.attack_dispatch import DispatchMode` 成功 |
| Required Validation | import 成功 |
| Step Review Focus | 不破坏既有导入 |
| Remaining Gap | none |

### T12-T13. clone 脚本改 SOUL/ATTRIBUTION
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | Thread B (Round 2 并行) |
| Scope | scripts/clone_cyberstrike_to_hack_deep.py |
| Current Slice | T12 替换 Parallel Logic 段；T13 append modification log |
| Definition of Done | 重克隆后 SOUL/ATTRIBUTION 含新内容 |
| Required Validation | 67/67 soul contract 测试过 |
| Step Review Focus | 字符串字面替换不改其他 |
| Remaining Gap | none |

### T14. docs/hack-deep.md §5.5
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | Thread C (Round 2 并行) |
| Scope | docs/hack-deep.md |
| Current Slice | 5 子节 (问题/SOUL 合约/Python API/on-disk 布局/实测) |
| Definition of Done | 文件含 Serial Mode 章节 |
| Required Validation | grep "Serial Mode" 命中 |
| Step Review Focus | 与代码实现一致 |
| Remaining Gap | none |

### T15. tests/test_attack_dispatch.py TestSerialMode
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | Thread A (Round 2 并行) |
| Scope | tests/test_attack_dispatch.py |
| Current Slice | TestSerialMode 类 8 测试 |
| Definition of Done | 8/8 测试过 |
| Required Validation | `pytest tests/test_attack_dispatch.py::TestSerialMode -v` |
| Step Review Focus | 既有 88 测试不破 |
| Remaining Gap | none |

### T16. tests/test_hack_deep_soul_contract.py
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | Thread A (Round 2 并行) |
| Scope | tests/test_hack_deep_soul_contract.py |
| Current Slice | 4 SOUL/ATTRIBUTION 断言 |
| Definition of Done | 4/4 测试过 |
| Required Validation | `pytest tests/test_hack_deep_soul_contract.py -v` |
| Step Review Focus | 用 ATTR 而非 ATTRIBUTION (既有命名) |
| Remaining Gap | none |

### T17. README.md Key Features 行
| Field | Value |
| --- | --- |
| Status | completed |
| Thread | Thread C (Round 2 并行) |
| Scope | README.md |
| Current Slice | 1 行替换 |
| Definition of Done | grep "v3.2" 命中 |
| Required Validation | grep README.md "v3.2" |
| Step Review Focus | 表格行不破 |
| Remaining Gap | none |

## 7. Round Order
1. **Round 1 (串行地基)**：T1-T11。改 executor.py / __init__.py 同一组文件；每个 T 完成后单测过、状态 completed。
2. **Round 2 (3 线程并行)**：
   - Thread A：T15 → T16 (测试)
   - Thread B：T12 → T13 (SOUL/ATTRIBUTION)
   - Thread C：T14 → T17 (docs + README)
3. **Round 3 (合闸串行)**：跑全量回归 + clone 落盘验证 + 手工核查清单 → final-review → decision=close。

## 8. Validation Rules
- 每改一个文件就 grep 确认 import / 命名一致
- 每个 T 完成即跑对应单测，不堆到 Round 3
- 任何新加 Pydantic 字段必须 Optional / 兜底默认
- 任何新加模式必须不破坏既有 W0-W8 deps 拓扑
- Round 3 合闸必须全绿才能 final-review

## 9. Risks / Watchpoints
- **R1**：per-specialist JSON 落盘失败 → 沿用既有 `try/except OSError` 模式
- **R2**：LLM 不遵守 SOUL 合约 → 用户选择"不动 runtime"；SOUL 表述明确降低违反概率
- **R3**：drill-in 路由 (W1.6a/b/c 不含 ".5") → `_artifact_path_for` 用 DRILL_IN_SLOTS 检测
- **R4**：per-specialist 与合并文件 handoff_id 冲突 → SERIAL 模式合并文件改名 `<wave>.combined.json`
- **R5**：既有 `_make_specialist_double` 工厂可能误用 envelope handoff_id sub_index 假设 → 测试已修复 (1, 2, 3)

## 10. Termination Checklist
- [x] Round 1 全部 11 个 T 状态 `completed`
- [x] Round 2 全部 6 个 T 状态 `completed`
- [x] Round 3 T12-T15 全量回归测试全绿
- [x] tests/test_attack_dispatch.py 全绿 (96/96)
- [x] tests/test_hack_deep_soul_contract.py 全绿 (67/67)
- [x] 重克隆后 `~/.opensquilla/agents/hack-deep/SOUL.md` 含 Serial Mode 章节
- [x] `docs/hack-deep.md` 含 §5.5 Serial Mode
- [x] `README.md` 含 v3.2 描述
- [x] 规范化 todo 全部 `completed`
- [x] delivery state: `decision=close`
