# Attribution — create-attack-path (v1.0, 2026-06-19)

## 角色

v6 重构新增的编排辅助 agent, 接受 `attack-path-list-v1` evidence 输
入, 输出**同 schema** 的 AttackPath 列表。owner = hack-deep (被
hack-deep 编排器 spawn, 不 spawn 任何子 specialist)。

## evidence_schema

| 字段 | 类型 | 必填 | 含义 |
| --- | --- | --- | --- |
| `tree_id` | str | ✓ | 目标资产树 id |
| `path_count` | int | ✓ | 路径总数 |
| `leaf_type_histogram` | dict[str, int] | ✓ | 各 leaf type 计数 |
| `paths[]` | list[dict] | ✓ | 每条 path 的概要 (path_id, leaf_type, leaf_value, scope_string, edge_count) |
| `warnings[]` | list[str] | ✗ | 非致命 warning (e.g. "max_depth_reached < 7") |

## 输入 envelope

```
HANDOFF <id> | deps=find-complete-v1 | schema=attack-path-list-v1 | eta=60
```

`deps` 必须是 `find-complete-v1` (即资产树 find 阶段已完成, 树上至
少有 1 个 L7 节点)。

## 输出 envelope

同 schema (`attack-path-list-v1`), phase=complete。末尾 `RESULT MARKER`。

## 调用方

`opensquilla.orchestrator.run_attack_paths.run()`:
1. 验证 `find-complete-v1` evidence 存在
2. sessions_spawn(agent_id="create-attack-path", task=<typed-envelope>)
3. 等 result marker, 拿 `paths[]` 列表
4. 逐条 sessions_spawn(agent_id="hack-deep", task=<attack-path-v1>) (第 2 步循环)

## 历史

- 2026-06-19: v1.0 初始, 配合 v6 hack-deep 重构 (按边攻击模型) 上线。
