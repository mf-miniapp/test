# hack-deep-find 工作流设计 (v5.2, 2026-06-18)

> **目标**: 编排器 (`agents/hack-deep-find`) 从一个 root_domain 出发, 按
> **8 层资产树** (L0..L7) 完整建出 资产清单; 终止条件 = find-skeleton 完整
> (L7 PARAMETER 触及 + 没有任何 UNSEEN)。L8 INJECTION_VECTOR 不要求存在
> (属于漏洞向量层, 由 hack-deep attack phase 写入)。
>
> **核心策略** (硬约束, 与 `attack_dispatch.waves.DISCOVERY_STRATEGY_MAP` 同步):
> - **L0..L3** (root → sub → ip → port/service) → **bulk_layer**: 一次取全层
>   UNSEEN, 多 batch 并发探测。子 agent 数 ≈ 节点数 / batch_size, 同层多
>   specialist 同时跑, 资源利用率最高。
> - **L4+** (url / endpoint / parameter / injection_vector) → **chain_fanout**:
>   按 parent chain 分组, **每条 chain 1 个 specialist 深度下钻**。避免
>   1 个 service 出 1000+ endpoint 时 specialist context 爆掉。
>
> **8 层资产映射** (L0 = ROOT, 业务资产层, v5.2 修正):
> ```
> L0  ROOT_DOMAIN          ─┐
> L1  SUB_DOMAIN            │  bulk_layer
> L2  IP / STORAGE          │  (W0.5 / W1)
> L3  PORT / SERVICE /      │
>     STORAGE_OBJECT        ─┘
> L4  URL / COMPONENT       ─┐
> L5  ENDPOINT /            │
>     AUTH_SURFACE /        │  chain_fanout
>     STATIC_ASSET /        │  (W1.5 / W1.5c /
>     API_SCHEMA /          │   W3.5)
>     COOKIE / HEADER       │
> L6  PARAMETER             │
> L7  (业务最深层)         ─┘  ← find 终止契约目标
> ---
> L8  INJECTION_VECTOR      (漏洞向量层, 不在 find 责任范围)
> ```
> **重要**: 旧版 (v5) 把 L6 标为 PARAMETER, L7 为"空跳", L8 为 INJ;
> v5.2 核对实际代码: PARAMETER 在 path_depth=7 (L7), L6 主链未占用.
> find 终止契约 = max_depth >= 7 = 触及 L7 PARAMETER.
>
> 跨层挂载 (不占主链 depth): `SECRET`, `GENERIC` 兜底。

---

## 0. 编排器全局状态

`hack-deep-find` 的 LLM-coordinator 在 1 次 find run 内维护以下 state
(在 session prompt 顶部声明, 跨 turn 持久):

```python
class FindRunState:
    root_domain: str
    tree_id: str
    root_node_id: str
    first_run: bool                              # F-pre 判定
    diff_w0_5: DiffResult | None
    waves_run: list[str]                         # e.g. ["W0.5", "W0.6", "W1", ...]
    waves_skipped: list[str]
    failed_ingest: dict[str, list[dict]]         # {wave: [evidence_payload, ...]}
    target_queue: list[str]                      # W4/W5/W6 emit 的新目标
    specialists_invoked: list[str]               # 实际跑过的 specialist
    skeleton_max_depth_reached: int              # 每 wave 后刷新
    skeleton_unseen_total: int
    completion_pct: float
    strategy_applied: dict[str, DiscoveryStrategy]  # 用于 find-complete-v1
```

---

## 1. 6 阶段架构 (与 6 wave 严格对应, v5.2: W2.5 不在 find 责任范围)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ F0   (W0.5) bulk_layer  ──── root + sub + ip 横向扩展 + 网络层            │
│ F0.6 (W0.6) bulk_layer  ──── 资源检查点 (skills/wordlists/payloads)       │
│ F1   (W1)   bulk_layer  ──── port + service (网络层, 全部一起逐层)       │
│ F1.5 (W1.5) chain_fanout ─── per-chain web app / component / storage     │
│ F1.5c(W1.5c) chain_fanout ── per-chain 条件 expand scan                  │
│ ~~F2.5 (W2.5)~~        ─── ~~per-chain injection_vector (跨 owner)~~   │
│ F3.5 (W3.5) chain_fanout ─── per-chain secret / cookie / header 跨层信号 │
└──────────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
              F-final-pre (调 asset_tree_check_skeleton)
                          │
                          ▼
                 F-final (tree-finalizer 完整性核查 + URL 存活复核)
                          │
                          ▼
                 find-complete-v1 (find 自身终止, 不再 handoff hack-deep)
                          │
                          ▼
              find-skeleton complete == true 才允许发 (L7 PARAMETER)
```

---

## 2. F0 (W0.5) — root + sub_domain + IP + extra_seeds

**策略**: `bulk_layer` — 1 个 wave 跑 2 个 specialist 全量, **不分 chain**
(因为 L1/L2 节点数 ~ 几十个, chain_fanout 反而引入额外 envelope 开销)。

### 子 agent 矩阵

| specialist_id | 父节点 | 输出节点 | 工具组 | batch |
|---|---|---|---|---|
| `domain-expander` | ROOT_DOMAIN | SUB_DOMAIN + IP + extra_seeds | `group:recon:dns` + `group:recon:seed` | 1 (全量) |
| `osint-collector` | ROOT_DOMAIN | ROOT_DOMAIN 兄弟 (extra_seeds) | `group:recon:seed` | 1 (全量) |

### 编排器行为

```
1. wave = WAVES["W0.5"]   # fanout=static_fanout, 2 agents
2. strategy = "bulk_layer" (DISCOVERY_STRATEGY_MAP["W0.5"])
3. fire 2 个 sessions_spawn (domain-expander + osint-collector)
   同 turn fire-and-forget, 1 barrier
4. ingest: 2 份 evidence -> add_nodes
5. v4.5 incremental diff (only when first_run == False)
6. 批量 state 推进: 新增的 sub_domain/ip 节点 -> update_state("discovered")
7. 输出 [WAVE W0.5 COMPLETE]
   new/preserved/resurrected/abandoned 计数
```

### 输出: L1 (SUB_DOMAIN) + L2 (IP) + L2 (STORAGE, 由 F1.5 补)

---

## 3. F0.6 (W0.6) — 资源检查点 (不写资产树)

**策略**: `bulk_layer` — 静态 fanout, 3 个 agent 并行扫资源, **不发**
**任何 specialist spawn 的工具** (只读)。

| specialist_id | 工具 |
|---|---|
| `recon` | `read_file` (skills / wordlists / payloads) |
| `penetration` | `read_file` (同) |
| `engagement-planning` | `read_file` (同) |

**fail-open**: 缺失资源 = 警告 + 标记, **不阻塞**。

---

## 4. F1 (W1) — port + service (网络层, 全部一起逐层)

**策略**: `bulk_layer` (硬约束: L1..L3 全部一起逐层并行)

### 子 agent 矩阵

| specialist_id | 父节点 | 输出节点 | 工具组 | batch_size |
|---|---|---|---|---|
| `port-scanner` | IP | PORT | `group:recon:portscan` | 5-10 IP/batch |
| `service-fingerprint` | PORT | SERVICE | `group:recon:portscan` + `group:recon:http` | 10-20 port/batch |

### 编排器行为 (滑动 barrier, v4.5.2)

```
1. wave = WAVES["W1"]
2. strategy = "bulk_layer"
3. **phase A: port-scanner**
   a. unseen_ips = asset_tree_find_unseen("ip")
   b. for batch in chunk(unseen_ips, 5-10):
        sessions_spawn(agent_id="port-scanner", task=batch_envelope)
      同 turn 全部 fire, 不 await
   c. sessions_yield()  # 1 barrier
   d. ingest: port-scanner.ports -> PORT 节点 (parent=ip.id)
4. **phase B: service-fingerprint**
   a. unseen_ports = asset_tree_find_unseen("port")
   b. for batch in chunk(unseen_ports, 10-20):
        sessions_spawn(agent_id="service-fingerprint", task=batch_envelope)
   c. yield -> ingest
   d. ingest: service-fingerprint.services -> SERVICE 节点 (parent=port.id)
5. v4.5 incremental diff (only when first_run == False)
6. 批量 state 推进: 新增 port/service -> update_state("discovered")
7. **覆盖率自检** (硬约束, 不允许静默跳过):
   plan = asset_tree_plan_pending(tree_id)
   if plan.pending_waves 仍有 W1 (ip:unseen / port:unseen > 0)
     且 provider 正常: 编排器自动重跑 step 3-4, 直到 W1 完全空
8. 输出 [WAVE W1 COMPLETE]
```

### 输出: L3 (PORT + SERVICE) + L3 (STORAGE_OBJECT, 部分)

### 与 chain_fanout 的区别 (本 wave 用 bulk_layer)

- 节点数相对可控: sub (几十) + ip (几十) + port (几百)
- 单 specialist 探 1 个 vs 10 个 port 成本接近 (网络握手开销主导)
- **总 spawn 次数 = ceil(总节点 / batch_size)**, 不是节点数
- 6 个 specialist slot 持续满载 (高吞吐)

---

## 5. F1.5 (W1.5) — per-chain web app / component / storage / secret

**策略**: `chain_fanout` (硬约束: L4+ 单链深度, 避免 context 爆炸)

### 子 agent 矩阵 (4 类 specialist, 按 parent chain 派)

| specialist_id | 父节点 (chain root) | 输出节点 | 工具组 | chain 入口 |
|---|---|---|---|---|
| `webapp-discoverer` | SERVICE | URL (含 vhost 探测) | `group:recon:webapp` + `group:recon:http` | service.id |
| `component-detector` | SERVICE | COMPONENT (product + version + cpe) | `group:recon:component` | service.id |
| `storage-discoverer` | SUB_DOMAIN | STORAGE + STORAGE_OBJECT | `group:recon:storage` + `group:recon:dns` | sub.id |
| `secret-scanner` | URL (W1.5 早跑给 W3.5 铺垫) | SECRET (跨层挂载) | `group:recon:secret` + `group:recon:http` | url.id |

### 编排器行为 (chain_fanout 模式)

```
1. wave = WAVES["W1.5"]
2. strategy = "chain_fanout"
3. **3 个分桶** (按 parent chain):
   a. service_chains = asset_tree_find_unseen_chain(asset_type="service", min_depth=3)
   b. subdomain_chains = asset_tree_find_unseen_chain(asset_type="sub_domain", min_depth=1)
   c. url_chains = asset_tree_find_unseen_chain(asset_type="url", min_depth=4)
4. **per-chain 派发** (1 chain 1 specialist, **不合并 batch**):
   for chain in service_chains:
     sessions_spawn(webapp-discoverer, chain)       # 1 spawn per chain
     sessions_spawn(component-detector, chain)      # 2 specialist 同 chain 并行
     # ↑ 关键: 不像 bulk_layer 那样把多条 chain 合并成 1 个 batch
   for chain in subdomain_chains:
     sessions_spawn(storage-discoverer, chain)      # 1 chain 1 spawn
   for chain in url_chains:
     sessions_spawn(secret-scanner, chain)          # 1 chain 1 spawn
5. 同 turn fire-and-forget, 1 barrier per specialist family
6. ingest 9 步 (asset_tree_add_nodes + verification + update_state)
7. v4.5 incremental diff
8. 批量 state 推进: 新增 url/component/storage/secret -> discovered
9. 覆盖率自检: service:unseen / sub_domain:unseen / url:unseen 必须 == 0
   否则编排器自动重跑
10. 输出 [WAVE W1.5 COMPLETE]
```

### 输出: L4 (URL + COMPONENT) + L4 (STORAGE) + L3 (STORAGE_OBJECT) + SECRET (跨层)

### 与 bulk_layer 的区别 (本 wave 用 chain_fanout)

- 1 个 service 可能派生 **1000+ url_candidate** (vhost + path 组合)
- 全部塞进 1 个 specialist envelope → context 必爆
- 改成"每条 chain 1 specialist", chain = (parent, 它所有 unseen 子孙)
- 编排器按 `unseen_count` 降序处理"大链"优先, 限流稳定

---

## 6. F1.5c (W1.5c) — conditional expand scan

**策略**: `chain_fanout`

**触发条件** (任一):
- `port_scan_complete == false` (W1 端口未扫全)
- `dir_bust_evidence missing`
- `wayback missing`

**行为**: 1 个 spawn (单 specialist), 跑完 -> ingest -> 输出 [WAVE W1.5c COMPLETE/SKIPPED]。

---

## 8. F3.5 (W3.5) — per-chain secret / cookie / header 跨层信号

**策略**: `chain_fanout`

### 子 agent 矩阵 (3 类 specialist)

| specialist_id | 父节点 (chain root) | 输出节点 | 工具组 | chain 入口 |
|---|---|---|---|---|
| `webapp-discoverer` | URL (二探) | URL tech_stack 更新 + STATIC_ASSET | `group:recon:webapp` + `group:recon:http` | url.id |
| `content-classifier` | URL | STATIC_ASSET + AUTH_SURFACE + COOKIE + HEADER | `group:recon:sensitive` + `group:recon:auth` + `group:recon:header` | url.id |
| `api-surface-mapper` | URL | API_SCHEMA + ENDPOINT + PARAMETER | `group:recon:api` + `group:recon:http` | url.id |

### 编排器行为

```
1. wave = WAVES["W3.5"]
2. strategy = "chain_fanout"
3. url_chains = asset_tree_find_unseen_chain(
     asset_type="url", min_depth=4, max_chains=50
   )
4. **per-chain 派发 3 specialist** (1 chain 3 spawn):
   for chain in url_chains:
     sessions_spawn(webapp-discoverer, chain)
     sessions_spawn(content-classifier, chain)
     sessions_spawn(api-surface-mapper, chain)
5. 同 turn fire-and-forget, 1 barrier
6. **INGEST 9 步 (v4.5.3 强制, 不允许 specialist 自己 add_nodes)**:
   a. sessions_history(sk, last_n=1) 拉 specialist 真实输出
   b. 拆 evidence 为 (parent_id, asset_type, values[]) 多元组
   c. 调 asset_tree_add_nodes (一次 1 parent × 1 asset_type)
   d. dedup 内置, 不需要 LLM 预判
   e. 失败 -> state.failed_ingest, **不丢**
7. 批量 state 推进: 新增节点 -> discovered
8. 覆盖率自检: url:unseen == 0
9. 输出 [W3.5 COMPLETE]
```

### 输出: L5 (ENDPOINT + STATIC_ASSET + AUTH_SURFACE + API_SCHEMA + COOKIE + HEADER) + L6 (PARAMETER) + SECRET (跨层补)

---

## 9. F-final-pre (终止前骨架核查)

**调用**: `asset_tree_check_skeleton(tree_id)` 工具

**返回** (v5.2 加 `find_termination_depth` 字段, `max_depth_reached` 改 7):
```json
{
  "complete": true,
  "max_depth_reached": 7,
  "max_depth_cap": 8,
  "find_termination_depth": 7,
  "completion_pct": 1.0,
  "nodes_per_layer": {"0": 1, "1": 12, "2": 18, "3": 47, "4": 21, "5": 64, "6": 132, "7": 18},
  "unseen_total": 0,
  "unseen_by_type": {},
  "unseen_by_layer": {},
  "abandoned_total": 2
}
```

**不满足怎么办**:
- `complete=false` -> 编排器自动重跑 F-resume (调 `asset_tree_plan_pending`)
- 跑哪个 wave: `pending_waves[0]`
- 直到 `complete=true` 才允许发 `find-complete-v1`

---

## 10. F-final (tree-finalizer 完整性核查 + URL 存活复核)

**specialist**: `tree-finalizer` (只读, 不 spawn)

**输出**: `asset-tree-v1` evidence

**关键步骤** (新增 step 0):
```
0. **find-skeleton 核查** (v5.2 改名: 不是 8 层, 是 L7 PARAMETER):
   skeleton = asset_tree_check_skeleton(tree_id)
   if not skeleton["complete"]:
     raise IncompleteSkeletonError  # 回到 F-final-pre 重跑
```

**其它步骤** (沿用 tree-finalizer SOUL_BODY 既有 step 1-7): 节点统计、
verified 比例、URL 存活复核、evidence 完整性、coverage_gaps。

---

## 11. F-complete (find-complete-v1 handoff)

**evidence 字段** (v5.2 强化):
```json
{
  "evidence_schema": "find-complete-v1",
  "tree_id": "tree-...",
  "root_domain": "example.com",
  "tree_path": "~/.opensquilla/state/asset_trees/tree-...json",
  "tree_stats": {...},
  "frontier_summary": [...],
  "duration_s": 1234,
  "specialists_invoked": ["domain-expander", "port-scanner", ...],

  "skeleton_complete": true,
  "skeleton_max_depth_reached": 7,
  "skeleton_completion_pct": 1.0,
  "skeleton_nodes_per_layer": {"0": 1, "1": 12, ..., "7": 18},
  "skeleton_unseen_total": 0,
  "find_termination_depth": 7,
  "discovery_strategy_applied": {
    "W0.5": "bulk_layer", "W0.6": "bulk_layer", "W1": "bulk_layer",
    "W1.5": "chain_fanout", "W1.5c": "chain_fanout",
    "W3.5": "chain_fanout"
  }
}
```

**v5.2 重大变更**: find 自身**不**再委派 hack-deep. find-complete-v1
写到本地磁盘后, find 自身终止.

**与上层 orchestrator 的契约**:
- `skeleton_complete=true` + `specialists_invoked != []` → 上层 orchestrator
  可以启动 hack-deep
- `skeleton_complete=false` → 编排器自己补全 (F-resume), 不允许推给 hack-deep
- `skeleton_unseen_total > 0` → 编排器自己补全后再发 (不允许推给 hack-deep)

**与 hack-deep 的契约 (历史, v2 之前)**:
- ~~`skeleton_complete=true` + `specialists_invoked != []` → hack-deep 接受~~
- ~~`skeleton_complete=false` → hack-deep 应返回 `find_incomplete` 错误~~

---

## 12. 工具映射表 (5 个 v5 工具)

| 工具 | 用途 | 何时调 |
|---|---|---|
| `asset_tree_find_unseen` (bulk) | L0..L3 全层取 UNSEEN | F0 / F1 (bulk_layer wave) |
| `asset_tree_find_unseen_chain` | L4+ 按 parent chain 取 | F1.5 / F1.5c / F3.5 (chain_fanout wave; F2.5 不在 find 范围) |
| `asset_tree_check_skeleton` | find-skeleton 完成度报告 (L7 + 无 UNSEEN) | F-final-pre 必调 |
| `asset_tree_add_nodes` | 入树 (含 verification) | 每个 specialist 跑完 ingest |
| `asset_tree_plan_pending` | 待跑 wave 计划 | F-resume 触发时调 |

---

## 13. 资源与并发预算

| 项 | 值 | 说明 |
|---|---|---|
| max_children_per_session | 30 | 同 session 累计 spawn 数 |
| subagent_reserved_slots | 6 | 同时运行的 specialist 数 |
| batch_size (L0..L3 bulk) | 5-20 | 视 specialist 而定 (port-scanner 5-10 IP, service-fingerprint 10-20 port) |
| chain_size (L4+ chain) | 1 chain 1 spawn | 不合并, 避免 context 爆 |
| max_chains (F3.5) | 50 | 默认值, 编排器可调 |
| fire-and-forget turn 数 | 1 turn 全 fire | 同一 turn 内不 await child session_id |
| barrier 频率 | bulk: 1/wave; chain: per specialist family | 滑动 barrier |

---

## 14. 失败 / 异常处理矩阵

| 失败类型 | 处理 |
|---|---|
| specialist spawn 失败 | 重试 1 次, 仍错 -> 标 [WAVE {W} SPAWN FAILED], 记入 state.failed_spawn |
| specialist evidence 解析失败 | 标 [INGEST FAILED], 存到 state.failed_ingest (不丢) |
| add_nodes ToolError | 重试 1 次, 仍错 -> failed_ingest |
| `complete=false` at F-final-pre | 自动 F-resume (plan_pending -> 重跑对应 wave) |
| 编排器自己生成假数据入树 | **fraud 行为**, SOUL_BODY 明确禁止 |
| 1 个 IP 84 port 但 70 丢失 (51ifind bug) | 已被 v4 修: 全部入树 + 验证 envelope |
| URL 假阳性 (error page) | 已被 v4 修: 验证 envelope + recon_url_validate |

---

## 15. v5 与既有版本对比

| 项 | v4 (2026-06-17) | v5 (2026-06-18) | v5.2 (2026-06-18) |
|---|---|---|---|
| 深度上限 | 无硬约束 | `MAX_TREE_DEPTH=8` (业务硬上限) | 同 + `FIND_TERMINATION_DEPTH=7` (find 终止深度) |
| 父子校验 | `_VALID_PARENT_CHILD` (白名单) | 同 + DB CHECK 兜底 | 同 |
| 编排策略 | 隐式 (每 wave 自由选) | **显式 bulk_layer / chain_fanout** | 同 (W2.5 从 find 责任范围移除) |
| 终止条件 | `find_unseen` 空 | **`is_skeleton_complete` (L8 + 无 UNSEEN)** | **`is_skeleton_complete` (L7 + 无 UNSEEN)** |
| find-complete-v1 字段 | tree_id / tree_path / frontier | + `skeleton_*` + `discovery_strategy_applied` | + `find_termination_depth` (7) |
| find_unseen 工具 | 单个 (按 type) | + `find_unseen_chain` (按 parent chain) | 同 |
| bulk vs chain 边界 | 模糊 | **L0..L3 = bulk; L4+ = chain** (硬约束) | 同 (W2.5 不在范围) |
| **find → hack-deep 委派** | `sessions_spawn(hack-deep, find-complete-v1)` 跨 owner handoff | 同 | **取消**: find 不再 spawn hack-deep; 写 evidence 到本地后自身终止, 上层 orchestrator 自行启动 hack-deep |
| **W2.5 (per-port attack plan)** | find 拼 dispatch + 跨 owner 转交 | 同 | **不在 find 责任范围**: W2.5 整体由 hack-deep 在 attack phase 自行执行 |
| **INJECTION_VECTOR (L8) 节点** | find 可能产 (依赖 W2.5) | 同 | **不要求存在**: find 不写, hack-deep 后续 attack phase 自行写入 |

---

## 16. 关键文件索引

- `docs/features/asset-tree-asset-types.md` — 20 类节点 / 父子白名单
- `docs/features/hack-deep-find-workflow.md` — 本文档
- `src/opensquilla/asset_tree/models.py` — `AssetType` / `MAX_TREE_DEPTH` / `validate_parent_child` / `validate_depth` / `DepthExceededError`
- `src/opensquilla/asset_tree/tree.py` — `AssetTree.is_skeleton_complete` / `skeleton_report` / `nodes_per_layer` / `dispatch_plan` / `max_depth_reached`
- `src/opensquilla/asset_tree/db/schema.py` — `ck_asset_nodes_depth_max CHECK (path_depth <= 8)`
- `src/opensquilla/asset_tree/db/backend.py` — `find_unseen(max_depth=...)`
- `src/opensquilla/tools/builtin/asset_tree/tree.py` — 11 个工具 (含 v5 新增 `find_unseen_chain`, `check_skeleton`, `dispatch_plan`)
- `src/opensquilla/attack_dispatch/waves.py` — `DiscoveryStrategy` / `DISCOVERY_STRATEGY_MAP` / `WAVE_MAX_PATH_DEPTH` / `wave_owns_depth` / `strategy_of_wave`
- `src/opensquilla/attack_dispatch/evidence.py` — `FindCompleteEvidence` (含 `skeleton_*` 字段)
- `src/opensquilla/agents/hack-deep-find/SOUL_BODY.md` — 编排器契约 (v5 段落指向本文)
- `src/opensquilla/agents/hack-deep-find/specialists/tree-finalizer/SOUL_BODY.md` — tree-finalizer 契约 (F-final 步骤)
- `tests/test_asset_tree_depth_v5.py` — 16 个 8 层深度测试
- `tests/test_hack_deep_find_workflow_v5.py` — 工作流策略 + 终止测试
