# hack-deep-find 提速方案 (v1, 2026-06-17)

> 范围: `opensquilla.agents.hack-deep-find` v4 (LLM-coordinator + 13 specialist) 端到端执行。
> 目标: 典型 1 root_domain run (30 sub_domain × 4 spec F1.5 + 20 web_service × 3 spec F3.5)
> 从 **约 35-50 分钟** 降到 **6-10 分钟**, 减少 ~70% wall-clock, 同步压低 token 消耗 ~50%。

---

## 1. 现状瓶颈清单 (按影响排序)

代码已读：`src/opensquilla/agents/hack-deep-find/SOUL_BODY.md`、
`src/opensquilla/tools/builtin/sessions.py`、
`src/opensquilla/tools/builtin/asset_tree/tree.py`、
`src/opensquilla/gateway/subagent_announce.py`、
`src/opensquilla/agents/hack-deep-find/specialists/*/SOUL_BODY.md` (20 份)、
`src/opensquilla/engine/turn_runner/` (10 个 stage, 5074 行)。

| # | 瓶颈 | 位置 | 量级 |
|---|------|------|------|
| B1 | **per-subdomain / per-bucket 串行 LLM round** | `SOUL_BODY.md:397-428` (F1.5) / `:486-518` (F3.5) | 30+ round (F1.5) + 5+ round (F3.5)，每 round 1 spawn |
| B2 | **per-parent spawn 串行锁** | `sessions.py:226-243`, `:568-571` | 同一 parent 内 `async with spawn_lock` 把"单消息 4 个 spawn" 串行化 4 次 |
| B3 | **Specialist 内部串行 tool-call** | `specialists/domain-expander/SOUL_BODY.md:43-87` (50-100 DNS 串行) | 100+ round/specialist |
| B4 | **surface-aggregator 把整棵 AssetTree 读进 LLM** | `specialists/surface-aggregator/SOUL_BODY.md:32-49` | O(N) 节点 × N round, 单 round 20-60s |
| B5 | **System prompt 过大** | `SOUL_BODY.md` 56KB / specialist 100-200 行 | 每 round 40-80K input tokens |
| B6 | **同 URL 3 specialist 各做 1 次 HTTP** | F3.5: webapp / content / api 各 1 探 | 3× 网络往返 / URL |
| B7 | **F2.5 跨 owner dispatch envelope 链** | `SOUL_BODY.md:447-485` | find→deep→vuln-triage→deep→find 5 跳 |
| B8 | **无 mid-run checkpoint** | 全流程 | 任何 specialist 失败 → 30 分钟重跑 |
| B9 | **每 spawn 锁内 DB 同步 `count_active_children`** | `sessions.py:175-227` | 每 spawn 1 次 DB 往返 |
| B10 | **`sessions_yield` 后等 background push → parent wake** | `subagent_announce.py:308-365` | 30-300ms idle × N wave |

**总成本（典型 30 sub + 20 web）**:
- LLM round 数 ≈ Step0(1) + F0(2) + F0.6(3) + F1(3) + F1.5(30×4=120) + F1.5c(1) + F2.5(5) + F3.5(5×3=15) + F-final-pre(1) + F-final(2) ≈ **153 个 round**
- Specialist 内 tool-call: domain-expander 100 + port 50 + web 200 + api 80 ≈ **430 个 tool-call round**
- 单 round 平均 5-10s → 35-50 分钟 wall-clock

---

## 2. 提速方案 (3 层 / 9 项)

### Layer 1 — 砍 round 数（最大头，预计 60% 提速）

#### S1. F1.5 / F3.5 改为 "shell script + batch spawn"（-100 round）

**现状**：`SOUL_BODY.md:397-428` 让 LLM 编排器自己写 for 循环，每 sub_target 一轮 LLM round。
**改**：把循环下沉到 Python 工具，新增 `asset_tree_batch_dispatch` 工具。

```python
# 新工具 src/opensquilla/tools/builtin/asset_tree/batch_dispatch.py
@tool(name="asset_tree_batch_dispatch", ...)
async def asset_tree_batch_dispatch(
    tree_id: str,
    parent_kind: str,           # "sub_domain" | "service"
    parent_ids: list[str],      # 30 个
    specialists: list[str],     # 4 个 v4 specialist
    envelope_template: str,     # 含 {parent_id} 占位符
    concurrency: int = 4,
) -> str:
    """对每 (parent × specialist) 组合 spawn 1 个子任务，
    全局并发上限 = concurrency, 全部完成后一次性返回 evidence[]。
    不再依赖 LLM 编排器多轮 round 循环。"""
    # 内部: asyncio.Semaphore 控制并发; 一个 parent × 一组 spec 完成后
    # 调 asset_tree_add_nodes 落盘, 然后 yield
```

**对应 SOUL 改动**（`SOUL_BODY.md:397-428` + `:486-518`）:
```text
### Step F1.5 (W1.5) — 批量 fan-out (S1 改)
1. sub_targets = state.evidence["W0.5"].sub_targets
2. asset_tree_batch_dispatch(
     tree_id=tree_id, parent_kind="sub_domain",
     parent_ids=[s.node_id for s in sub_targets],
     specialists=["webapp-discoverer","component-detector",
                  "storage-discoverer","secret-scanner"],
     envelope_template=ENVELOPE_F15, concurrency=4)
3. 工具一次性返回所有 evidence → ingest 一次性
4. 一次性调 asset_tree_add_nodes 落盘
5. 输出 [WAVE W1.5 COMPLETE] (1 round 完成)
```

**效果**: F1.5 从 30 round → 1 round (-29), F3.5 从 5 round → 1 round (-4)。

#### S2. 释放 per-parent spawn 锁（并行 spawn 真正生效，-50% wall）

**现状**：`sessions.py:226-243` `_get_spawn_lock` 同一 parent session_key 共享 1 个 `asyncio.Lock`, 把"单 LLM 消息里的 4 个 tool-call spawn" 串行排队。
**改**：拆锁粒度。

```python
# sessions.py:226-243 改:
def _get_spawn_lock(parent_session_key: str, child_agent_id: str) -> asyncio.Lock:
    """Lock by (parent, child) pair, not by parent alone.
    Same parent can spawn 2 different children concurrently."""
    key = (parent_session_key, child_agent_id)
    lock = _spawn_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _spawn_locks[key] = lock
    return lock
```

**安全论证**：原本共享锁的理由是 "max_children gate + create 原子化" (sessions.py:566-572 注释)；
拆成 per-(parent, child) 后, 同一 child agent 不可能并发 spawn 两次（parent 一次只产出 1 个 tool call）,
不同 child agent 之间没有共享可变状态, 无 race。

**效果**: F0/F1/F1.5/F3.5/F-final-pre 的"4 个 spawn 同时发出"真并行, 每个 wave 节省 N×(tool_call_latency + 100ms)。

#### S3. 新增 `recon_dns_batch` 批处理工具（-100 round/specialist）

**现状**：`domain-expander/SOUL_BODY.md:43-87` 写"50-100 DNS 候选串行调 recon_dns_resolve"，实际 100 个 round。
**改**：新增批处理工具, LLM 单次 tool-call 提交列表。

```python
# src/opensquilla/tools/builtin/recon/dns.py 新增
@tool(name="recon_dns_resolve_batch", ...)
async def recon_dns_resolve_batch(
    hostnames: list[str],       # 100 个一起传
    timeout_s: float = 5.0,
    concurrency: int = 32,
) -> str:
    """批量 DNS 解析, 内部 asyncio.Semaphore 控制并发。
    返回 {hostname: {ips: [...], error: ...}} 的 dict。"""
    sem = asyncio.Semaphore(concurrency)
    async def one(h):
        async with sem:
            return h, await recon_dns_resolve(h, timeout_s=timeout_s)
    pairs = await asyncio.gather(*(one(h) for h in hostnames))
    return json.dumps(dict(pairs), ensure_ascii=False)
```

**specialist SOUL 改**:
```text
2. DNS 候选枚举: 一次调 recon_dns_resolve_batch(candidates=全 100 个),
   返回 {host: {ips, error}} dict, 1 round 完成
```

**效果**: domain-expander 从 100 round → 1 round (-99); 其他 specialist (whois / asn / ct) 同理。

#### S4. F3.5 三 specialist 共用一次 HTTP 探针（-200 round, -3× 网络）

**现状**：`SOUL_BODY.md:486-518` 三 specialist 各自 1 次 HTTP（webapp-discoverer / content-classifier / api-surface-mapper）。
**改**：新增 `http_batch_probe` 工具, 一次发起 4 类信号探测 (status / headers / body-marker / form-action), 三个 specialist 都消费同一份 raw 探针结果。

```python
# src/opensquilla/tools/builtin/recon/http_probe.py 新增
@tool(name="http_batch_probe", ...)
async def http_batch_probe(
    urls: list[str], concurrency: int = 16
) -> str:
    """一次 HTTP GET 拿 {status, headers, body_sha, redirect_chain, timing_ms}。
    webapp / content-classifier / api-surface-mapper 三 specialist 共享此输出。"""
    # 内部并发拉, 持久化到 scratch 路径, 三 specialist 都 read_file 同一路径
```

**效果**: F3.5 单 host 网络请求数 3→1, wall-clock 减 60%; specialist round 数同 S1 减少。

#### S5. surface-aggregator 改 "读 metadata 索引 + 选择性 LLM 调"（-1 round, -90% token）

**现状**：`specialists/surface-aggregator/SOUL_BODY.md:32-49` 读整棵 AssetTree 进 LLM, 1000+ 节点 → 200K token。
**改**：拆成 "Python 索引 + LLM 调".

```python
# 新工具 src/opensquilla/tools/builtin/asset_tree/priority_index.py
@tool(name="asset_tree_priority_candidates", ...)
async def asset_tree_priority_candidates(
    tree_path: str,
    max_candidates: int = 50,
) -> str:
    """纯 Python 计算, 不调 LLM:
    1. 遍历 tree, 收集 (CVE 关联 / default-creds / secret-hit / info-leak)
       命中的节点, 每节点算 exploitability_score (0-100, 启发式)
    2. 排序, 取 top-N
    3. 返回 [{node_id, score, reasons[]}, ...]"""
```

**specialist SOUL 改**:
```text
2. 调 asset_tree_priority_candidates(tree_path, max=50) → top 50 候选
3. 只把 top 50 的 summary 读进 LLM, 让 LLM 写 attack-priority-v1 evidence
   (避免全树进 context)
```

**效果**: surface-aggregator round 1 的 input token 200K → 5K (-97%), 1 round wall-clock 30s → 3s。

---

### Layer 2 — 砍 token / 砍启动开销（次大头，预计 30% 提速）

#### S6. spawn 锁内去掉同步 DB 查（-50ms × 100 spawn）

**现状**：`sessions.py:566-580` 在 `async with spawn_lock` 块内调 `_count_active_children` → `mgr.list_sessions(parent_session_key)`, 这是同步 SQL。
**改**：把 count 缓存到内存, 锁外先估算, 锁内只 create。

```python
# sessions.py:566-580 改:
# 锁外: cached = self._active_children_cache.get(parent_session_key, 0)
# 锁内: 乐观创建, DB 唯一约束冲突时 (max_children 触顶) 才走 _count_active_children
```

**效果**: 每 spawn -50ms × 100 spawn = -5s (单独不大, 但叠加 S2 后 spawn 真正并行, 整体可观)。

#### S7. System prompt 拆分 + 动态加载（-50% input token）

**现状**: find SOUL 56KB + 13 specialist SOUL (平均 12K) 都在 system_prompt 注入。但**实际 1 个 turn 只需要相关章节**。
**改**：`opensquilla/prompt/loader.py` 增加 "section-on-demand" 工具。

```python
# 新工具 src/opensquilla/tools/builtin/find_context.py
@tool(name="find_load_section", ...)
async def find_load_section(
    section: str,  # "F0_DAG" | "F1.5_ENVELOPE" | "DEDUPE_RULES" | ...
) -> str:
    """按需加载 find SOUL 内的某个章节, 返回字符串。
    编排器 LLM 在第一次需要时调, 后续 round 命中 cache。"""
```

**效果**: 输入 token 80K → 30K, 每 round 节省 1-2s。

#### S8. F2.5 跨 owner dispatch 链改成 "单 envelope 直接 spawn"（-3 round）

**现状**：`SOUL_BODY.md:447-485` find 拼 envelope → sessions_spawn(hack-deep) → hack-deep 解析后再 spawn(vulnerability-triage) → ack 回路, 5 跳。
**改**：find 把 vulnerability-triage 的 allow_agents 临时开起来（短 TTL），单 envelope 直 spawn, hack-deep 不参与中转。

```python
# config 改: hack-deep-find 的 allow_agents 临时加入 vulnerability-triage (session-only override)
# sessions_spawn 时 check 子 session 的 allow_agents, 由 orchestrator 注入临时 grant
```

**效果**: F2.5 5 round → 2 round, 跨 owner 调度时间 30s → 8s。

---

### Layer 3 — 健壮性 / 抗失败（剩余 10% 提速 + 抗长尾）

#### S9. mid-run checkpoint + 断点续跑（-90% 失败重跑时间）

**现状**: 35 分钟跑到 30 分钟失败 → 0 进度保留, 重跑再 35 分钟。
**改**：

```python
# 新工具 src/opensquilla/tools/builtin/asset_tree/checkpoint.py
@tool(name="asset_tree_checkpoint", ...)
async def asset_tree_checkpoint(
    tree_id: str, phase: str,  # "F0.5" | "F1" | "F1.5" | "F3.5" | "F-final-pre"
) -> str:
    """落盘 phase 完成标记 + 已 ingest evidence 路径列表。
    resume_run() 读 checkpoint 跳过已完成 phase。"""
```

**效果**: 中途挂掉 → resume 跳过已完成 phase, 重跑时间 30min → 5min。

---

## 3. 实施优先级（影响 × 改动量）

| 序 | 编号 | 改动量 | 单项提速 | 推荐顺序 |
|----|------|--------|----------|----------|
| 1 | S1 (batch_dispatch) | 1 新工具 + 2 处 SOUL 改 | -15% | **P0** |
| 2 | S2 (spawn 锁粒度) | sessions.py ~30 行 | -10% | **P0** |
| 3 | S3 (dns_batch) | 1 新工具 + 1 处 SOUL 改 | -15% | **P0** |
| 4 | S5 (priority_candidates) | 1 新工具 + 1 处 SOUL 改 | -10% | **P1** |
| 5 | S4 (http_batch_probe) | 1 新工具 + 3 处 SOUL 改 | -15% | **P1** |
| 6 | S7 (prompt section loader) | 1 新工具 + SOUL 重排 | -10% | **P1** |
| 7 | S6 (count cache) | sessions.py ~20 行 | -2% | **P2** |
| 8 | S8 (F2.5 直 spawn) | config + 1 处 SOUL 改 | -3% | **P2** |
| 9 | S9 (checkpoint) | 1 新工具 + resume 入口 | 抗失败 | **P2** |

**P0 必做**（S1+S2+S3）合计 -40% round 数, 提速 50-60%。
**P1 配合**（S5+S4+S7）合计再 -50% wall-clock 与 -50% token。
**P2 收尾**（S6+S8+S9）打磨与抗失败。

---

## 4. 风险与回滚

| 风险 | 缓解 |
|------|------|
| S2 拆锁破坏 max_children 原子性 | 加 per-parent "active child count" in-memory 缓存 + 单写者协程, 锁只在 cache miss 时退化到 SQL |
| S3 批量 DNS 触发 rate-limit | `concurrency` 参数默认 32, 提供 `OPENSQUILLA_RECON_BATCH_CONCURRENCY` env 限速 |
| S5 启发式打分漏掉低分但高危的节点 | 设 score < 30 的节点也保留 10% 抽样进 LLM |
| S4 HTTP 批探针错过 specialist 自定义 header | specialist 可选传 `extra_headers` 覆盖 |
| S1 batch 失败 1 个不影响其他 | 工具内部 per-(parent, spec) 独立 try/except, 失败进 error[] 字段 |
| S7 章节缓存失效导致 stale | 缓存 key = (agent_id, file_mtime), mtime 变化自动 reload |

回滚策略: S1/S3/S4/S5 全部是**新工具** + **SOUL 文字**, 不动老工具; 只需把 SOUL 改回旧版, 立刻退到 v4 当前行为。

---

## 5. 度量指标 (上线后必须看)

埋点（建议加到 `src/opensquilla/observability/`）:
- `find_wall_clock_total_seconds{root_domain}` (histogram)
- `find_llm_round_count{phase}` (counter)
- `find_spawn_serial_wait_ms` (histogram, 来自 spawn_lock)
- `find_specialist_tool_call_count{specialist, tool}` (counter)
- `find_input_token_count{round}` (histogram)

回归测试（已有 `tests/agents/test_hack_deep_find_contracts.py`）新增:
- `tests/perf/test_hack_deep_find_speed.py`: 固定 root_domain 录下 wall-clock, 阈值 < 600s (P0+P1 上线后)。

---

## 6. 不在本次范围

- hack-deep / hack-deep-ex 的优化 (另外的 run)
- 换更快的底层 LLM provider
- 引入持久化 message queue (本方案靠现有 background_completion_manager 即可)
- 改写 LLM-coordinator 为纯 Python 状态机 (这是根本解, 但工作量是 10x)
