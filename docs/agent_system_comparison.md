# Agent 系统对比报告：Claude-BugHunter vs OpenSquilla

## 1. 架构概览

| 维度 | Claude-BugHunter | OpenSquilla |
|------|------------------|-------------|
| **定位** | Bug Bounty / 红队技能包 | 企业级 Agent 运行时 |
| **核心范式** | Skills + Engine 编排 | 微内核 + MCP-native |
| **LLM 调用** | `claude -p` 子进程 | Provider 抽象层 |
| **工具集成** | Burp MCP + 受限 Bash | MCP Server + 插件系统 |
| **状态管理** | 文件系统 (JSON) | SQLModel + PostgreSQL |
| **部署形态** | 单机 CLI | Gateway 服务 + Web UI |

---

## 2. Agent 编排对比

### Claude-BugHunter Engine

```
scope → recon → rank → hunt → validate → report
```

- **确定性控制流**：LLM 只在 recon/hunt/validate 阶段介入
- **Scope 边界强制**：代码级过滤，recon 发现只保留 in-scope 目标
- **状态持久化**：每步写入 `state.json`，支持断点续跑
- **优先级排序**：基于漏洞类别的确定性权重（rce=100, sqli=90, ...）

```python
# engine.py 核心循环
for wave in scope.waves():
    items = rank(wave, state)  # 确定性排序
    for item in items:
        evidence = run_agent(hunt_task(item), skills_on=True)
        state.add_finding(evidence)
```

### OpenSquilla Wave Executor

```
Wave DAG → Typed Envelope → Specialist → Evidence Schema → Artifact Persistence
```

- **波次 DAG**：支持依赖关系和扇出（single/static/dynamic）
- **类型化信封**：HandoffEnvelope 强制 schema 校验
- **证据持久化**：每波输出写入 `<artifact_root>/<wave>/<handoff_id>.json`
- **Drill-in 机制**：支持深入探测（Wn.5a/b/c）

```python
# executor.py 核心
for wave in dag.topological():
    envelope = build_envelope(wave, upstream_evidence)
    evidence = specialist_fn(envelope, brief)
    validate(evidence, wave.evidence_schema)
    persist(evidence, artifact_path)
```

---

## 3. 技能/知识系统

### Claude-BugHunter Skills

- **71 个专业技能**，每个是独立的 Markdown 文件
- **681 个漏洞报告模式**，覆盖 24 个核心漏洞类别
- **结构化元数据**：name, description, sources, report_count
- **按漏洞类型组织**：hunt-sqli, hunt-xss, hunt-rce, ...

```yaml
# skills/hunt-sqli/SKILL.md
---
name: hunt-sqli
description: Hunting skill for sqli vulnerabilities
sources: github, hackerone_public
report_count: 12
---
## Crown Jewel Targets
- SaaS platforms with multi-tenant databases
- E-commerce/payment systems
...
```

### OpenSquilla Agent Contracts

- **SOUL.md / ATTRIBUTION.md**：每个 agent 的身份和归属
- **Specialist Subagents**：6 个专业探测器
  - subdomain-discoverer
  - ip-resolver
  - port-scanner
  - service-fingerprint
  - endpoint-crawler
  - leaf-verifier
- **Config-backed Registry**：Agent 注册在 TOML 配置中

```python
# specialists/__init__.py
_SUBMODULES = (
    "subdomain_discoverer",
    "ip_resolver",
    "port_scanner",
    "service_fingerprint",
    "endpoint_crawler",
    "leaf_verifier",
)
```

---

## 4. 工具集成对比

### Claude-BugHunter

```python
ALLOWED_TOOLS = [
    "mcp__burp__send_http1_request",
    "mcp__burp__send_http2_request",
    "mcp__burp__get_collaborator_interactions",
    "Bash(curl:*)", "Bash(python3:*)", "Bash(jq:*)",
]
```

- **Burp Suite 深度集成**：HTTP 请求、Collaborator、被动扫描
- **受限 Bash**：只允许 curl/python3/jq/openssl/base64
- **Skills 禁用优化**：eval 显示 skills 添加 ~12-15k tokens 但能力提升有限

### OpenSquilla

- **MCP-native**：工具通过 MCP 协议注册
- **插件系统**：`plugins/` 目录支持动态加载
- **Sandbox 隔离**：`sandbox/` 模块提供执行隔离
- **工具边界**：`tool_boundary.py` 定义工具调用范围

---

## 5. 状态与持久化

### Claude-BugHunter

```
<engagement>/
  state.json      # 表面资产、工作列表、已测试、候选发现、已确认
  engine.log      # 追加日志
  evidence/       # 每个发现的证据文件
  report.md       # 最终报告
```

- **JSON 文件**：简单、可审计、可恢复
- **原子写入**：先写 `.tmp` 再 `os.replace`

### OpenSquilla

- **SQLModel + PostgreSQL**：结构化持久化
- **Session 管理**：`AgentTaskRecord` 追踪任务状态
- **Artifact 持久化**：波次证据写入文件系统
- **迁移系统**：`migration/` 支持 schema 升级

---

## 6. Scope 与安全控制

### Claude-BugHunter

```python
class Scope:
    def __init__(self, config):
        self.domains = config.get("domains", [])
        self.exclude = config.get("exclude", [])
    
    def in_scope(self, host):
        return any(host.endswith(d) for d in self.domains)
```

- **硬边界**：recon 发现自动过滤 out-of-scope
- **Hunt 不越界**：永远不会在 out-of-scope 目标上 dispatch
- **权限模式**：`bypassPermissions`（因为是受控环境）

### OpenSquilla

- **Agent Identity**：`AgentIdentity` + `AgentProfile`
- **Capability 声明**：`AgentCapability` 定义能力边界
- **Safety 模块**：`safety/` 提供安全检查
- **Permissions**：`permissions.py` 定义访问控制

---

## 7. 可吸纳的点

### 从 Claude-BugHunter 吸纳

| 特性 | 价值 | 实现建议 |
|------|------|----------|
| **Skills 元数据结构** | 知识可搜索、可统计 | 在 `agents/` 中添加 SKILL.md 元数据 |
| **漏洞报告模式库** | 681 个实战模式 | 移植到 `skills/` 或 `contracts/` |
| **确定性优先级排序** | 减少 LLM 调用 | 在 `attack_dispatch` 中添加 rank 模块 |
| **Engagement 文件夹结构** | 可审计、可恢复 | 参考 `state.json` 设计 |
| **Scope 硬边界** | 防止越界探测 | 强化 `scope.py` 的过滤逻辑 |
| **原子状态写入** | 防止损坏 | 在 `persistence/` 中应用 |
| **Collaborator 集成** | 被动交互收集 | 通过 MCP 集成 Burp Collaborator |
| **报告生成模板** | 标准化输出 | 添加 `reporting/` 模块 |

### OpenSquilla 的优势（保持）

| 特性 | 价值 |
|------|------|
| **微内核架构** | 可扩展、可测试 |
| **MCP-native** | 工具生态兼容 |
| **类型化信封** | 强类型保证 |
| **波次 DAG** | 复杂依赖编排 |
| **多通道消息** | 灵活的交互方式 |
| **SQLModel 持久化** | 企业级数据管理 |

---

## 8. 具体实现建议

### 1. 添加 Skills 元数据层

```python
# opensquilla/skills/metadata.py
from pydantic import BaseModel

class SkillMetadata(BaseModel):
    name: str
    description: str
    sources: list[str] = []
    report_count: int = 0
    tags: list[str] = []
    
    @classmethod
    def from_md(cls, path: Path) -> "SkillMetadata":
        """从 SKILL.md 解析元数据"""
        content = path.read_text()
        # 解析 YAML frontmatter
        ...
```

### 2. 移植漏洞模式库

```bash
# 将 Claude-BugHunter 的 skills 复制到 opensquilla
cp -r /Users/zlpc/Downloads/Claude-BugHunter/skills/hunt-* \
      src/opensquilla/skills/vuln-patterns/
```

### 3. 增强 Scope 硬边界

```python
# opensquilla/agents/scope.py
class ScopeGuard:
    def __init__(self, config: ScopeConfig):
        self.allowed_domains = set(config.domains)
        self.blocked_patterns = config.exclude
    
    def filter_targets(self, targets: list[str]) -> list[str]:
        """硬过滤 out-of-scope 目标"""
        return [t for t in targets if self._in_scope(t)]
    
    def _in_scope(self, target: str) -> bool:
        return (
            any(target.endswith(d) for d in self.allowed_domains)
            and not any(re.search(p, target) for p in self.blocked_patterns)
        )
```

### 4. 添加确定性排序模块

```python
# opensquilla/attack_dispatch/ranking.py
CLASS_WEIGHT = {
    "rce": 100, "sqli": 90, "ssrf": 85, "auth-bypass": 85,
    "idor": 80, "deserialization": 88, "xxe": 75, "ssti": 88,
    "lfi": 78, "xss": 55, "cors": 45, "csrf": 50,
}

def rank_findings(findings: list[Finding]) -> list[Finding]:
    """基于漏洞类别的确定性排序"""
    return sorted(findings, key=lambda f: CLASS_WEIGHT.get(f.category, 0), reverse=True)
```

### 5. Engagement 持久化结构

```
<session_dir>/
  engagement.json    # 会话元数据
  state.json         # 当前状态快照
  evidence/          # 每波证据
    wave_01/
    wave_02/
  findings/          # 已确认发现
  report.md          # 生成的报告
```

---

## 9. 总结

| 维度 | Claude-BugHunter | OpenSquilla | 建议 |
|------|------------------|-------------|------|
| **知识密度** | ⭐⭐⭐⭐⭐ (71 skills, 681 patterns) | ⭐⭐ (6 specialists) | 吸纳漏洞模式库 |
| **架构扩展性** | ⭐⭐ (单机 CLI) | ⭐⭐⭐⭐⭐ (微内核) | 保持 OpenSquilla 架构 |
| **工具生态** | ⭐⭐⭐ (Burp-focused) | ⭐⭐⭐⭐ (MCP-native) | 保持 MCP 生态 |
| **状态管理** | ⭐⭐⭐ (JSON files) | ⭐⭐⭐⭐ (SQLModel) | 保持 SQLModel |
| **安全边界** | ⭐⭐⭐⭐ (硬 scope) | ⭐⭐⭐ (软 scope) | 强化 scope 硬边界 |
| **可审计性** | ⭐⭐⭐⭐ (文件日志) | ⭐⭐⭐ (需要增强) | 添加 engagement 日志 |

**核心结论**：Claude-BugHunter 的价值在于其**知识密度**（71 skills + 681 漏洞模式）和**确定性控制流**，而 OpenSquilla 的优势在于**架构扩展性**和**企业级持久化**。最佳策略是将前者的知识库和控制模式移植到后者的架构中。
