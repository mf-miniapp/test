# hack-deep-find Batch 1 — Web 表面深度收口 + 组件级 CVE 视角

Date: 2026-06-15
Status: Draft (评审中)
Owner: OpenSquilla / recon-team
Depends on: hack-deep-find v2 (Phase 2 已经 shipped 6 specialist) / asset_tree v2 (18 AssetType)
Supersedes: 2026-06-14 hack-deep-find v2 redesign 中的 "Phase 2 = 6 specialist" 范围

## 1. Goal

把 `hack-deep-find` 从"主链 + 末端端点扁平列表"升级为**主链 + Web 表面 8 类资产 + 组件级 CVE 视角**的全景图。具体在 Batch 1 内交付 5 个新 specialist:

| ID | 输入 | 输出 | 作用 |
|---|---|---|---|
| [6] `service-detailed` | SERVICE | COMPONENT | 把 banner / 响应头 / JS bundle 解析成 `product:version:cpe` 节点, 直接对接 CVE 数据库 |
| [7] `webapp-discoverer` | SERVICE | URL (多个) | 识别同一 ip:port 上的多个 web 应用 (vhost / port / path 划分) |
| [8] `api-surface` | URL | API_SCHEMA + ENDPOINT | 拉 OpenAPI / GraphQL SDL, 提取结构化 endpoint |
| [9] `parameter-extract` | ENDPOINT | PARAMETER | 从 path / query / header / cookie / body 提取参数 |
| [11] `static-asset` | URL | STATIC_ASSET | 把 `/.env` `/swagger.json` `/.git/HEAD` `/backup.zip` 等高价值静态文件单独建节点 |

**Batch 1 不做 (后续 Batch)**:
- [10] `auth-mapper` (Batch 2) — login/SSO/OAuth/JWT
- [12] `cookie-header` (Batch 2) — Cookie 头/安全头
- [13] `cloud-storage` (Batch 3) — S3/OSS/Blob
- [14] `secret-scanner` (Batch 3) — 凭证扫描
- [1][2] 横向/合并 (Batch 4) — ASN/Org seed + 资产合并器
- Batch 5 — 时间维度 (diff 扫描)

## 2. Background — 为什么需要 Batch 1

`hack-deep-find` v2 (Phase 2, 2026-06-14) shipped 了 6 个 specialist, 主链深度:
`ROOT_DOMAIN → SUB_DOMAIN → IP → PORT → SERVICE → ENDPOINT (扁平)`

但 `opensquilla.asset_tree.models` 在设计阶段就承诺了 18 个 AssetType, 其中 9 类资产 (URL / API_SCHEMA / PARAMETER / INJECTION_VECTOR / AUTH_SURFACE / STATIC_ASSET / COOKIE / HEADER / COMPONENT) 至今**没有任何 specialist 在生产**。后果是:

1. **一 ip:port 多应用场景**丢失 — 反向代理挂了 N 个 vhost, `endpoint-crawler` 只看到 21 词根路径
2. **API 表面扁平化** — OpenAPI/GraphQL 没有结构化抽取, 100 个 endpoint 跟 100 个静态资源一样扁平
3. **CVE 视角缺失** — `service-fingerprint` 输出 `service_name="nginx"` `version="1.24.0"`, 树里没有 COMPONENT 节点, `hack-deep` 端做漏洞匹配时**没办法把 banner → CVE 拍平**
4. **参数级洞点不可下钻** — `INJECTION_VECTOR` (param × vuln-type) 是设计承诺, 没有 PARAMETER 节点就没法下钻
5. **高价值静态文件淹没在端点里** — `/.env` 命中 200 跟 `/favicon.ico` 一样, 没法差异化优先级

**关键问题** (上一轮对齐的 3 个架构级问题):
1. ✅ specialist 数量: 按 20 个走, 一职责一 specialist, 不合并
2. ✅ Batch 顺序: 1 → 2 → 3 顺序
3. ❓ **PARAMETER / INJECTION_VECTOR 范围**: 本 Batch 只做 PARAMETER, INJECTION_VECTOR 留到 `hack-deep` 端做漏洞挖掘时再下钻 (scope 收敛, handoff 数据完整即可, 探测阶段不要扩张)

## 3. Non-Goals

- **不实现 PARAMETER → INJECTION_VECTOR 的下钻**: 那是 `hack-deep` 漏洞挖掘阶段的事, `hack-deep-find` 只生产 PARAMETER 节点 + 给每个参数打 `inferred_type` 元数据 (`number` / `string` / `email` / `uuid` / `path` / `header_name` / `cookie_name`), `hack-deep` 自己拍 vuln-type
- **不引入新数据库 / 新表**: 复用 `asset_nodes` + `asset_tree` JSONL 持久化
- **不替换 `service-fingerprint`**: Batch 1 新加的 `service-detailed` 跟 `service-fingerprint` **并存**, 前者专注于 COMPONENT 输出 (CVE 视角), 后者继续产 SERVICE 节点 (网络协议视角)
- **不破坏现有 6 specialist 的 SOUL 契约**: ATTRIBUTION_BODY.md 既有 schema (`subdomain-v1` / `ip-v1` / `port-v1` / `service-v1` / `endpoint-v1` / `leaf-v1`) 不动
- **不增加 6 specialist 之外的 recon 工具组命名空间**: 新工具全部归入 `group:recon:webapp` / `group:recon:api` / `group:recon:component` 三个新组, 避免继续污染 `group:recon:http`

## 4. Design Decisions

### 4.1 Node Type 新增/确认

| AssetType | 现状 | Batch 1 改动 |
|---|---|---|
| `URL` | 已定义, 无 specialist | **新增 specialist [7] webapp-discoverer** 生产 |
| `ENDPOINT` | 已定义, 有 specialist | **保留** specialist, 升级 schema 加 `api_schema_id` 关联字段 |
| `PARAMETER` | 已定义, 无 specialist | **新增 specialist [9] parameter-extract** 生产 |
| `API_SCHEMA` | 已定义, 无 specialist | **新增 specialist [8] api-surface** 生产 |
| `STATIC_ASSET` | 已定义, 无 specialist | **新增 specialist [11] static-asset** 生产 |
| `COMPONENT` | 已定义, 无 specialist | **新增 specialist [6] service-detailed** 生产 |

`INJECTION_VECTOR` / `AUTH_SURFACE` / `COOKIE` / `HEADER` / `STORAGE` / `STORAGE_OBJECT` / `SECRET` 留后续 Batch, 本 Batch **不**创建。

### 4.2 父子关系 (在 `_VALID_PARENT_CHILD` 基础上扩展)

Batch 1 不需要改 `_VALID_PARENT_CHILD` (现有约束已经包含所有新增节点的合法挂载点)。验证:

```
SERVICE     →  URL              ✓ 已有
SERVICE     →  COMPONENT        ✓ 已有
URL         →  ENDPOINT         ✓ 已有
URL         →  API_SCHEMA       ✓ 已有
URL         →  STATIC_ASSET     ✓ 已有
URL         →  COMPONENT        ✓ 已有 (JS bundle 视角)
ENDPOINT    →  PARAMETER        ✓ 已有
```

### 4.3 Metadata 字段约定 (按节点类型)

新 specialist 写入的 `metadata` 字典必须遵循下列 schema, **强一致性** (后续 `asset_tree_stats` 报告 / `brief_gen` 都按这 schema 取数):

#### `URL` 节点
```python
{
    "scheme": "https" | "http",
    "host": "api.example.com" | "1.2.3.4",
    "port": 443,
    "base_path": "/api/v1" | "",
    "vhost": "api.example.com" | null,
    "app_type": "spring-boot" | "next.js" | "wordpress" | "django" | "express" | "nginx-proxy" | "unknown",
    "tech_stack": ["nginx/1.24.0", "php/8.2"],
    "tls": True | False,
    "sni_required": True | False,
    "auth_context": "none" | "basic" | "bearer" | "cookie" | "sso_redirect",
    "discovery_mode": "vhost" | "port" | "path",
    "siblings_count": 4,
}
```

#### `ENDPOINT` 节点 (扩展)
```python
{
    "method": "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD" | "WS" | "GRAPHQL",
    "path": "/api/v1/users/{id}",
    "status": 200 | 404 | 401 | 500,
    "content_type": "application/json" | "text/html" | "...",
    "title": "Admin Panel" | null,
    "source": "openapi" | "graphql" | "directory_bruteforce" | "js_extract" | "manual",
    "api_schema_id": "abc123def456" | null,
    "params_summary": {
        "path": ["id"],
        "query": ["q", "page"],
        "header": ["Authorization"],
        "cookie": ["session"],
    },
    "auth_required": True | False,
    "idempotent": True | False,
    "http_version": "HTTP/1.1" | "HTTP/2",
    "response_size": 1234,
}
```

#### `API_SCHEMA` 节点
```python
{
    "schema_type": "openapi" | "swagger" | "graphql" | "postman" | "grpc_reflection" | "wsdl" | "wadl",
    "schema_version": "3.0.3" | "2.0" | null,
    "schema_url": "https://api.example.com/v3/api-docs",
    "endpoint_count": 47,
    "title": "Example API" | null,
    "version": "1.2.0" | null,
    "auth_schemes": ["bearer", "apiKey", "oauth2"],
    "server_urls": ["https://api.example.com"],
    "graphql_endpoint": "/graphql" | null,
    "raw_size": 38412,
    "parse_status": "ok" | "truncated" | "error",
}
```

#### `PARAMETER` 节点
```python
{
    "name": "id" | "q" | "Authorization" | "session",
    "location": "path" | "query" | "header" | "cookie" | "body_form" | "body_json" | "body_xml",
    "inferred_type": "integer" | "string" | "uuid" | "email" | "boolean" | "date" | "base64" | "url" | "filename" | "free_text" | "header_name" | "cookie_name",
    "required": True | False,
    "default_value": "100" | null,
    "enum_values": ["active", "disabled"] | null,
    "pattern": "^[a-z0-9-]{36}$" | null,
    "example": "550e8400-e29b-41d4-a716-446655440000" | null,
    "sensitivity": "credential" | "pii" | "internal_id" | "public" | "unknown",
    "source": "openapi" | "graphql" | "path_pattern" | "form_parse" | "json_schema",
}
```

#### `STATIC_ASSET` 节点
```python
{
    "path": "/.env" | "/swagger.json" | "/backup.zip",
    "status": 200 | 403 | 404 | 401,
    "content_type": "application/octet-stream" | "application/json" | "text/plain" | "application/zip",
    "size": 1234 | 0,
    "category": "config" | "backup" | "vcs" | "docs" | "debug" | "metadata" | "api_doc" | "credential",
    "sensitivity": "critical" | "high" | "medium" | "low" | "info",
    "signature": "aws_access_key_id" | "jwt_token" | "private_key" | "db_connection_string" | null,
    "etag": "W/\"5d8c...\"",
    "last_modified": "2025-12-01T12:34:56Z" | null,
    "auth_required": True | False,
    "vcs_exposed": True | False,
    "source": "directory_bruteforce" | "robots_sitemap" | "js_extract" | "extension_variant",
}
```

#### `COMPONENT` 节点
```python
{
    "product": "nginx" | "spring-boot" | "mysql" | "openssl" | "lodash" | "...",
    "version": "1.24.0" | null,
    "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" | null,
    "vendor": "f5" | "oracle" | "apache" | "nodejs" | null,
    "source": "banner" | "server_header" | "x_powered_by" | "js_bundle" | "ico_hash" | "tls_cert" | "html_meta",
    "evidence": "nginx/1.24.0",
    "confidence": "high" | "medium" | "low",
    "cve_relevant": True | False,
    "extracted_at": "service" | "url",
}
```

### 4.4 Specialist 通用契约

5 个新 specialist 全部沿用现有 6 specialist 的契约范式 (见 `src/opensquilla/agents/hack-deep-find/specialists/<id>/SOUL_BODY.md`):

- **输入**: 来自编排器 LLM 拼装的 HANDOFF envelope, 第一行 `HANDOFF W{wave}.{specialist}.{seq} | deps=empty | schema={schema}-v1 | eta={seconds}`
- **输出**: JSON evidence payload + 最后一行 `RESULT MARKER: schema: {x} | phase: evidence-collection | wave: {N/M} | deps: empty`
- **不可递归**: `subagents.allow_agents=[]`, 不调 `sessions_spawn`
- **写树**: 编排器 LLM 在收到 evidence 后调 `asset_tree_add_nodes` 写入, specialist 自己**不**调 `asset_tree_*` 工具 (保持与现有 6 specialist 一致)

### 4.5 新增工具组 (4 组)

| 工具组 | 包含的工具 (草拟) | 用途 |
|---|---|---|
| `group:recon:webapp` | `recon_vhost_bruteforce`, `recon_robots_sitemap`, `recon_tech_detect`, `recon_app_fingerprint`, `recon_url_dedupe` | 服务指纹 → web 应用边界识别 |
| `group:recon:api` | `recon_openapi_parse`, `recon_graphql_introspect`, `recon_js_crawl_recursive`, `recon_api_path_normalize`, `recon_auth_probe` | URL → API_SCHEMA + 结构化 ENDPOINT |
| `group:recon:component` | `recon_cpe_resolve`, `recon_js_component_extract`, `recon_tls_cert_parse`, `recon_ico_hash_lookup` | 指纹 → CPE 格式组件 |
| `group:recon:sensitive` | `recon_sensitive_fingerprint`, `recon_sensitive_variants`, `recon_secret_extract` | 静态资源/响应体敏感度打标 |

工具组注册在 `src/opensquilla/tools/policy_config.py` 的 `_TOOL_GROUPS` dict 里, 跟现有 `group:recon:dns` / `group:recon:portscan` / `group:recon:http` 平级。

### 4.6 编排器 (hack-deep-find SOUL) 升级

**当前编排循环** (`SOUL_BODY.md:84-100`) 写死 `current_layer_type` 取最低层级, 6 个 specialist 顺序处理。新编排循环需要:

1. **分层执行**: 按资产层级深度执行, 同一层全部 UNSEEN 处理完才进下一层
2. **并行扇出**: 同一层多个 UNSEEN 节点并发 `sessions_spawn` (用 `sessions_spawn_batch` 模式, 一次发多个 envelope, 等 wave barrier)
3. **写树前先 dedupe**: `asset_tree_add_nodes` 之前 LLM 自己做去重判断 (URL/endpoint/path 的等价类), 避免重复建节点

**SOUL_BODY.md 新增章节** (放 Step N 之后, Step FINAL 之前):

```
### Step N.5: 分层调度 (Batch 1 引入)

每波次开始时:
1. asset_tree_find_unseen(tree_id, asset_type=<current_layer>) → 本层 UNSEEN 节点
2. 如果本层 UNSEEN 非空:
   a. 按节点类型查 specialist 表 → 得到 specialist_id
   b. **批量发包**: 一次 sessions_spawn 所有 UNSEEN 节点 (不是逐个)
   c. sessions_yield() 收口
   d. 解析所有 specialist 返回, 写树, 更新 state
   e. 回到 Step N.5 顶部
3. 如果本层 UNSEEN 为空:
   a. 找下一层 (asset_tree_find_unseen 不带 filter, 选最低层级)
   b. 跳到 Step N.5.1
```

**specialist 选择表扩充**:

| asset_type | specialist_id | tools group |
|---|---|---|
| `root_domain` | `subdomain-discoverer` (Phase 2) | `group:recon:dns` |
| `sub_domain` | `ip-resolver` (Phase 2) | `group:recon:dns` |
| `ip` | `port-scanner` (Phase 2) | `group:recon:portscan` |
| `port` | `service-fingerprint` (Phase 2) | `group:recon:portscan` |
| `service` | `service-detailed` (Batch 1 **[6]**) + `webapp-discoverer` (Batch 1 **[7]**) | `group:recon:component` + `group:recon:webapp` |
| `url` | `api-surface` (Batch 1 **[8]**) + `static-asset` (Batch 1 **[11]**) | `group:recon:api` + `group:recon:sensitive` |
| `endpoint` | `parameter-extract` (Batch 1 **[9]**) | `group:recon:api` |
| `parameter` | (no specialist — leaf-verifier 收尾) | `group:recon:http` |
| `api_schema` | (no specialist — leaf-verifier 收尾) | `group:recon:http` |
| `static_asset` | `leaf-verifier` 收尾 | `group:recon:http` |
| `component` | (no specialist — leaf-verifier 收尾) | `group:recon:http` |
| `secret` / `cookie` / `header` / `storage*` / `auth_surface` / `injection_vector` | (后续 Batch) | — |

**SERVICE 层双 specialist 并行**:
`service-detailed` 和 `webapp-discoverer` 输入都是 SERVICE, **同一波次并发发包** (不串行), evidence 回来后由编排器 LLM 合并写树 (SERVICE 节点的子节点同时含 COMPONENT 和 URL)。

### 4.7 持久化与 handoff

- 树持久化路径不变: `~/.opensquilla/state/asset_trees/<tree_id>.json`
- `asset_tree_complete` 返回的 `tree_path` 仍是 handoff 入口
- `find-complete-v1` schema **不**需要扩展 — `tree_stats` 字段已经能反映新类型分布
- `hack-deep` 接收端不需要改 SOUL — 它按节点类型遍历, 遇到 PARAMETER / API_SCHEMA / STATIC_ASSET / COMPONENT 自然会用对应 vulnerability 规则

## 5. Specialist 详细契约

### 5.1 [6] service-detailed

```
SOUL_BODY.md — SERVICE-DETAILED (SERVICE → COMPONENT)
```

#### 强制约束
- `subagents.allow_agents=[]`, 不递归
- 可用工具: `recon_cpe_resolve`, `recon_js_component_extract`, `recon_tls_cert_parse`, `recon_ico_hash_lookup` (新工具组 `group:recon:component`)

#### 任务流程
1. 解析 envelope → service (含 product hint from service-fingerprint)
2. 多源指纹采集 (并发):
   - `recon_cpe_resolve(product, version)` → CPE 2.3 字符串 + NVD 候选
   - `recon_js_component_extract(base_url)` → 拉主 HTML/JS, 解析前端库 (React/Vue/lodash/jquery 版本)
   - `recon_tls_cert_parse(ip, port)` → 证书 subject/issuer/SAN 中的软件信息
   - `recon_ico_hash_lookup(base_url)` → favicon hash 查 shodan/censys/二进制指纹库
3. 聚类去重: 同一 (product, version) 只产一个 COMPONENT 节点
4. 写 evidence schema: `component-v1`

#### Evidence Schema: `component-v1`

| 字段 | 类型 | 必填 | 描述 |
|---|---|---|---|
| `evidence_schema` | `"component-v1"` | yes |  |
| `service` | `str` | yes | 输入 service 名 |
| `components` | `list[ComponentEntry]` | yes |  |
| `ComponentEntry.product` | `str` | yes |  |
| `ComponentEntry.version` | `str \| null` | no |  |
| `ComponentEntry.cpe` | `str \| null` | no | CPE 2.3 字符串 |
| `ComponentEntry.vendor` | `str \| null` | no |  |
| `ComponentEntry.source` | `str` | yes | `banner` / `server_header` / `x_powered_by` / `js_bundle` / `ico_hash` / `tls_cert` / `html_meta` |
| `ComponentEntry.evidence` | `str` | yes | 原始证据 (如 `"nginx/1.24.0"`) |
| `ComponentEntry.confidence` | `str` | yes | `high` / `medium` / `low` |
| `ComponentEntry.cve_relevant` | `bool` | yes | 是否可对接到 NVD 查询 |
| `ComponentEntry.extracted_at` | `str` | yes | `service` / `url` |

#### 终止条件
- `service-fingerprint` 未识别 product → 仍然调用 `recon_cpe_resolve(product="unknown", version="unknown")` 走兜底
- JS 提取失败 → 跳过, 记录到 `extra_info.skipped_sources`
- 证书解析失败 → 跳过 TLS 路径

#### 错误处理
- 单源失败不影响其他源
- 全部失败 → 输出 `components: []`, 仍输出合法 schema

### 5.2 [7] webapp-discoverer

```
SOUL_BODY.md — WEBAPP-DISCOVERER (SERVICE → URL, 多个)
```

#### 强制约束
- `subagents.allow_agents=[]`
- 可用工具: `recon_vhost_bruteforce`, `recon_robots_sitemap`, `recon_tech_detect`, `recon_app_fingerprint`, `recon_url_dedupe` (新工具组 `group:recon:webapp`)

#### 任务流程
1. 解析 envelope → service (含 ip:port)
2. **多模式并行**尝试 (互不互斥, 决定有多少 URL 节点):
   - **vhost 模式** (port = 80/443/8080/8443 时): `recon_vhost_bruteforce(base_url, wordlist)` → 用常见子域作 Host 头, 找差异响应
   - **port 模式**: scan 同 host 的 80/443/8080/8443/8000 等常见 web 端口 (这一步会让扫描器在 tree 中产生新的 SERVICE 节点 — LLM 编排器需提前规划)
   - **path 模式**: `recon_directory_bruteforce(base_url)` 命中明显应用路径 (如 `/admin`, `/api/v1`, `/console`) → 同一 ip:port 下不同 base_path 视为不同应用
3. `recon_tech_detect(base_url)` 提取技术栈 → 写入 URL 节点 `tech_stack`
4. `recon_robots_sitemap(base_url)` 解析 robots.txt / sitemap.xml → 启发更多 URL
5. `recon_url_dedupe(urls)` 聚类去重 (规范化 host:port/path)
6. 写 evidence schema: `webapp-v1`

#### Evidence Schema: `webapp-v1`

| 字段 | 类型 | 必填 | 描述 |
|---|---|---|---|
| `evidence_schema` | `"webapp-v1"` | yes |  |
| `service` | `str` | yes | 输入 service 名 |
| `base_host` | `str` | yes | service 节点的 host (IP 或 vhost) |
| `base_port` | `int` | yes |  |
| `urls` | `list[UrlEntry]` | yes |  |
| `UrlEntry.value` | `str` | yes | 唯一标识 (vhost 时是 host, path 时是 base_path) |
| `UrlEntry.scheme` | `str` | yes | `http` / `https` |
| `UrlEntry.host` | `str` | yes |  |
| `UrlEntry.port` | `int` | yes |  |
| `UrlEntry.base_path` | `str` | yes |  |
| `UrlEntry.vhost` | `str \| null` | no |  |
| `UrlEntry.app_type` | `str` | yes | `spring-boot` / `next.js` / `wordpress` / `django` / `express` / `nginx-proxy` / `unknown` |
| `UrlEntry.tech_stack` | `list[str]` | yes |  |
| `UrlEntry.tls` | `bool` | yes |  |
| `UrlEntry.sni_required` | `bool` | yes |  |
| `UrlEntry.auth_context` | `str` | yes | `none` / `basic` / `bearer` / `cookie` / `sso_redirect` |
| `UrlEntry.discovery_mode` | `str` | yes | `vhost` / `port` / `path` |
| `UrlEntry.siblings_count` | `int` | yes | 同 SERVICE 下还有几个 URL |

#### URL 节点 value 字段约定

为了在树里唯一标识 URL 节点, 编排器 LLM 写树时必须把以下字段组合成 `value` 字符串:

```
vhost 模式: "{scheme}://{vhost}:{port}{base_path}"   e.g. "https://api.example.com:443"
port  模式: "{scheme}://{host}:{port}{base_path}"     e.g. "https://1.2.3.4:8443"
path  模式: "{scheme}://{host}:{port}{base_path}"     e.g. "http://1.2.3.4:8080/admin"
```

#### 终止条件
- 单模式无结果: 跳过该模式, 继续其他
- 全部模式无结果: 输出 `urls: [{...siblings_count=0, discovery_mode="path", value=base_url...}]` (至少一个 URL, 默认 path 模式)

#### 错误处理
- vhost 爆破 5xx 普遍 → 标记 `app_type="unknown"`, 继续
- robots.txt 不存在 → `siblings_count` 仍计算 (根据其它模式)

### 5.3 [8] api-surface

```
SOUL_BODY.md — API-SURFACE (URL → API_SCHEMA + ENDPOINT)
```

#### 强制约束
- `subagents.allow_agents=[]`
- 可用工具: `recon_openapi_parse`, `recon_graphql_introspect`, `recon_js_crawl_recursive`, `recon_api_path_normalize`, `recon_auth_probe` (新工具组 `group:recon:api`)

#### 任务流程
1. 解析 envelope → url (含 scheme/host/port/base_path/auth_context)
2. **探测 API 文档存在性** (并发):
   - `recon_openapi_parse(base_url, candidates=["/v3/api-docs", "/v2/api-docs", "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json"])` → 返回 schema_url + parsed endpoints
   - `recon_graphql_introspect(base_url, candidates=["/graphql", "/api/graphql", "/gql"])` → 返回 introspection SDL
3. **API 路径抽取** (三种来源):
   - 上述 schema 解析出的 paths
   - `recon_js_crawl_recursive(entry_js_url, depth=3)` → 递归抓 main.js / chunk.js 的 API 路径
   - `recon_directory_bruteforce` 命中 `/api/*` 等路径
4. `recon_api_path_normalize(endpoints)` → 路径聚类 (如 `/users/123` `/users/456` → `/users/{id}`)
5. `recon_auth_probe(url)` → 检测 401/403 状态, 标 `auth_required`
6. 写 evidence schema: `api-surface-v1`, **同时**包含 `api_schema` 列表 + `endpoints` 列表 (编排器 LLM 据此分两次写树: 一次写 API_SCHEMA 节点, 一次写 ENDPOINT 节点 + 关联 `api_schema_id`)

#### Evidence Schema: `api-surface-v1`

| 字段 | 类型 | 必填 | 描述 |
|---|---|---|---|
| `evidence_schema` | `"api-surface-v1"` | yes |  |
| `url` | `str` | yes | 输入 URL value |
| `api_schemas` | `list[ApiSchemaEntry]` | yes | 发现的 schema |
| `endpoints` | `list[EndpointEntry]` | yes | 抽取的 endpoint (与现有 endpoint-v1 兼容 + 扩展字段) |
| `ApiSchemaEntry.schema_type` | `str` | yes | `openapi` / `graphql` / `postman` / `grpc_reflection` |
| `ApiSchemaEntry.schema_version` | `str \| null` | no |  |
| `ApiSchemaEntry.schema_url` | `str` | yes | 拉取 schema 的 URL |
| `ApiSchemaEntry.title` | `str \| null` | no |  |
| `ApiSchemaEntry.version` | `str \| null` | no |  |
| `ApiSchemaEntry.auth_schemes` | `list[str]` | yes |  |
| `ApiSchemaEntry.server_urls` | `list[str]` | yes |  |
| `ApiSchemaEntry.graphql_endpoint` | `str \| null` | no | GraphQL 专用 |
| `ApiSchemaEntry.raw_size` | `int` | yes |  |
| `ApiSchemaEntry.parse_status` | `str` | yes | `ok` / `truncated` / `error` |
| `ApiSchemaEntry.endpoint_count` | `int` | yes | schema 内声明的 endpoint 数 |
| `EndpointEntry.method` | `str` | yes |  |
| `EndpointEntry.path` | `str` | yes | normalized 后的 path (含 `{id}` 占位) |
| `EndpointEntry.source` | `str` | yes | `openapi` / `graphql` / `js_extract` / `directory_bruteforce` |
| `EndpointEntry.api_schema_id` | `str \| null` | no | 关联到 API_SCHEMA 节点 id (由编排器 LLM 写树时回填) |
| `EndpointEntry.params_summary` | `dict` | yes | `{path: [], query: [], header: [], cookie: []}` |
| `EndpointEntry.auth_required` | `bool` | yes |  |
| `EndpointEntry.idempotent` | `bool` | yes |  |
| `EndpointEntry.status` | `int \| null` | no | 探测观察到的状态 |
| `EndpointEntry.content_type` | `str \| null` | no |  |

#### 终止条件
- 全部 schema 探测失败 + JS 提取失败 + dirbust 无 API 路径 → 输出 `api_schemas: []`, `endpoints: []`, 仍合法

#### 与现有 endpoint-crawler 的边界

- **保留** `endpoint-crawler` 继续处理**非 URL 节点的 SERVICE** (例如非 web 协议服务的 endpoint 抽象)
- **新职责** `api-surface` 接管 URL 节点下的 API 抽取
- 编排器 LLM 在选择 specialist 时按父节点类型:
  - 父 = `SERVICE` → `endpoint-crawler` (Phase 2)
  - 父 = `URL` → `api-surface` (Batch 1)

#### 错误处理
- OpenAPI parse 失败: `parse_status="error"`, 不算入 endpoint_count
- JS 递归过深 (>3): 截断, 记录到 `extra_info.truncated_depth`
- GraphQL introspection 失败: 跳过, 标记 `error`

### 5.4 [9] parameter-extract

```
SOUL_BODY.md — PARAMETER-EXTRACT (ENDPOINT → PARAMETER, 多个)
```

#### 强制约束
- `subagents.allow_agents=[]`
- 可用工具: 复用 `group:recon:api` 里的部分工具 (不需要新工具组), 主要是 `recon_api_path_normalize` 的副作用

#### 任务流程
1. 解析 envelope → endpoint (含 method, path, api_schema_id 关联, params_summary)
2. **多源参数抽取** (按来源优先级):
   - 优先 OpenAPI/GraphQL: 直接从 schema 取 (路径 / 查询 / header / cookie 全部)
   - 其次路径模式识别: `/users/{id}/orders/{orderId}` → 2 个 path 参数
   - 再次 query string 启发: dirbust 命中时观察到的 query
   - 最后 body 字段: 如果 `content_type=application/json` 且探测过 POST, 试 `recon_directory_bruteforce` 后备 — 不行就标记 `inferred_type="unknown"`
3. **类型推断** (`inferred_type`):
   - OpenAPI 显式 → 直接用
   - 路径 `{id}` + 数字 → `integer`
   - 路径 `{uuid}` → `uuid`
   - 名字含 `email` / `mail` → `email`
   - 名字含 `id` / `uuid` / `guid` → `uuid`
   - 名字含 `date` / `time` / `timestamp` → `date`
   - 名字含 `Authorization` / `Cookie` / `Set-Cookie` / `X-Api-Key` → `header_name` / `cookie_name`
   - 其它 → `free_text`
4. **sensitivity 启发**:
   - 名字含 `password` / `passwd` / `secret` / `token` / `apikey` / `api_key` → `credential`
   - 名字含 `email` / `phone` / `mobile` / `id_card` / `ssn` → `pii`
   - 名字含 `user_id` / `account` / `org_id` → `internal_id`
   - 其它 → `public`
5. 写 evidence schema: `parameter-v1`

#### Evidence Schema: `parameter-v1`

| 字段 | 类型 | 必填 | 描述 |
|---|---|---|---|
| `evidence_schema` | `"parameter-v1"` | yes |  |
| `endpoint` | `str` | yes | 输入 endpoint value |
| `method` | `str` | yes |  |
| `parameters` | `list[ParameterEntry]` | yes |  |
| `ParameterEntry.name` | `str` | yes |  |
| `ParameterEntry.location` | `str` | yes | `path` / `query` / `header` / `cookie` / `body_form` / `body_json` / `body_xml` |
| `ParameterEntry.inferred_type` | `str` | yes | 见 4.3 PARAMETER |
| `ParameterEntry.required` | `bool` | yes |  |
| `ParameterEntry.default_value` | `any \| null` | no |  |
| `ParameterEntry.enum_values` | `list \| null` | no |  |
| `ParameterEntry.pattern` | `str \| null` | no |  |
| `ParameterEntry.example` | `any \| null` | no |  |
| `ParameterEntry.sensitivity` | `str` | yes | `credential` / `pii` / `internal_id` / `public` / `unknown` |
| `ParameterEntry.source` | `str` | yes | `openapi` / `graphql` / `path_pattern` / `form_parse` / `json_schema` |

#### PARAMETER 节点 value 字段约定

```
"{location}:{name}"  e.g. "path:id", "query:q", "header:Authorization", "cookie:session"
```

编排器 LLM 写树时按此规则生成 value, 同一 (endpoint, location, name) 不重复建节点。

#### 终止条件
- endpoint 完全没有可推断参数 → 输出 `parameters: []` 合法
- 全部 location 都提取完 → 终止

#### 与 INJECTION_VECTOR 的关系

**本 specialist 不生产 INJECTION_VECTOR 节点** (那是 hack-deep 阶段)。PARAMETER 节点的 `sensitivity` 字段给 hack-deep 端做漏洞挖掘时**优先排序**:
- `credential` 优先打 (auth bypass / password brute)
- `pii` 第二优先 (data leak)
- `internal_id` 第三 (IDOR 风险)
- `public` 最后

### 5.5 [11] static-asset

```
SOUL_BODY.md — STATIC-ASSET (URL → STATIC_ASSET, 多个)
```

#### 强制约束
- `subagents.allow_agents=[]`
- 可用工具: `recon_sensitive_fingerprint`, `recon_sensitive_variants`, `recon_secret_extract` (新工具组 `group:recon:sensitive`)

#### 任务流程
1. 解析 envelope → url (含 base_path)
2. **高价值静态文件 wordlist 探测** (内置, 5 大类共约 80 个):
   - **config (15)**: `/.env`, `/.env.example`, `/.env.local`, `/.env.production`, `/config.yml`, `/config.json`, `/application.properties`, `/application.yml`, `/wp-config.php.bak`, `/.aws/credentials`, `/secrets.json`, `/config/database.yml`, `/config/master.key`, `/.dockerenv`, `/Procfile`
   - **backup (12)**: `/backup.zip`, `/backup.tar.gz`, `/www.zip`, `/site.zip`, `/db.sql`, `/dump.sql`, `/db_backup.sql`, `/backup.sql`, `/.bak`, `/index.html.bak`, `/old.zip`, `/latest.zip`
   - **vcs (8)**: `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/.svn/wc.db`, `/.hg/store`, `/.bzr/branch-format`, `/.DS_Store`, `/.htaccess`
   - **debug (15)**: `/actuator`, `/actuator/env`, `/actuator/health`, `/actuator/heapdump`, `/actuator/trace`, `/actuator/beans`, `/actuator/mappings`, `/debug`, `/debug/vars`, `/trace`, `/metrics`, `/health`, `/status`, `/info`, `/server-info`
   - **docs (10)**: `/swagger`, `/swagger-ui.html`, `/swagger-ui/`, `/v3/api-docs`, `/v2/api-docs`, `/openapi.json`, `/redoc`, `/docs`, `/api-docs`, `/graphql`
   - **admin (15)**: `/admin`, `/administrator`, `/manager/html`, `/phpmyadmin`, `/jenkins`, `/grafana`, `/kibana`, `/console`, `/wp-admin`, `/wp-login.php`, `/login`, `/user/login`, `/auth`, `/auth/login`, `/signin`
   - **metadata (5)**: `/robots.txt`, `/sitemap.xml`, `/humans.txt`, `/security.txt`, `/crossdomain.xml`
3. **变体探测** (对 403/401 命中):
   - 路径后缀: `.bak`, `.old`, `.swp`, `~`, `.orig`, `.save`, `.dist`, `.sample`, `.inc`, `.txt`
   - 路径前缀: `~`, `.`
   - 路径内嵌: `/.git/HEAD` → `/.git/HEAD~`, `/.git/HEAD.bak`
4. **敏感度打标**:
   - 命中 config/vcs/backup + status 200/403 → `sensitivity="critical"` (默认 403 也是 critical, 因为可能存在变体)
   - 命中 debug/admin + status 200 → `sensitivity="high"`
   - 命中 docs/metadata → `sensitivity="medium"`
5. **secret 提取** (对命中且 status=200 的):
   - `recon_secret_extract(response_body, content_type)` → 扫 `aws_access_key_id` / `private_key` / `jwt_token` / `password=` / `db_connection_string` 等模式
6. 写 evidence schema: `static-asset-v1`

#### Evidence Schema: `static-asset-v1`

| 字段 | 类型 | 必填 | 描述 |
|---|---|---|---|
| `evidence_schema` | `"static-asset-v1"` | yes |  |
| `url` | `str` | yes | 输入 URL value |
| `assets` | `list[StaticAssetEntry]` | yes |  |
| `StaticAssetEntry.path` | `str` | yes |  |
| `StaticAssetEntry.status` | `int` | yes |  |
| `StaticAssetEntry.content_type` | `str \| null` | no |  |
| `StaticAssetEntry.size` | `int` | yes |  |
| `StaticAssetEntry.category` | `str` | yes | `config` / `backup` / `vcs` / `docs` / `debug` / `admin` / `metadata` |
| `StaticAssetEntry.sensitivity` | `str` | yes | `critical` / `high` / `medium` / `low` / `info` |
| `StaticAssetEntry.signature` | `str \| null` | no | `aws_access_key_id` / `jwt_token` / `private_key` / `db_connection_string` / `...` |
| `StaticAssetEntry.etag` | `str \| null` | no |  |
| `StaticAssetEntry.last_modified` | `str \| null` | no | ISO 8601 |
| `StaticAssetEntry.auth_required` | `bool` | yes | status 401/403 时为 True |
| `StaticAssetEntry.vcs_exposed` | `bool` | yes |  |
| `StaticAssetEntry.source` | `str` | yes | `directory_bruteforce` / `extension_variant` / `robots_sitemap` / `js_extract` |

#### STATIC_ASSET 节点 value 字段约定

```
"{base_path}{path}"  e.g. "/.env", "/admin", "/api/v1/.git/HEAD"
```

#### 终止条件
- wordlist 80 个 + 变体全部探测完
- 触发硬性 limit: 单 URL 最多 200 个 STATIC_ASSET 节点, 防止过深递归

#### 错误处理
- 单个文件 5xx → 跳过, 继续下一个
- 变体探测超时 → 截断到 5 个变体

#### 与现有 endpoint-crawler 的边界

- `endpoint-crawler` (Phase 2) 仍然处理 `SERVICE` 父节点下的"非高价值"端点 (如 `robots.txt` 之外的普通页面)
- `static-asset` (Batch 1) 专责 URL 父节点下的"高价值静态文件"
- **不重复建节点**: 编排器 LLM 在写树时需检查 `STATIC_ASSET` 是否已存在 (按 `path` 字段去重)

## 6. SOUL_BODY.md 编排器升级 (diff 摘要)

现有 `src/opensquilla/agents/hack-deep-find/SOUL_BODY.md` 需修改的章节:

### 6.1 specialist 表格扩充

**原**:
```
| specialist_id | 输入节点类型 | 输出节点类型 | 工具组 |
|---|---|---|---|
| `subdomain-discoverer` | ROOT_DOMAIN | SUB_DOMAIN | `group:recon:dns` |
| `ip-resolver` | SUB_DOMAIN | IP | `group:recon:dns` |
| `port-scanner` | IP | PORT | `group:recon:portscan` |
| `service-fingerprint` | PORT | SERVICE | `group:recon:portscan` + `group:recon:http` |
| `endpoint-crawler` | SERVICE | ENDPOINT | `group:recon:http` |
| `leaf-verifier` | 任意 | (无子节点) | `group:recon:http` |
```

**新** (在原表后追加, 5 行):

```
| `service-detailed` | SERVICE | COMPONENT | `group:recon:component` |
| `webapp-discoverer` | SERVICE | URL | `group:recon:webapp` |
| `api-surface` | URL | API_SCHEMA + ENDPOINT | `group:recon:api` |
| `parameter-extract` | ENDPOINT | PARAMETER | `group:recon:api` (复用) |
| `static-asset` | URL | STATIC_ASSET | `group:recon:sensitive` |
```

总计 11 个 specialist (6 + 5)。

### 6.2 specialist 选择算法改写

**原 Step N 流程** (单 specialist 顺序) 替换为:

```
For each UNSEEN layer (从最高层到最低层):
  For each UNSEEN node in this layer:
    specialist_id = SPECIALIST_TABLE[node.asset_type]
    if node.asset_type in {"service"}:
      # SERVICE 层双 specialist 并行
      spawn_batch = [service-detailed, webapp-discoverer]
    elif node.asset_type in {"url"}:
      # URL 层双 specialist 并行
      spawn_batch = [api-surface, static-asset]
    else:
      spawn_batch = [specialist_id]
    for sid in spawn_batch:
      envelope = build_envelope(W{current_wave}.{sid}.{seq}, ...)
      sessions_spawn(agent_id=sid, task=envelope)
  sessions_yield()  # wave barrier
  # 解析所有 specialist 返回, 写树
```

### 6.3 specialist 全局限制 (新增)

```
每个 specialist 单次处理的节点数 ≤ 16 (防止单次 wave 太大)
每波次 UNSEEN 节点数 ≤ 64 (防止 LLM 上下文爆炸)
编排器每波次必须输出 1 行 [WAVE {N} COMPLETE] 状态摘要
```

### 6.4 ATTRIBUTION_BODY.md 扩展

**原 6 个 schema + 1 个 handoff schema** 不动, **追加 5 个新 schema**:
- `component-v1` (5.1)
- `webapp-v1` (5.2)
- `api-surface-v1` (5.3)
- `parameter-v1` (5.4)
- `static-asset-v1` (5.5)

## 7. asset_tree 字段/工具扩展

### 7.1 模型层

**不需要新加 AssetType** (8 个新类型在 models.py 顶层 docstring 已声明, 枚举在 AssetType 类里已定义)。

**不需要改 _VALID_PARENT_CHILD** (现有约束已包含新挂载点)。

**需要新增 metadata 字段约定** (4.3 节) — 写入 `docs/features/asset-tree-asset-types.md` 的对应类型章节。

### 7.2 工具层

**新工具注册** (4.5 节, 4 组共 14 个工具):
- `group:recon:webapp`: 5 个
- `group:recon:api`: 5 个
- `group:recon:component`: 4 个
- `group:recon:sensitive`: 3 个

**修改 `_TOOL_GROUPS` dict** (`src/opensquilla/tools/policy_config.py:18+`):

```python
"group:recon:webapp": frozenset({
    "recon_vhost_bruteforce", "recon_robots_sitemap",
    "recon_tech_detect", "recon_app_fingerprint", "recon_url_dedupe",
}),
"group:recon:api": frozenset({
    "recon_openapi_parse", "recon_graphql_introspect",
    "recon_js_crawl_recursive", "recon_api_path_normalize", "recon_auth_probe",
}),
"group:recon:component": frozenset({
    "recon_cpe_resolve", "recon_js_component_extract",
    "recon_tls_cert_parse", "recon_ico_hash_lookup",
}),
"group:recon:sensitive": frozenset({
    "recon_sensitive_fingerprint", "recon_sensitive_variants",
    "recon_secret_extract",
}),
"group:recon": frozenset(),  # 保持 union 自动展开
```

### 7.3 工具实现位置

- 14 个新工具放 `src/opensquilla/tools/builtin/recon/`, 按组分子目录:
  - `recon/webapp.py` (5 工具)
  - `recon/api.py` (5 工具)
  - `recon/component.py` (4 工具)
  - `recon/sensitive.py` (3 工具)
  - 现有 `recon/dns.py` / `recon/port_scan.py` / `recon/http_probe.py` / `recon/dir_bust.py` / `recon/js_extract.py` 不动

### 7.4 持久化

- `~/.opensquilla/state/asset_trees/<tree_id>.json` 路径不变
- 节点 metadata 字典按 4.3 节 schema 写入
- `asset_tree_stats` 输出会自动反映新节点类型 (`stats()` 按 AssetType 计数, 无需改实现)

## 8. clone 脚本

### 8.1 `scripts/clone_hack_deep_find.py`

不改 — 已经能从 `hack-deep-find/specialists/__init__.py` 拿到 6 个 specialist 列表。

### 8.2 `scripts/clone_hack_deep_find_specialists.py`

不改 — `specialists/__init__.py` 维护的 `_SUBMODULES` 元组在 Batch 1 落地时**追加 5 项**:
```python
_SUBMODULES = (
    "subdomain-discoverer", "ip-resolver",
    "port-scanner", "service-fingerprint", "endpoint-crawler", "leaf-verifier",
    # Batch 1 新增
    "service-detailed", "webapp-discoverer", "api-surface",
    "parameter-extract", "static-asset",
)
```
`_ALIAS` dict 同步追加 5 项 snake_case 别名。

## 9. 测试矩阵

### 9.1 单元测试 (`tests/agents/test_hack_deep_find_batch1_*.py`)

每个 specialist 一个测试文件, 验证:
- SOUL_BODY.md 加载成功, 长度 > 200
- 包含必要的工具调用约束 (严禁 + 不允许)
- 包含对应的 evidence schema 名 (如 `component-v1`)
- 包含 RESULT MARKER 格式说明
- 包含错误处理章节

### 9.2 集成测试 (`tests/integration/test_batch1_walk.py`)

构造一个 mock AssetTree, 跑完整 11 specialist 编排:
1. seed: `example.com`
2. 预期产出至少: 1 ROOT_DOMAIN + ≥1 SUB_DOMAIN + ≥1 IP + ≥1 PORT + ≥1 SERVICE + ≥1 URL + ≥1 API_SCHEMA + ≥1 ENDPOINT + ≥1 PARAMETER + ≥1 STATIC_ASSET + ≥1 COMPONENT
3. 验证 metadata 字段 schema 4.3 节的字段都在
4. 验证父子关系合法 (`validate_parent_child` 不抛)

### 9.3 契约测试 (`tests/contracts/test_evidence_schemas_batch1.py`)

5 个新 schema (component-v1 / webapp-v1 / api-surface-v1 / parameter-v1 / static-asset-v1) 各构造一个合法 JSON, 验证:
- 字段必填/可选约束
- 枚举值合法 (method / category / sensitivity / location / source / inferred_type)
- evidence_schema 字段值匹配

### 9.4 工具测试 (`tests/tools/test_recon_batch1.py`)

14 个新工具各 1 个测试, mock 外部依赖 (DNS / HTTP / 文件读取), 验证:
- 入参 schema 校验
- 出参 JSON 合法
- 错误处理路径 (超时 / 5xx / 解析失败)

### 9.5 E2E (`tests/e2e/test_hack_deep_find_batch1.py`)

跑一次完整 find, 验证:
- 11 specialist 全部被 spawn 至少一次
- 树深度 ≥ 10
- 节点总数 ≥ 30
- `asset_tree_complete` 返回的 tree_path 可被 `AssetTree.from_json` 反序列化

## 10. 实施顺序 (按周, 假设 1 个全职)

| 周 | 工作 |
|---|---|
| W1 (D1-2) | 5 个 specialist 的 `__init__.py` + `SOUL_BODY.md` 模板 |
| W1 (D3-5) | 14 个新工具的骨架 + 单元测试 |
| W2 (D1-3) | ATTRIBUTION_BODY.md 追加 5 schema + 单元测试 |
| W2 (D4-5) | 编排器 SOUL_BODY.md 升级 + 集成测试 |
| W3 (D1-3) | E2E 测试 + docs/features/asset-tree-asset-types.md 同步 |
| W3 (D4-5) | clone 脚本验证 + docs 更新 + CHANGELOG |

总计 3 周, 1 人。

## 11. 风险与权衡

### 11.1 风险

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 新工具调用外部服务 (shodan / census / crt.sh) 需要 API key | 中 | 高 (没 key 全失败) | `recon_cpe_resolve` 等支持本地 NVD feed 兜底; crt.sh 不需要 key |
| OpenAPI schema 太大 (>10MB) LLM 处理不了 | 低 | 中 | `recon_openapi_parse` 截断到前 1000 行, 标 `parse_status="truncated"` |
| vhost 爆破误报 (Host 头被吞) | 中 | 中 | 配合 `recon_auth_probe` 二次验证, 状态码差异 < 50 视为同一应用 |
| `asset_tree_add_nodes` metadata 字段自由度过高导致 LLM 写错 | 中 | 中 | 4.3 节强约定 + 集成测试断言必填字段都在 |
| 双 specialist 并发 spawn 引入 race condition (tree_id 同时写) | 低 | 高 | `asset_tree_add_nodes` 现有 lock 机制 (assumed); 集成测试加并发用例 |
| 11 specialist 编排循环 LLM 上下文爆 | 中 | 中 | specialist 选择表硬约束, 每波次 UNSEEN ≤ 64, 编排器只持 specialist_id 不持 evidence (evidence 由 specialist 自己写文件) |

### 11.2 权衡

- **不实现 INJECTION_VECTOR**: 减少 Batch 1 范围, handoff 给 hack-deep 后再下钻。代价: handoff 数据缺少漏洞点定位, hack-deep 阶段需要自己做 PARAMETER → INJECTION_VECTOR 推断
- **SERVICE 层不替换 service-fingerprint**: 两者并存, `service-fingerprint` 产网络协议 SERVICE 节点, `service-detailed` 产 CVE 视角 COMPONENT 节点。代价: 同 SERVICE 节点会有两个子 specialist 并发, evidence 写两次
- **不引入新数据库表**: 复用 `asset_nodes` + JSONL 持久化。代价: 查询大树的性能, 用 `tree.get_subtree(node_id, max_depth=N)` 截断
- **编排器 LLM 自己做 URL dedupe**: 不在 `asset_tree_add_nodes` 里做 URL 规范化。代价: 编排器 prompt 需要写清楚 dedupe 规则

## 12. 后续 Batch 接入点

Batch 1 落地后, 接入点已就位, 后续 Batch 只需:
- **Batch 2** (auth-mapper / cookie-header): 在 SOUL_BODY specialist 表追加 2 行 + 2 个新工具 + 1 个新 schema
- **Batch 3** (cloud-storage / secret-scanner): 同样模式
- **Batch 4** (横向 seed-expander + 资产合并器): 改动 `asset_tree_create` 接受多 seed + 新工具 `asset_tree_merge`, **需要改 asset_tree 工具层** (这是 Batch 1 不动 asset_tree 工具层的唯一例外)
- **Batch 5** (时间维度): 不改 specialist 层, 只在编排器外层加 scheduler

## 13. Open Questions (评审时请确认)

1. **PARAMETER 节点是否需要 `hack-deep` 端做 union/dedupe 跨端点参数?**
   比如 `/users/{id}` 和 `/orders/{userId}` 都有 "id 形式的 path 参数", hack-deep 端做漏洞挖掘时是否要把它视为同一类?
2. **API_SCHEMA 节点的 value 字段是 schema URL 唯一还是 URL + schema_type 唯一?**
   同一 url 可能同时有 OpenAPI 和 GraphQL 暴露, value 应该区分
3. **STATIC_ASSET 的 `auth_required` 字段如果同时是 `sensitivity=critical` (如 403 的 `/.git/HEAD`), 编排器是否要触发变体重试?**
   还是留给 `hack-deep` 阶段做?
4. **COMPONENT 节点如果在不同 SERVICE/URL 下都识别到同一 product+version, 是否 dedupe (只挂一份) 还是多挂?**
   dedupe 简化查询但丢失溯源; 多挂保完整但树膨胀
5. **SERVICE 层双 specialist 并发 vs 串行, 哪一档?**
   并发省时间但 evidence 解析顺序不固定; 串行稳定但慢 2 倍
6. **新工具调用 crt.sh / NVD / shodan 需不需要 LLM 端审批?**
   当前 `group:recon:*` 不走 `require_escalated`, 但这些第三方 API 有 rate limit 风险

## 14. 评审检查表

- [ ] 5 个 specialist 职责划分 (一职责一 specialist) 是否合理
- [ ] 4.3 节 metadata 字段是否完整 / 有冗余
- [ ] 14 个新工具是否需要合并 / 拆分
- [ ] 编排器升级 (6.2 节) LLM 上下文是否扛得住
- [ ] 不引入新数据库表的权衡是否可接受
- [ ] 3 周实施时间评估是否合理
- [ ] 13 节 6 个 open question 给出结论
