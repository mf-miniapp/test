# AssetTree — 资产类型约定

> `opensquilla.asset_tree` 的节点类型、层级约束和 metadata 约定。
> 维护者改 `AssetType` 时必须同步更新本页。

## 层级总览

```
Network surface
  ROOT_DOMAIN
    └─ SUB_DOMAIN
         ├─ IP ─ PORT ─ SERVICE ─ URL
         │                       ├─ ENDPOINT ─ PARAMETER ─ INJECTION_VECTOR
         │                       ├─ AUTH_SURFACE
         │                       ├─ STATIC_ASSET
         │                       ├─ API_SCHEMA
         │                       ├─ COMPONENT
         │                       ├─ COOKIE
         │                       └─ HEADER
         ├─ STORAGE ─ STORAGE_OBJECT
         └─ SECRET                  (跨层级白名单挂载)

Off-host surface
  COMPONENT                       (SERVICE / URL 之下)
  STORAGE / STORAGE_OBJECT
  SECRET

Catch-all
  GENERIC                         (父位可接受任意子类型)
```

## 类型清单

### Network surface

#### `ROOT_DOMAIN` / `sub_domain` 父

- `ROOT_DOMAIN` — 顶层根域名。`AssetTree(root_domain=...)` 自动创建。
- `SUB_DOMAIN` — 子域名。挂 `ROOT_DOMAIN` 之下。

`SUB_DOMAIN.metadata`：`{"resolver": "dns", "records": ["A: 1.2.3.4"]}`

#### `IP` / `PORT` / `SERVICE`

- `IP` — IPv4 / IPv6 地址。`metadata`：`{"asn": "AS12345", "geo": "US", "isp": "Cloudflare"}`
- `PORT` — 开放端口，**值用字符串**（如 `"443"`）。`metadata`：`{"state": "open", "protocol": "tcp"}`
- `SERVICE` — 端口上的服务指纹，值形如 `"HTTPS/NGINX 1.24.0"`。
  `metadata`：`{"product": "nginx", "version": "1.24.0", "cpe": "cpe:2.3:a:..."}`

### Web surface（`URL` 之下）

#### `URL`

可调用 URL（vhost / scheme / 认证上下文）。值形如 `https://api.example.com`。
`metadata` (Batch 1, 2026-06-15 扩展):

```json
{
    "scheme": "https",
    "host": "api.example.com",
    "port": 443,
    "base_path": "/api/v1",
    "vhost": "api.example.com",
    "app_type": "spring-boot",
    "tech_stack": ["nginx/1.24.0", "java/spring-boot"],
    "tls": true,
    "sni_required": true,
    "auth_context": "bearer",
    "discovery_mode": "vhost",
    "siblings_count": 4
}
```

> **重要**：`URL` 是 web 资产唯一挂载点；不要把 `ENDPOINT` 直接挂到 `SERVICE` 上。
> 旧数据迁移见 [迁移旧 ENDPOINT 数据](#迁移旧-endpoint-数据)。
>
> **值约定 (Batch 1)**: 编排器 LLM 写树时按 `"{scheme}://{host}:{port}{base_path}"` 格式生成 value。
> vhost 模式省略默认端口: `https://api.example.com` (无 `:443`)。

#### `ENDPOINT`

可调用接口。**值推荐格式**：`METHOD path`（如 `GET /v1/users/:id`）。
`metadata` (Batch 1, 2026-06-15 扩展):

```json
{
  "method": "GET",
  "path": "/v1/users/:id",
  "status": 200,
  "content_type": "application/json",
  "title": null,
  "source": "openapi",
  "api_schema_id": "abc123def456",
  "params": [
    {"name": "id", "in": "path", "required": true, "sample": "42"}
  ],
  "params_summary": {
    "path": ["id"],
    "query": ["q", "page"],
    "header": ["Authorization"],
    "cookie": ["session"]
  },
  "auth_required": true,
  "idempotent": true,
  "auth": "bearer|cookie|session|apikey|mtls|none",
  "content_type_in": "application/json",
  "content_type_out": "application/json",
  "response_codes": [200, 401, 403],
  "http_version": "HTTP/1.1",
  "response_size": 1234,
  "poc_ready": false,
  "risk": "low|medium|high|critical"
}
```

`api_schema_id` 由编排器 LLM 写树时回填 (关联到 API_SCHEMA 节点 id)。

#### `PARAMETER`

接口下的具体参数。值是参数名（如 `id`、`q`、`file`、`callback`）。
`metadata`：`{"in": "query|path|header|cookie", "type": "int|string|bool", "reflected": true, "fuzzed": false, "risk_hints": ["sqli", "ssrf"]}`

#### `INJECTION_VECTOR`

"参数 × 注入类型"二元漏洞点。值形如 `id:sqli` / `q:xss` / `file:path_traversal`。
`metadata`：

```json
{
  "category": "sqli|ssrf|xss|path_traversal|command_injection|open_redirect|deserialization|xxe|idor|...",
  "technique": "error-based|time-based|boolean-based|union-based|...",
  "payload": "' OR 1=1--",
  "response_signature": "You have an error in your SQL syntax",
  "verified": false
}
```

工具方法 `find_injection_vectors(category=..., verified_only=...)` 直接消费此结构。

#### `AUTH_SURFACE`

鉴权面。值形如 `/api/auth/login` / `OAuth/Google` / `JWT/HS256`。
`metadata`：

```json
{
  "kind": "login|register|sso|apikey|jwt|oauth|reset|mfa",
  "creatable": true,
  "default_creds": ["admin:admin"],
  "rate_limited": false,
  "mfa": false
}
```

#### `STATIC_ASSET`

静态资源。值形如 `/robots.txt` / `/swagger.json` / `app-1.2.3.js`。
`metadata`：

```json
{
  "size": 1234,
  "http_status": 200,
  "content_type": "application/json",
  "leak_kind": "spec|git|backup|js_map|env|sourcemap|swagger|robots|backup|other",
  "component": {"name": "swagger-ui", "version": "4.1.0"}
}
```

#### `API_SCHEMA`

结构化接口描述。值形如 `openapi://api.example.com/v3` / `graphql://api.example.com/graphql`。
`metadata`：

```json
{
  "format": "openapi3|graphql|postman|grpc|protobuf",
  "endpoints_count": 47,
  "auth_schemes": ["bearer"],
  "deprecated": false
}
```

#### `COOKIE`

Cookie。值形如 `session=abc123; HttpOnly; SameSite=Lax`。
`metadata`：`{"name": "session", "http_only": true, "secure": true, "samesite": "Lax", "expires": "2026-12-31"}`

#### `HEADER`

HTTP 头。值形如 `Strict-Transport-Security` / `X-Powered-By: PHP/8.1`。
`metadata`：`{"present": true, "value": "...", "security_relevant": true, "missing": false}`

### Off-host surface

#### `COMPONENT`

组件指纹（独立 CVE 视角）。值形如 `nginx 1.24.0` / `struts2 2.5.30` / `jquery 1.8.3`。
`metadata`：

```json
{
  "product": "struts2",
  "version": "2.5.30",
  "cpe": "cpe:2.3:a:apache:struts:2.5.30",
  "cves": ["CVE-2017-5638"],
  "source": "header|banner|fingerprint|sca"
}
```

可挂 `SERVICE`（指纹）也可挂 `URL`（从 JS bundle / 响应头识别）。工具方法
`find_shared_components()` 返回 `product+version` 被 2+ 父节点共享的项。

#### `STORAGE` / `STORAGE_OBJECT`

云存储。值形如 `s3://example-prod-logs` / `azure://company-backup`。
`metadata`：`{"provider": "aws|azure|gcs|oss|minio", "bucket": "...", "public": true, "region": "us-east-1", "objects_count": 12345}`

`STORAGE_OBJECT` 挂在 `STORAGE` 之下，值是对象 key（如 `db-dump-2026.sql.gz`）。

#### `SECRET`

泄漏的凭证 / 内部信息。值形如 `aws_access_key=AKIA...` / `internal_host=10.0.0.5`。
`metadata`：

```json
{
  "kind": "aws_key|api_token|internal_host|email|jwt|private_key|generic",
  "source": "js|env|config|git|document",
  "validated": false,
  "blast_radius": "low|medium|high|critical"
}
```

`SECRET` 走单独的白名单校验（`models._SECRET_ALLOWED_PARENTS`），可挂：

- `SUB_DOMAIN` / `IP` / `SERVICE` / `URL` / `STATIC_ASSET` / `API_SCHEMA`
- `STORAGE` / `STORAGE_OBJECT`

工具方法 `find_leaked_secrets(validated_only=...)` 直接消费此结构。

### Catch-all

#### `GENERIC`

兜底类型。父位可接受任何子类型。**不**作为常规层级的子节点。

## 状态机（所有类型通用）

```
UNSEEN ──(扫描)──→ DISCOVERED ──(triage)──→ TRIAGED ──(exploit)──→ EXPLOITED
   └──────────────────┬──────────────────────────┬──────────────────────┐
                      └─────────────────────────→ ABANDONED
```

波次选择驱动：

- `tree.unseen_leaves()` — 下一波次目标候选
- `tree.frontier()` — 已发现但未深入的节点
- `tree.find_leaked_secrets(validated_only=True)` — 已验证泄漏的高优
- `tree.find_injection_vectors(verified_only=True)` — 已验证漏洞的高优

## 添加新类型时必须同步

1. `src/opensquilla/asset_tree/models.py` — `AssetType` 枚举 + `_VALID_PARENT_CHILD`
2. `src/opensquilla/asset_tree/db/schema.py` — `ck_asset_nodes_asset_type` SQLAlchemy 声明式 + DDL 模板
3. `src/opensquilla/asset_tree/models.py` — `AssetNode.value` 注释里描述该类型 value 格式
4. 本文档 — 补"类型清单"和 metadata 约定

## 迁移旧 ENDPOINT 数据

旧数据中 `ENDPOINT` 节点直接挂在 `SERVICE` 之下，值可能是完整路径
（如 `/api/v1/users`）。新约束要求 `SERVICE → URL → ENDPOINT`。

迁移脚本 `src/opensquilla/asset_tree/migrate_endpoints_to_url.py`
（见仓库）会：

1. 扫描所有 `parent_id` 直接是 `SERVICE` 的 `ENDPOINT` 节点
2. 为每个 SERVICE 创建一个共享的 `URL` 节点（值 = SERVICE 的 base URL，
   推断自 `metadata.scheme`/端口号，缺省 `https://{sub_domain}:{port}`）
3. 把旧 `ENDPOINT` 节点的 `parent_id` 改挂到新 `URL` 之下
4. 在原 `ENDPOINT.metadata` 写入 `{"_migrated_from": "service", "at": "..."}`
5. 校验：迁移完成后不再存在 `SERVICE → ENDPOINT` 边


## Batch 1 新增 specialist 与节点类型映射 (2026-06-15)

> 详细 RFC 见 `docs/plans/2026-06-15-hack-deep-find-batch-1-plan.md`

| specialist_id | 输入类型 | 输出类型 | 工具组 | ATTRIBUTION schema |
|---|---|---|---|---|
| `service-detailed` | SERVICE | COMPONENT | `group:recon:component` | `component-v1` |
| `webapp-discoverer` | SERVICE | URL | `group:recon:webapp` | `webapp-v1` |
| `api-surface` | URL | API_SCHEMA + ENDPOINT | `group:recon:api` | `api-surface-v1` |
| `parameter-extract` | ENDPOINT | PARAMETER | `group:recon:api` (read-only) | `parameter-v1` |
| `static-asset` | URL | STATIC_ASSET | `group:recon:sensitive` | `static-asset-v1` |

**关键变化**:

- `URL` 节点从"理论存在"变为"由 webapp-discoverer 实际生产"
- `ENDPOINT` 不再只挂在 `SERVICE` 下, 新增 URL → ENDPOINT 路径
- `COMPONENT` 节点从可选元数据 (在 SERVICE.metadata.cpe) 变为独立节点, 可挂 SERVICE 或 URL
- 新增 `API_SCHEMA` 节点 (OpenAPI/GraphQL/Postman/gRPC 等结构化描述)
- 新增 `STATIC_ASSET` 节点 (高价值静态文件, 独立于 ENDPOINT 单独建节点)
- 新增 `PARAMETER` 节点 (按 location:path/query/header/cookie/body_* 细分)

**双 specialist 并行 (SERVICE / URL 层)**:

- SERVICE 层: `service-detailed` (COMPONENT) + `webapp-discoverer` (URL) 同波次并发
- URL 层: `api-surface` (API_SCHEMA + ENDPOINT) + `static-asset` (STATIC_ASSET) 同波次并发

**节点 value 字段约定 (Batch 1)**:

- `URL`: `"{scheme}://{host}:{port}{base_path}"` (vhost 模式省略默认端口)
- `ENDPOINT`: `"{method} {path}"` (例: `"GET /api/v1/users/{id}"`)
- `API_SCHEMA`: `"{schema_type}:{schema_url}"` (例: `"openapi:https://api.example.com/v3/api-docs"`)
- `PARAMETER`: `"{location}:{name}"` (例: `"path:id"`, `"header:Authorization"`)
- `STATIC_ASSET`: `"{base_path}{path}"` (例: `"https://api.example.com/.env"`)
- `COMPONENT`: `"{product}:{version}"` (例: `"nginx:1.24.0"`)

## Batch 2 新增 specialist 与节点类型映射 (2026-06-15)

| specialist_id | 输入类型 | 输出类型 | 工具组 | ATTRIBUTION schema |
|---|---|---|---|---|
| `auth-mapper` | URL | AUTH_SURFACE | `group:recon:auth` | `auth-surface-v1` |
| `cookie-header` | URL | COOKIE + HEADER (双产) | `group:recon:header` | `cookie-header-v1` |

**关键变化**:

- `AUTH_SURFACE` 节点从"画在 docstring 里"变成由 auth-mapper 实际生产
- `COOKIE` / `HEADER` 节点从无到有, cookie-header 是 URL 层首个**双产**specialist
- URL 层并发数从 Batch 1 的 2 路提升到 **4 路** (api-surface + static-asset + auth-mapper + cookie-header)

**COOKIE 节点 risk 评估**:

- `auth keyword (session/token/jwt/sid/csrf/...)` + 缺 HttpOnly → `high`
- 缺 Secure / SameSite=None → `medium`
- 其它 → `low`

**HEADER 节点分类**:

- 安全头缺失: `CSP` / `HSTS` / `X-Frame-Options` / `X-Content-Type-Options` / `Referrer-Policy` / `Permissions-Policy` 等
- 信息泄露头: `Server` (版本) / `X-Powered-By` (栈) / `X-AspNet-Version` / `X-Runtime` / `Via` / `X-Generator`

## Batch 3 新增 specialist 与节点类型映射 (2026-06-15)

| specialist_id | 输入类型 | 输出类型 | 工具组 | ATTRIBUTION schema |
|---|---|---|---|---|
| `cloud-storage` | SUB_DOMAIN | STORAGE + STORAGE_OBJECT | `group:recon:storage` | `cloud-storage-v1` |
| `secret-scanner` | 任意 (8 类父节点) | SECRET | `group:recon:secret` | `secret-v1` |

**关键变化**:

- `STORAGE` / `STORAGE_OBJECT` 节点从 docstring 提升到生产; 4 大云厂商 (S3/OSS/GCS/Azure) 全部覆盖
- `SECRET` 节点首次实现**跨层挂载** — 可挂在 SUB_DOMAIN / IP / SERVICE / URL / STATIC_ASSET / API_SCHEMA / STORAGE / STORAGE_OBJECT 之下
- SUB_DOMAIN 层从单 specialist (ip-resolver) 升级到**双 specialist 并行** (ip-resolver + cloud-storage)

**STORAGE 节点 value 约定**:

- `"{provider}://{bucket}"` 格式 (例: `"s3://acme-corp-backup"`, `"oss://acme-prod"`, `"gcs://acme-logs"`, `"azure://acme.blob.core.windows.net/backups"`)

**STORAGE_OBJECT 敏感度分类**:

- `credential` / `key` (`.env`, `*.pem`, `*.key`) → `critical`
- `database_dump` / `backup` / `archive` → `high` / `medium`
- `config` / `log` / `data` → `medium` / `low`

**SECRET 节点 blast_radius 评估**:

- `aws_access_key_id` + validated=True → `critical`
- `private_key` → `critical`
- `jwt_token` (未验证) → `high`
- `internal_host` (内部域名, SSRF 风险) → `medium`
- `email` → `low`

## Batch 4 新增 specialist 与节点类型映射 (2026-06-15)

| specialist_id | 输入类型 | 输出类型 | 工具组 | ATTRIBUTION schema |
|---|---|---|---|---|
| `seed-expander` | ROOT_DOMAIN | seed list (不写树) | `group:recon:seed` | `seed-v1` |

**关键变化 — 架构层**:

- **asset_tree_create 扩展**: 接受 `extra_seeds` 参数 (`list[{kind, value}]`), 多 seed 自动建成 ROOT_DOMAIN 子节点
- **新工具 asset_tree_merge**: 跨树合并 (按 (parent_id, asset_type, value) 三元组去重)
- asset_tree 工具数: 8 → 9

**seed-expander 不写树**:

- seed-expander 返回 `seed-v1` evidence, 包含 `seeds[]` 列表 (kind ∈ {domain, asn, ip_range, org_name, keyword})
- 编排器 LLM 据此决策:
  - Option A: `asset_tree_create(extra_seeds=...)` (推荐, seed 数 ≤ 16)
  - Option B: 多树 + `asset_tree_merge(target=...)` (seed 数 > 16)

**ROOT_DOMAIN 层双 specialist 并行** (Batch 4):

- `subdomain-discoverer` (主链: ROOT_DOMAIN → SUB_DOMAIN)
- `seed-expander` (横向: ROOT_DOMAIN → seed list, 供 Step 0 二轮决策)

**全 asset tree 工具清单 (9 个, Batch 4 升级)**:

| 工具 | 用途 |
|---|---|
| `asset_tree_create(root_domain, tree_id?, extra_seeds?)` | 建树, 支持多 seed |
| `asset_tree_add_nodes(...)` | 加子节点 |
| `asset_tree_update_state(...)` | 状态流转 |
| `asset_tree_find_unseen(...)` | 推下一波次 |
| `asset_tree_get_subtree(...)` | 渲染子树 |
| `asset_tree_list_siblings(...)` | 兄弟节点 |
| `asset_tree_stats(...)` | 终止报告 |
| `asset_tree_complete(...)` | 持久化路径 |
| `asset_tree_merge(target_tree_id, source_tree_ids[], create_target_if_missing?)` | 跨树合并 (Batch 4 新) |
