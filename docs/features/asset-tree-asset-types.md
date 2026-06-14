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
`metadata`：`{"vhost": "api.example.com", "scheme": "https", "auth": "bearer"}`

> **重要**：`URL` 是 web 资产唯一挂载点；不要把 `ENDPOINT` 直接挂到 `SERVICE` 上。
> 旧数据迁移见 [迁移旧 ENDPOINT 数据](#迁移旧-endpoint-数据)。

#### `ENDPOINT`

可调用接口。**值推荐格式**：`METHOD path`（如 `GET /v1/users/:id`）。
`metadata`（推荐结构化）：

```json
{
  "method": "GET",
  "path": "/v1/users/:id",
  "params": [
    {"name": "id", "in": "path", "required": true, "sample": "42"}
  ],
  "auth": "bearer|cookie|session|apikey|mtls|none",
  "content_type_in": "application/json",
  "content_type_out": "application/json",
  "response_codes": [200, 401, 403],
  "poc_ready": false,
  "risk": "low|medium|high|critical"
}
```

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
