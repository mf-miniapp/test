# ATTRIBUTION.md — HACK-DEEP-FIND Evidence Schemas

## Specialist Output Schemas (Phase 2: all 6 wired)

### `subdomain-v1` — subdomain-discoverer
Output of ROOT_DOMAIN → SUB_DOMAIN enumeration (active DNS bruteforce).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"subdomain-v1"` | yes | Schema discriminator |
| `root_domain` | `str` | yes | The input root domain |
| `subdomains` | `list[SubdomainEntry]` | yes | Discovered subdomains |
| `SubdomainEntry.subdomain` | `str` | yes | Full subdomain (e.g. "api.example.com") |
| `SubdomainEntry.source` | `str` | yes | Discovery source: `dns_bruteforce` / `crtsh` / `passive_dns` |
| `SubdomainEntry.confidence` | `str` | yes | `high` / `medium` / `low` |

### `ip-v1` — ip-resolver
Output of SUB_DOMAIN → IP resolution.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"ip-v1"` | yes | Schema discriminator |
| `subdomain` | `str` | yes | Input subdomain |
| `ips` | `list[str]` | yes | Resolved IP addresses (A + AAAA) |
| `ttl` | `int \| null` | no | DNS TTL if DoH provider exposes it |
| `error` | `str \| null` | no | Error message if resolution failed |

### `port-v1` — port-scanner
Output of IP → PORT discovery.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"port-v1"` | yes | Schema discriminator |
| `ip` | `str` | yes | Input IP |
| `ports` | `list[PortEntry]` | yes | Discovered open ports |
| `PortEntry.port` | `int` | yes | Port number |
| `PortEntry.protocol` | `str` | no | `tcp` (default) / `udp` |
| `PortEntry.state` | `str` | yes | `open` / `closed` / `filtered` |
| `PortEntry.banner` | `str \| null` | no | Service banner if grabbed |

### `service-v1` — service-fingerprint
Output of PORT → SERVICE fingerprinting.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"service-v1"` | yes | Schema discriminator |
| `services` | `list[ServiceEntry]` | yes | Identified services |
| `ServiceEntry.ip` | `str` | yes | IP address |
| `ServiceEntry.port` | `int` | yes | Port number |
| `ServiceEntry.service_name` | `str` | yes | Service identifier (e.g. "HTTPS/nginx") |
| `ServiceEntry.version` | `str \| null` | no | Detected version |
| `ServiceEntry.technology` | `str \| null` | no | Tech stack (PHP / Node.js / etc.) |
| `ServiceEntry.extra_info` | `dict` | no | Server header, TLS info, etc. |

### `endpoint-v1` — endpoint-crawler
Output of SERVICE → ENDPOINT discovery.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"endpoint-v1"` | yes | Schema discriminator |
| `service` | `str` | yes | Input service identifier |
| `endpoints` | `list[EndpointEntry]` | yes | Discovered endpoints |
| `EndpointEntry.url` | `str` | yes | Full URL |
| `EndpointEntry.method` | `str` | no | HTTP method (default: GET) |
| `EndpointEntry.status_code` | `int` | no | Response status code |
| `EndpointEntry.content_type` | `str \| null` | no | Content-Type header |
| `EndpointEntry.title` | `str \| null` | no | HTML `<title>` if present |

### `leaf-v1` — leaf-verifier
Output of leaf verification (no children produced).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"leaf-v1"` | yes | Schema discriminator |
| `nodes` | `list[LeafEntry]` | yes | Verification results |
| `LeafEntry.node_id` | `str` | yes | Verified node id |
| `LeafEntry.is_leaf` | `bool` | yes | Whether the node is a leaf |
| `LeafEntry.reason` | `str` | yes | `unreachable` / `service_alive` / `terminal_type` / etc. |

---

## Specialist Output Schemas (Batch 1: 5 new wired, 2026-06-15)

### `component-v1` — service-detailed
Output of SERVICE → COMPONENT (CVE-perspective component fingerprinting).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"component-v1"` | yes | Schema discriminator |
| `service` | `str` | yes | Input service identifier |
| `components` | `list[ComponentEntry]` | yes | Discovered components |
| `ComponentEntry.product` | `str` | yes | Product name (e.g. "nginx", "jquery") |
| `ComponentEntry.version` | `str \| null` | no | Version string |
| `ComponentEntry.cpe` | `str \| null` | no | CPE 2.3 formatted string |
| `ComponentEntry.vendor` | `str \| null` | no | Vendor name |
| `ComponentEntry.source` | `str` | yes | `banner` / `server_header` / `x_powered_by` / `js_bundle` / `ico_hash` / `tls_cert` / `html_meta` |
| `ComponentEntry.evidence` | `str` | yes | Raw evidence string (e.g. "nginx/1.24.0") |
| `ComponentEntry.confidence` | `str` | yes | `high` / `medium` / `low` |
| `ComponentEntry.cve_relevant` | `bool` | yes | Whether product+version can be cross-referenced with NVD |
| `ComponentEntry.extracted_at` | `str` | yes | `service` / `url` |

### `webapp-v1` — webapp-discoverer
Output of SERVICE → URL (web application boundary identification).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"webapp-v1"` | yes | Schema discriminator |
| `service` | `str` | yes | Input service identifier |
| `base_host` | `str` | yes | Service node host (IP or vhost) |
| `base_port` | `int` | yes |  |
| `urls` | `list[UrlEntry]` | yes | Discovered URLs |
| `UrlEntry.value` | `str` | yes | Unique identifier (see value convention in SOUL) |
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
| `UrlEntry.siblings_count` | `int` | yes |  |

### `api-surface-v1` — api-surface
Output of URL → API_SCHEMA + ENDPOINT (structured API surface extraction).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"api-surface-v1"` | yes | Schema discriminator |
| `url` | `str` | yes | Input URL value |
| `api_schemas` | `list[ApiSchemaEntry]` | yes | Discovered schemas |
| `endpoints` | `list[EndpointEntry]` | yes | Extracted endpoints (compatible with endpoint-v1 + extensions) |
| `ApiSchemaEntry.schema_type` | `str` | yes | `openapi` / `swagger` / `graphql` / `postman` / `grpc_reflection` / `wsdl` / `wadl` |
| `ApiSchemaEntry.schema_version` | `str \| null` | no |  |
| `ApiSchemaEntry.schema_url` | `str` | yes | URL the schema was fetched from |
| `ApiSchemaEntry.title` | `str \| null` | no |  |
| `ApiSchemaEntry.version` | `str \| null` | no |  |
| `ApiSchemaEntry.auth_schemes` | `list[str]` | yes |  |
| `ApiSchemaEntry.server_urls` | `list[str]` | yes |  |
| `ApiSchemaEntry.graphql_endpoint` | `str \| null` | no | GraphQL-specific |
| `ApiSchemaEntry.raw_size` | `int` | yes |  |
| `ApiSchemaEntry.parse_status` | `str` | yes | `ok` / `truncated` / `error` |
| `ApiSchemaEntry.endpoint_count` | `int` | yes | Number of endpoints declared in the schema |
| `EndpointEntry.method` | `str` | yes |  |
| `EndpointEntry.path` | `str` | yes | Normalized path (with `{id}` placeholders) |
| `EndpointEntry.source` | `str` | yes | `openapi` / `graphql` / `js_extract` / `directory_bruteforce` |
| `EndpointEntry.api_schema_id` | `str \| null` | no | Back-linked by orchestrator after writing API_SCHEMA node |
| `EndpointEntry.params_summary` | `dict` | yes | `{path: [], query: [], header: [], cookie: []}` |
| `EndpointEntry.auth_required` | `bool` | yes |  |
| `EndpointEntry.idempotent` | `bool` | yes |  |
| `EndpointEntry.status` | `int \| null` | no | Observed status code during probing |
| `EndpointEntry.content_type` | `str \| null` | no |  |

### `parameter-v1` — parameter-extract
Output of ENDPOINT → PARAMETER (parameter-level extraction).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"parameter-v1"` | yes | Schema discriminator |
| `endpoint` | `str` | yes | Input endpoint value (e.g. "GET /api/v1/users/{id}") |
| `method` | `str` | yes |  |
| `url` | `str` | yes | Parent URL value (for context) |
| `parameters` | `list[ParameterEntry]` | yes |  |
| `ParameterEntry.name` | `str` | yes |  |
| `ParameterEntry.location` | `str` | yes | `path` / `query` / `header` / `cookie` / `body_form` / `body_json` / `body_xml` |
| `ParameterEntry.inferred_type` | `str` | yes | `integer` / `string` / `uuid` / `email` / `boolean` / `date` / `base64` / `url` / `filename` / `free_text` / `header_name` / `cookie_name` |
| `ParameterEntry.required` | `bool` | yes |  |
| `ParameterEntry.default_value` | `any \| null` | no |  |
| `ParameterEntry.enum_values` | `list \| null` | no |  |
| `ParameterEntry.pattern` | `str \| null` | no |  |
| `ParameterEntry.example` | `any \| null` | no |  |
| `ParameterEntry.sensitivity` | `str` | yes | `credential` / `pii` / `internal_id` / `public` / `unknown` |
| `ParameterEntry.source` | `str` | yes | `openapi` / `graphql` / `path_pattern` / `form_parse` / `json_schema` |

### `static-asset-v1` — static-asset
Output of URL → STATIC_ASSET (high-value static file discovery).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"static-asset-v1"` | yes | Schema discriminator |
| `url` | `str` | yes | Input URL value |
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
| `StaticAssetEntry.auth_required` | `bool` | yes | True if status 401/403 |
| `StaticAssetEntry.vcs_exposed` | `bool` | yes |  |
| `StaticAssetEntry.source` | `str` | yes | `directory_bruteforce` / `extension_variant` / `robots_sitemap` / `js_extract` |

### `auth-surface-v1` — auth-mapper
Output of URL → AUTH_SURFACE (auth entry identification).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"auth-surface-v1"` | yes | Schema discriminator |
| `url` | `str` | yes | Input URL value |
| `auth_surfaces` | `list[AuthEntry]` | yes | Discovered auth entries |
| `AuthEntry.kind` | `str` | yes | `login` / `register` / `sso` / `apikey` / `jwt` / `oauth` / `reset` / `mfa` |
| `AuthEntry.path` | `str \| null` | no | Path of the auth entry |
| `AuthEntry.method` | `str \| null` | no | HTTP method |
| `AuthEntry.form_action` | `str \| null` | no | Form action (login type) |
| `AuthEntry.form_fields` | `list[str] \| null` | no | Form field names |
| `AuthEntry.auth_schemes` | `list[str]` | yes | `form` / `basic` / `bearer` / `oauth2` / `oidc` / `saml` |
| `AuthEntry.authorization_endpoint` | `str \| null` | no | OAuth/OIDC: auth endpoint |
| `AuthEntry.token_endpoint` | `str \| null` | no | OAuth/OIDC: token endpoint |
| `AuthEntry.scopes_supported` | `list[str] \| null` | no | OAuth/OIDC: scopes |
| `AuthEntry.default_creds` | `list[str]` | yes | Discovered default credentials (e.g. `["admin:admin"]`) |
| `AuthEntry.rate_limited` | `bool \| null` | no | Whether rate-limited |
| `AuthEntry.mfa` | `bool \| null` | no | Whether MFA is supported |
| `AuthEntry.creatable` | `bool \| null` | no | Whether new accounts can be created |
| `AuthEntry.status` | `int \| null` | no | HTTP status code observed |
| `AuthEntry.content_type` | `str \| null` | no |  |
| `AuthEntry.jwt_alg` | `str \| null` | no | JWT kind only: signing algorithm |
| `AuthEntry.jwt_exp` | `str \| null` | no | JWT kind only: expiry |
| `AuthEntry.jwt_aud` | `str \| null` | no | JWT kind only: audience |
| `AuthEntry.token_location` | `str \| null` | no | JWT kind only: `header` / `cookie` / `body` |

### `cookie-header-v1` — cookie-header
Output of URL → COOKIE + HEADER (browser security posture).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"cookie-header-v1"` | yes | Schema discriminator |
| `url` | `str` | yes | Input URL value |
| `cookies` | `list[CookieEntry]` | yes | Set-Cookie entries |
| `headers` | `list[HeaderEntry]` | yes | Security-relevant response headers |
| `CookieEntry.name` | `str` | yes |  |
| `CookieEntry.value_preview` | `str` | yes | Truncated (20 chars max) for safety |
| `CookieEntry.value_length` | `int` | yes | Full value length |
| `CookieEntry.http_only` | `bool` | yes |  |
| `CookieEntry.secure` | `bool` | yes |  |
| `CookieEntry.same_site` | `str` | yes | `Strict` / `Lax` / `None` |
| `CookieEntry.expires` | `str \| null` | no |  |
| `CookieEntry.max_age` | `int \| null` | no |  |
| `CookieEntry.domain` | `str \| null` | no |  |
| `CookieEntry.path` | `str` | yes |  |
| `CookieEntry.risk` | `str` | yes | `low` / `medium` / `high` |
| `CookieEntry.risk_reasons` | `list[str]` | yes | Heuristic reasons |
| `HeaderEntry.name` | `str` | yes |  |
| `HeaderEntry.present` | `bool` | yes |  |
| `HeaderEntry.value` | `str \| null` | no |  |
| `HeaderEntry.security_relevant` | `bool` | yes |  |
| `HeaderEntry.missing` | `bool` | yes | True for expected-but-absent headers |
| `HeaderEntry.disclosure` | `bool` | no | True for info-leaking headers (e.g. Server) |
| `HeaderEntry.disclosure_kind` | `str \| null` | no | `version_revealed` / `stack_revealed` / `framework_version_revealed` / `proxy_chain_revealed` / `generator_revealed` |

### `cloud-storage-v1` — cloud-storage
Output of SUB_DOMAIN → STORAGE + STORAGE_OBJECT (cloud bucket discovery).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"cloud-storage-v1"` | yes | Schema discriminator |
| `subdomain` | `str` | yes | Input subdomain |
| `company_name` | `str` | yes | Extracted company name |
| `storages` | `list[StorageEntry]` | yes | Discovered buckets |
| `StorageEntry.value` | `str` | yes | `"s3://bucket"` / `"oss://bucket"` / `"gcs://bucket"` / `"azure://account/container"` |
| `StorageEntry.provider` | `str` | yes | `aws` / `oss` / `gcs` / `azure` / `minio` / `aliyun` |
| `StorageEntry.bucket` | `str` | yes | Bucket/container name |
| `StorageEntry.region` | `str` | yes | Provider region |
| `StorageEntry.public` | `bool` | yes | Whether anonymous ListBucket is allowed |
| `StorageEntry.objects_count` | `int \| null` | no | Number of objects visible |
| `StorageEntry.storage_objects` | `list[StorageObjectEntry]` | yes | Visible objects (sensitive ones flagged) |
| `StorageObjectEntry.value` | `str` | yes | `"s3://bucket/filename"` |
| `StorageObjectEntry.filename` | `str` | yes |  |
| `StorageObjectEntry.size` | `int \| null` | no |  |
| `StorageObjectEntry.last_modified` | `str \| null` | no | ISO 8601 |
| `StorageObjectEntry.sensitive_kind` | `str` | yes | `database_dump` / `backup` / `credential` / `key` / `config` / `log` / `data` / `archive` / `other` |
| `StorageObjectEntry.sensitivity` | `str` | yes | `critical` / `high` / `medium` / `low` |

### `secret-v1` — secret-scanner
Output of cross-layer (URL/ENDPOINT/STATIC_ASSET/API_SCHEMA/STORAGE/STORAGE_OBJECT) → SECRET (credential leak detection).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"secret-v1"` | yes | Schema discriminator |
| `parent_type` | `str` | yes | `url` / `endpoint` / `static_asset` / `api_schema` / `storage` / `storage_object` |
| `parent_id` | `str` | yes | Parent node id |
| `parent_value` | `str` | yes | Parent node value |
| `secrets` | `list[SecretEntry]` | yes | Discovered secrets |
| `SecretEntry.kind` | `str` | yes | `aws_access_key_id` / `aws_secret_access_key` / `api_token` / `internal_host` / `email` / `jwt` / `private_key` / `db_connection_string` / `stripe` / `google_api` / `slack` / `github_pat` / `password` / `generic` |
| `SecretEntry.source` | `str` | yes | `js` / `env` / `config` / `git` / `document` / `api_response` / `backup` |
| `SecretEntry.evidence` | `str` | yes | Raw evidence (truncated to 80 chars) |
| `SecretEntry.context` | `str` | yes | Surrounding 50-char context |
| `SecretEntry.validated` | `bool` | yes | Whether validated via public API |
| `SecretEntry.validation_detail` | `str \| null` | no |  |
| `SecretEntry.blast_radius` | `str` | yes | `low` / `medium` / `high` / `critical` |

### `seed-v1` — seed-expander
Output of ROOT_DOMAIN → seed list (horizontal expansion). Does NOT write to AssetTree.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"seed-v1"` | yes | Schema discriminator |
| `root_domain` | `str` | yes | Input root domain |
| `seeds` | `list[SeedEntry]` | yes | Discovered seeds |
| `SeedEntry.kind` | `str` | yes | `domain` / `asn` / `ip_range` / `org_name` / `keyword` |
| `SeedEntry.value` | `str` | yes | Seed value (FQDN, ASN12345, 10.0.0.0/8, org name, or keyword) |
| `SeedEntry.confidence` | `str` | yes | `high` / `medium` / `low` |
| `SeedEntry.source` | `str` | yes | `whois` / `asn` / `ct` / `passive_dns` / `related_domain` / `heuristic` |
| `SeedEntry.reason` | `str` | yes | Why this seed was discovered |

---

## Handoff Schema (Phase 3, unchanged)---

## Handoff Schema (Phase 3, unchanged)### `seed-v1` — seed-expander
Output of ROOT_DOMAIN → seed list (horizontal expansion). Does NOT write to AssetTree.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"seed-v1"` | yes | Schema discriminator |
| `root_domain` | `str` | yes | Input root domain |
| `seeds` | `list[SeedEntry]` | yes | Discovered seeds |
| `SeedEntry.kind` | `str` | yes | `domain` / `asn` / `ip_range` / `org_name` / `keyword` |
| `SeedEntry.value` | `str` | yes | Seed value (FQDN, ASN12345, 10.0.0.0/8, org name, or keyword) |
| `SeedEntry.confidence` | `str` | yes | `high` / `medium` / `low` |
| `SeedEntry.source` | `str` | yes | `whois` / `asn` / `ct` / `passive_dns` / `related_domain` / `heuristic` |
| `SeedEntry.reason` | `str` | yes | Why this seed was discovered |

---

## Handoff Schema (Phase 3, unchanged)---

## Handoff Schema (Phase 3, unchanged)### `cloud-storage-v1` — cloud-storage
Output of SUB_DOMAIN → STORAGE + STORAGE_OBJECT (cloud bucket discovery).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"cloud-storage-v1"` | yes | Schema discriminator |
| `subdomain` | `str` | yes | Input subdomain |
| `company_name` | `str` | yes | Extracted company name |
| `storages` | `list[StorageEntry]` | yes | Discovered buckets |
| `StorageEntry.value` | `str` | yes | `"s3://bucket"` / `"oss://bucket"` / `"gcs://bucket"` / `"azure://account/container"` |
| `StorageEntry.provider` | `str` | yes | `aws` / `oss` / `gcs` / `azure` / `minio` / `aliyun` |
| `StorageEntry.bucket` | `str` | yes | Bucket/container name |
| `StorageEntry.region` | `str` | yes | Provider region |
| `StorageEntry.public` | `bool` | yes | Whether anonymous ListBucket is allowed |
| `StorageEntry.objects_count` | `int \| null` | no | Number of objects visible |
| `StorageEntry.storage_objects` | `list[StorageObjectEntry]` | yes | Visible objects (sensitive ones flagged) |
| `StorageObjectEntry.value` | `str` | yes | `"s3://bucket/filename"` |
| `StorageObjectEntry.filename` | `str` | yes |  |
| `StorageObjectEntry.size` | `int \| null` | no |  |
| `StorageObjectEntry.last_modified` | `str \| null` | no | ISO 8601 |
| `StorageObjectEntry.sensitive_kind` | `str` | yes | `database_dump` / `backup` / `credential` / `key` / `config` / `log` / `data` / `archive` / `other` |
| `StorageObjectEntry.sensitivity` | `str` | yes | `critical` / `high` / `medium` / `low` |

### `secret-v1` — secret-scanner
Output of cross-layer (URL/ENDPOINT/STATIC_ASSET/API_SCHEMA/STORAGE/STORAGE_OBJECT) → SECRET (credential leak detection).

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"secret-v1"` | yes | Schema discriminator |
| `parent_type` | `str` | yes | `url` / `endpoint` / `static_asset` / `api_schema` / `storage` / `storage_object` |
| `parent_id` | `str` | yes | Parent node id |
| `parent_value` | `str` | yes | Parent node value |
| `secrets` | `list[SecretEntry]` | yes | Discovered secrets |
| `SecretEntry.kind` | `str` | yes | `aws_access_key_id` / `aws_secret_access_key` / `api_token` / `internal_host` / `email` / `jwt` / `private_key` / `db_connection_string` / `stripe` / `google_api` / `slack` / `github_pat` / `password` / `generic` |
| `SecretEntry.source` | `str` | yes | `js` / `env` / `config` / `git` / `document` / `api_response` / `backup` |
| `SecretEntry.evidence` | `str` | yes | Raw evidence (truncated to 80 chars) |
| `SecretEntry.context` | `str` | yes | Surrounding 50-char context |
| `SecretEntry.validated` | `bool` | yes | Whether validated via public API |
| `SecretEntry.validation_detail` | `str \| null` | no |  |
| `SecretEntry.blast_radius` | `str` | yes | `low` / `medium` / `high` / `critical` |

### `seed-v1` — seed-expander
Output of ROOT_DOMAIN → seed list (horizontal expansion). Does NOT write to AssetTree.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"seed-v1"` | yes | Schema discriminator |
| `root_domain` | `str` | yes | Input root domain |
| `seeds` | `list[SeedEntry]` | yes | Discovered seeds |
| `SeedEntry.kind` | `str` | yes | `domain` / `asn` / `ip_range` / `org_name` / `keyword` |
| `SeedEntry.value` | `str` | yes | Seed value (FQDN, ASN12345, 10.0.0.0/8, org name, or keyword) |
| `SeedEntry.confidence` | `str` | yes | `high` / `medium` / `low` |
| `SeedEntry.source` | `str` | yes | `whois` / `asn` / `ct` / `passive_dns` / `related_domain` / `heuristic` |
| `SeedEntry.reason` | `str` | yes | Why this seed was discovered |

---

## Handoff Schema (Phase 3, unchanged)---

## Handoff Schema (Phase 3, unchanged)### `seed-v1` — seed-expander
Output of ROOT_DOMAIN → seed list (horizontal expansion). Does NOT write to AssetTree.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"seed-v1"` | yes | Schema discriminator |
| `root_domain` | `str` | yes | Input root domain |
| `seeds` | `list[SeedEntry]` | yes | Discovered seeds |
| `SeedEntry.kind` | `str` | yes | `domain` / `asn` / `ip_range` / `org_name` / `keyword` |
| `SeedEntry.value` | `str` | yes | Seed value (FQDN, ASN12345, 10.0.0.0/8, org name, or keyword) |
| `SeedEntry.confidence` | `str` | yes | `high` / `medium` / `low` |
| `SeedEntry.source` | `str` | yes | `whois` / `asn` / `ct` / `passive_dns` / `related_domain` / `heuristic` |
| `SeedEntry.reason` | `str` | yes | Why this seed was discovered |

---

## Handoff Schema (Phase 3, unchanged)---

## Handoff Schema (Phase 3, unchanged)

### `find-complete-v1` — coordinator → hack-deep
Sent via `sessions_spawn(agent_id="hack-deep", ...)` with the AssetTree JSON
path embedded in `artifacts=...`.

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"find-complete-v1"` | yes | Schema discriminator |
| `tree_id` | `str` | yes | The AssetTree id |
| `root_domain` | `str` | yes | Root domain discovered |
| `tree_path` | `str` | yes | Absolute path to persisted AssetTree JSON |
| `tree_stats` | `dict` | yes | Snapshot of `tree.stats()` |
| `frontier_summary` | `list[str]` | yes | One-line per UNSEEN leaf (for the LLM brief) |
| `duration_s` | `int` | yes | Total find-run duration in seconds |

---

## Provenance

- **Created**: 2026-06-14 (hack-deep-find v2 redesign, Phase 3 complete)
- **Updated**: 2026-06-15 (Batch 1: 5 new specialist + 5 new evidence schema)
- **Updated**: 2026-06-15 (Batch 2: 2 new specialist + 2 new evidence schema + 9 new tools)
- **Updated**: 2026-06-15 (Batch 3: 2 new specialist + 2 new evidence schema + 12 new tools)
- **Updated**: 2026-06-15 (Batch 4: 1 new specialist + 1 new evidence schema + 5 new tools + asset_tree_create extended with extra_seeds + new asset_tree_merge tool)
- **Updated**: 2026-06-15 (Batch 5: 0 new specialist + 0 new evidence schema + 2 new orchestrator tools (recon_list_snapshots, recon_diff_snapshots) + asset_tree_complete extended with snapshot_id field. Time-dimension support reusing existing 16 specialist + opensquilla cron)
- **Based on**: hack-deep v3.2 Typed Task Envelope
- **Architecture**: Pure LLM orchestrator + 11 specialist subagents (6 Phase 2 + 5 Batch 1) + handoff to hack-deep
- **Persistence**: AssetTree at `~/.opensquilla/state/asset_trees/<tree_id>.json`
- **Handoff evidence schema**: `find-complete-v1` registered in `attack_dispatch.evidence.EVIDENCE_SCHEMAS`

## Specialist Registry (16 total: 6 Phase 2 + 5 Batch 1 + 2 Batch 2 + 2 Batch 3 + 1 Batch 4)

> **Batch 5 没有新增 specialist**, 只在 orchestrator 层加 2 个 `recon_*` 工具 (在 `group:recon:diff` group)。
> 这 2 个工具是编排器本人直接调, 不通过 `sessions_spawn` 委派。
> Batch 4+ 的 `seed-expander` 返回 `seed-v1` evidence (不进 AssetTree) 给编排器做二轮决策。

### Phase 2 (network surface)

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `subdomain-discoverer` | 子域名枚举专家 | ROOT_DOMAIN | SUB_DOMAIN | `recon_dns_resolve`, `recon_dns_over_https` |
| `ip-resolver` | DNS 解析专家 | SUB_DOMAIN | IP | `recon_dns_resolve`, `recon_dns_over_https` |
| `port-scanner` | 端口发现专家 | IP | PORT | `recon_port_scan_tcp`, `recon_port_scan_range`, `recon_grab_banner`, `masscan_scan`, `nmap_scan` |
| `service-fingerprint` | 服务指纹专家 | PORT | SERVICE | `recon_grab_banner`, `recon_http_probe`, `nmap_scan` |
| `endpoint-crawler` | 端点爬取专家 | SERVICE | ENDPOINT | `recon_directory_bruteforce`, `recon_extract_endpoints_from_js`, `recon_http_probe` |
| `leaf-verifier` | 叶子验证专家 | 任意 | (无子节点) | `recon_http_probe` |

### Batch 1 (web surface + component-level CVE view)

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `service-detailed` | 组件指纹专家 (CVE 视角) | SERVICE | COMPONENT | `recon_cpe_resolve`, `recon_js_component_extract`, `recon_tls_cert_parse`, `recon_ico_hash_lookup` |
| `webapp-discoverer` | Web 应用边界识别专家 | SERVICE | URL | `recon_vhost_bruteforce`, `recon_robots_sitemap`, `recon_tech_detect`, `recon_app_fingerprint`, `recon_url_dedupe` |
| `api-surface` | API 表面结构化专家 | URL | API_SCHEMA + ENDPOINT | `recon_openapi_parse`, `recon_graphql_introspect`, `recon_js_crawl_recursive`, `recon_api_path_normalize`, `recon_auth_probe` |
| `parameter-extract` | 参数级提取专家 | ENDPOINT | PARAMETER | (复用 `group:recon:api` 部分, 不主动 HTTP) |
| `static-asset` | 高价值静态文件专家 | URL | STATIC_ASSET | `recon_sensitive_fingerprint`, `recon_sensitive_variants`, `recon_secret_extract`, `recon_directory_bruteforce` |

### Batch 2 (auth + cookie/header security posture)

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `auth-mapper` | 鉴权面识别专家 | URL | AUTH_SURFACE | `recon_auth_endpoint_discover`, `recon_oauth_flow_probe`, `recon_jwt_analyze`, `recon_default_creds_probe`, `recon_auth_form_parse` |
| `cookie-header` | 浏览器安全态势专家 | URL | COOKIE + HEADER | `recon_cookie_security_parse`, `recon_security_header_audit`, `recon_info_disclosure_header_scan`, `recon_cookie_jar_collect` |

### Batch 3 (cloud storage + cross-layer secret)

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `cloud-storage` | 云存储桶发现专家 | SUB_DOMAIN | STORAGE + STORAGE_OBJECT | `recon_bucket_naming_variants`, `recon_s3_check`, `recon_oss_check`, `recon_gcs_check`, `recon_azure_blob_check`, `recon_bucket_list_objects` |
| `secret-scanner` | 凭证/泄漏扫描专家 | 任意 (跨层) | SECRET | `recon_secret_scan_text`, `recon_secret_scan_js_bundle`, `recon_secret_scan_git_history`, `recon_secret_scan_env_dump`, `recon_secret_classify`, `recon_secret_validate_aws_key` |

### Batch 4 (horizontal seed expansion)

| ID | Name | Input Type | Output Type | Tools |
|---|---|---|---|---|
| `seed-expander` | 横向种子扩展专家 | ROOT_DOMAIN | seed list (不写树) | `recon_whois_lookup`, `recon_asn_lookup`, `recon_ct_subdomain_enum`, `recon_passive_dns`, `recon_related_domain_mining` |

### Batch 5 (time-dimension: snapshot diff)

> **Batch 5 加 0 个新 specialist**, 只在 orchestrator 层加 2 个工具 + 扩展 `asset_tree_complete`。
> 复用 Batch 1-4 的所有 16 specialist + 现有 `opensquilla cron` 触发器。

| Tool | Layer | 用途 | Tool Group |
|---|---|---|---|
| `recon_list_snapshots` | 编排器 (orchestrator 直接调) | 列出 `~/.opensquilla/state/asset_trees/*.json` 历史快照, 支持 `root_domain_substr` 过滤 + mtime 倒序 + 节点统计 | `group:recon:diff` |
| `recon_diff_snapshots` | 编排器 (orchestrator 直接调) | 对比两个 snapshot JSON, 输出 added/removed/changed/moved + sensitivity_escalations (info<low<medium<high<critical 梯子, 单向). `sensitivity_field` 默认 `"risk"` (COOKIE/HEADER convention), STATIC_ASSET 可传 `"sensitivity"` | `group:recon:diff` |

**`asset_tree_complete` 增强 (Batch 5)**:

| 新字段 | 类型 | 说明 |
|---|---|---|
| `snapshot_id` | `str` | 格式 `<tree_id>--<iso_ts>`, 如 `tree-acme-corp.com--2026-06-15T12-34-56Z`. 每次 find-run 生成 distinct snapshot, 可被 `recon_diff_snapshots` 用于时间维度 delta |
| `snapshot_ts` | `str` | 同样的 iso timestamp (UTC) |
| `tree_path` | `str` | (原本就有) 持久化文件绝对路径 |

**典型 cron + diff 报告用法**:
```bash
# 1. 注册每天凌晨 3 点跑一次 find
opensquilla cron add --name "acme-daily-find" \
  --every "0 3 * * *" --agent hack-deep-find \
  --task "FIND acme-corp.com | full-recursive"

# 2. cron 跑完自动写新 snapshot, 下次会话编排器调:
recon_list_snapshots(root_domain_substr="acme-corp.com", limit=2)
#   → 拿到 latest 2 snapshot_id
recon_diff_snapshots(snapshot_a_path=<older.json>, snapshot_b_path=<newer.json>)
#   → 拿到 added/removed/changed/sensitivity_escalations 报告
```

详见 `docs/operations/hack-deep-find-scheduled-scan.md`。


---

## v2 Cross-Owner Evidence Schemas (2026-06-16)

v2 在 `opensquilla.attack_dispatch.evidence` 里注册了 2 个**跨 owner 桥接**
schema, find 编排器在 F2.5 (W2.5 dispatch) 和 F-final (drill-in declaration)
会发。本节是字段表 (类型定义见 `attack_dispatch/evidence.py`)。

### `w2.5-dispatch-v1` — find → deep W2.5 cross-owner dispatch

W2.5 (per-port attack plan) 的 owner 是 `hack-deep-find`, 但 `vulnerability-triage`
specialist 在 deep 的 allow_agents 里。find 不直接 spawn triage, 而是把 dispatch
计划作为 evidence 写盘, 转交 deep 代行 spawn。

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"w2.5-dispatch-v1"` | yes | Schema discriminator |
| `target` | `str` | yes | EvidenceBase 字段; v2 默认填 `"cross-owner-w2.5-dispatch"` |
| `sub_tracks` | `list[dict]` | yes | 每项含 `track_id` (S###), `ports` (ip:port 列表), `vector_class`, `eta_s` |
| `trigger_wave` | `str` | no | 固定 `"W2.5"` (今天只有这一个) |
| `recon_evidence_path` | `str \| None` | no | 派生的 F1 recon-v1 路径 |
| `triage_evidence_path` | `str \| None` | no | 上游 F2 triage-v1 路径, 供 deep 排序 |

Typed Envelope 头 (F2.5 step 8):

```text
HANDOFF W2.5-DISPATCH.find.1
  | deps=W1,W2,W1.5c
  | schema=w2.5-dispatch-v1
  | eta=60
  | artifacts={"dispatch_evidence": "<path>",
              "triage_evidence": "<path>",
              "recon_evidence": "<path>"}
```

### `drill-in-request-v1` — find → deep drill-in declaration

W1.6a/b/c drill-in 归 hack-deep own。find 若 W1 evidence 显示需要 drill-in
(端口扫描缺 / 目录爆破缺 / 历史快照缺等), 不会直接 spawn `recon`, 而是
构造 `DrillInRequestEvidence` 嵌入 find-complete-v1 envelope 的
`artifacts.drill_in_request` 字段, 由 deep 决定是否开 W1.6*。

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_schema` | `"drill-in-request-v1"` | yes | Schema discriminator |
| `target` | `str` | yes | EvidenceBase 字段; v2 默认填 `"cross-owner-drill-in-request"` |
| `requested_slots` | `list[str]` | yes | 推荐开的 slot 名, 必须是 `DRILL_IN_SLOTS["W1"]` 的子集 (今天: `W1.6a/b/c`) |
| `reasons` | `list[str]` | yes | 每个 slot 一条自由文本理由 (e.g. `"W1.6c: port_scan_complete=false on 4 hosts"`) |
| `evidence_paths` | `list[str]` | yes | 决策依据的 F1 证据路径, deep 可重读 |

**deep 收到后的处理** (见 `agents/hack-deep/SOUL_BODY.md` "W2.5 Cross-Owner
Dispatch Handling" 一节): 校验 `requested_slots` 合法性后, 自行决定是否
开 W1.6* drill-in, deep 代行 spawn `recon` (前提: `recon` 在 deep 的
`subagents.allow_agents` 白名单里)。


---

## v3 Adaptive Execution Fallback Table (2026-06-17)

当 16 specialist 不可用时, hack-deep-find 的 3-tier fallback 协议
按下表选 Tier 2 / Tier 3 target。

| Wave (Layer) | Parent asset_type | Tier 1 specialist | Tier 2 legacy_recon | Tier 3 recon_* tool |
|---|---|---|---|---|
| F0 (W0.5) | root_domain (横向) | `seed-expander` | `intel-collection` | `recon_whois_lookup` + `recon_asn_lookup` |
| F0.5 (W0.6) | resource-checkpoint | (n/a) | `recon` | n/a (resource enumeration, not recon) |
| F1 (W1) | sub_domain (主链) | `ip-resolver` | `recon` | `recon_dns_resolve` + `recon_dns_over_https` |
| F1 (W1) | sub_domain (横向) | `cloud-storage` | `attack-surface-enumeration` | `recon_bucket_naming_variants` |
| F1.5 (W1.5) | ip | `port-scanner` | `recon` | `recon_port_scan_range` |
| F1.5c (W1.5c) | port | `service-fingerprint` | `recon` | `recon_grab_banner` |
| F5 (service) | service (comp) | `service-detailed` | `attack-surface-enumeration` | `recon_cpe_resolve` |
| F5 (service) | service (web) | `webapp-discoverer` | `attack-surface-enumeration` | `recon_robots_sitemap` |
| F5 (service) | service (crawl) | `endpoint-crawler` | `recon` | `recon_directory_bruteforce` (小规模) |
| F6a (url) | url (api) | `api-surface` | `attack-surface-enumeration` | `recon_openapi_parse` |
| F6a (url) | url (static) | `static-asset` | `recon` | `recon_sensitive_fingerprint` |
| F6b (url) | url (auth) | `auth-mapper` | `attack-surface-enumeration` | `recon_auth_probe` |
| F6b (url) | url (cookie) | `cookie-header` | `recon` | `recon_extract_endpoints_from_js` |
| F7 (endpoint) | endpoint | `parameter-extract` | `attack-surface-enumeration` | (group:recon:api read-only) |
| 终态 (leaf) | 任意 | `leaf-verifier` | `recon` | `recon_http_probe` |
| 跨层 (secret) | 任意 (白名单) | `secret-scanner` | `recon` | `recon_secret_scan_text` |

**降级触发条件** (3 个):

1. `sessions_spawn(specialist_id, ...)` returns `ToolError: Agent not found`
2. specialist evidence contains `error="specialist_disabled"`
3. `sessions_spawn` returns `ToolError: not in allow_agents`

LLM 必须在 output 里显式写 `[FALLBACK tier=N reason=...]` 状态摘要,
否则视为协议违反(同 specialist 超时 3 次的违规级别)。

**为什么 Tier 3 仍然允许**: 真正的小 install (3-5 个 host) 上, 16
specialist 启动开销 > 自己跑一次 `recon_dns_resolve`。Tier 3 让 find
能在资源受限 install 上**最低限度**完成 (虽然功能降级, 但**不**降
到"自己调 bash / curl" — 这是不可降级边界)。
