# Attribution — hack-deep

Cloned from `cyberstrike-deep` on 2026-06-05. The 13 specialist agents and their
`evidence_schema` names are inherited from `cyberstrike-deep`'s port; this
attribution documents only the v3.1 differences.

## 13 Specialist `evidence_schema` Reference

| agent_id | evidence_schema | Added fields (v3.1) |
| --- | --- | --- |
| engagement-planning | `roe-v1` | + `success_unit: per-port \| per-host \| per-domain` |
| recon | `recon-v1` | + `infra_sharing: [{subdomain, ip, asn, cidr, ssl_cert_fp, js_bundle_hash}]` |
| intel-collection | `intel-v1` | (unchanged) |
| attack-surface-enumeration | `surface-v1` | (unchanged) |
| vulnerability-triage | `triage-v1` | (unchanged) |
| opsec-evasion | `opsec-v1` | + `per_target_group: [{group_id, strategy, stop_signal}]` |
| penetration | `pentest-v1` | (dynamic sub-tracks; no fixed count) — v3.2 (2026-06-07) fully typed: every finding has `cvss` (3.1 base + vector), `classification` (CWE/OWASP/MITRE/technique), `auth_context` (anonymous/admin/...), `request`+`response` (full PoC capture), `reproduce_steps` (structured, NOT free-text), `chain_id`/`follows_from`/`enables`, `roe_violation`, `tool_used`+`manual_effort_minutes`, `cleanup_*` fields, `discovered_by`+`discovered_at`. `footholds` typed with `type`/`persistence_level`/`cleanup_difficulty`. New `methodology_steps` (PTES-aligned), `coverage_gaps`, `suggested_drill_in`, `out_of_scope_hits`+`scope_violations`, `rate_limit_per_vector` (per-vector). |
| privilege-escalation | `privesc-v1` | (unchanged) |
| lateral-movement | `lateral-v1` | (reads `recon`'s `infra_sharing` for cross-subdomain) |
| persistence-maintenance | `persist-v1` | (v3.3 2026-06-08 fully typed) — see PersistEvidence: `topology_map` (list[TopologyHop] = client→edge→...→backend), `options` (list[PersistenceOption] with 16 fields incl. `mechanism` enum 40+ values, `output_target` (OutputTarget: location = response_header\|body\|error_log\|access_log\|written_file\|jwt_token\|cookie\|database_row\|external_artifact\|process_state\|kernel_object, path, expected_marker), `expected_behavior` (map: connect=403 / http_proxy=301 etc. — fixes the CONNECT false-negative), `antipatterns` (list[str] — things that LOOK like failures but are not), `pass_criteria` (list[PassCriterion] with kind enum 11 values + expected + description), `verification_script` (ONE complete script — no v1→v2→v3→v4 iteration), `validation_outcome` (pass\|warn\|fail\|in_progress\|blocked — set ONCE, not iterated), `verification_timing` (read_after_s ≥ 2 / poll_attempts ≥ 3 / poll_interval_s ≈ 1 — fixes the file-write race), `parallel_verification` (bool), `cache_key` (composite key for re-runs), `raw_evidence` (structured: proof_type + proof_content + captured_at — replaces grep/head mixing), `cleanup_difficulty` (trivial\|easy\|moderate\|hard\|irreversible), `cleanup_notes`, `discovered_by` + `discovered_at`, `manual_effort_minutes`, `depends_on_foothold` (foothold_id from pentest-v1). Top-level: `antipattern_log`, `parallel_verification_used`, `cache_keys_emitted`. Backward-compat: old dict-shaped options are coerced by Pydantic; the schema name stays `persist-v1`. |
| impact-exfiltration | `impact-v1` | (unchanged) |
| cleanup-rollback | `cleanup-v1` | (unchanged) |
| reporting-remediation | `report-v1` | + `per_target_finding: [{entry_id, status, evidence_ref, impact_ref}]` |

## 7 Granular Fix Markers

1. `success_unit` — per-port / per-host / per-domain 成功粒度
2. `per_target_group` — W3 隐蔽策略 per-target 段
3. `dynamic_sub_tracks` — W4 fan-out 数量(非固定 3)
4. `Wn.5a` / `Wn.5b` / `Wn.5c` — drill-in reason classes
5. `infra_sharing` — W1 evidence 喂给 W6 lateral
6. `per_target_finding` — W8 report 主索引
7. `W3_internal_subcall` — W3 允许 2 次 in-wave sub-call

## Modification log

- 2026-06-05: Cloned from `cyberstrike-deep`. Re-framed as 4-layer × 9-wave DAG
  with strict Typed Task Envelope. `cyberstrike-deep` **not modified**.
- 2026-06-07: `scripts/clone_cyberstrike_to_hack_deep.py::_register_in_config`
  now auto-enables `[subagent_supervisor] enabled = true` in
  `~/.opensquilla/config.toml`. The watchdog cron is idempotent — re-running
  the clone with the supervisor already on is a no-op. This change was made
  to prevent recurrence of the 2026-06-05 hack-deep incident where the
  primary path's dedup set dropped a terminal announce and no supervisor
  existed to replay it.
- 2026-06-07: **Serial mode v3.2** — SOUL contract flipped from
  "一次 assistant message 内多 sessions_spawn 调用 (fan-out)" to
  "一次 1 个 sessions_spawn + sessions_yield 等收口". The Python
  executor (now `mode=DispatchMode.SERIAL` by default for hack-deep)
  persists each specialist's raw to a per-specialist JSON file
  (`<root>/<wave>/<handoff_id>.json`) BEFORE the next call, and fires
  the `context_reduction` callback so the LLM can release the raw
  from its context window. Drill-in slots (`.5a`/`.5b`/`.5c`) also
  go through serial-mode per-slot persistence. Combined per-wave
  artifacts remain in place, slim-evidence + a
  `per_specialist_artifacts` map. The 51ifind.com pressure test
  showed a 4× reduction in LLM context window for the breadth layer
  (W1 fan-out 3→1) without losing any evidence fidelity. The
  dispatch executor's PARALLEL mode (the default at the Python
  library level) is unchanged — existing cyberstrike-deep wiring
  (if any) is not affected.
- 2026-06-08: **fix 11 — auto-continue contract** — eliminates the
  "shall I continue?" / "是否继续?" stall that paused the
  2026-06-08 51ifind.com orchestrator at "是否继续推进 W3?" for
  24+ hours. Three layers:
  - `attack_dispatch.envelope.is_confirmation_question_stall(text)`
    detects confirmation questions ending in `?` / `？` / `。` / `)`
    with stall keywords (`shall i` / `should i` / `do you want me
    to` / `want me to` / `continue?` / `should i proceed` /
    `是否继续|开始|推进|进入|执行|启动|要` / `请确认是否` / etc.).
    Conservative: only the LAST non-empty line is checked, and a
    real RESULT MARKER wins over the question (the LLM is
    intentionally handing off).
  - `_result_payload` in `gateway/subagent_announce.py` calls the
    helper and tags the wake payload with `auto_continue=True` +
    `stall_reason="confirmation_question"`. The parent's
    `sessions_yield` no longer waits on operator input.
  - The new SOUL_BODY.md §10 ("Auto-Continue Contract") is the
    LLM-side rule: 13 specialists (including persistence-
    maintenance) **MUST NOT** output any of the 7+ forbidden
    confirmation patterns at wave boundaries, drill-in triggers,
    cleanup phases, or reporting closure. The brief footer
    (`_templates/persistence_brief_footer.md`) adds a dedicated
    `## 🚫 ANTI-PATTERN` section naming the forbidden patterns
    inline so the persistence specialist sees them every time.
- 2026-06-08: **persist-v1 v3.3** — full schema rewrite of the W7
  persistence evidence, mirroring the pentest-v1 v3.2 hardening.
  Triggered by the 2026-06-08 hack-deep W7 session optimization
  report (10 pain points from the 51ifind.com pressure test).
  `PersistEvidence` now carries `topology_map` (list[TopologyHop] =
  client→edge→...→backend, populated BEFORE any curl runs);
  `options` is now `list[PersistenceOption]` with 16 fields: a
  40+-value `mechanism` enum (cron_job / systemd_unit /
  ssh_authorized_keys / apache_module / nginx_module / lua_module /
  jwt_signing_key / ssh_reverse_tunnel / etc.), `topology_path`
  (must be a contiguous suffix of `topology_map`),
  `output_target` (OutputTarget: `location` is one of
  response_header|body|error_log|access_log|written_file|jwt_token|
  cookie|database_row|external_artifact|process_state|kernel_object,
  with `path` + `expected_marker`),
  `expected_behavior` (map of access-mode → response code — fixes
  the CONNECT-403 false-negative, where the 403 is actually
  expected isolation not a fail),
  `antipatterns` (list[str] — things that LOOK like failures but
  are not, e.g. "Apache 200 + 0-byte body = mod_lua loaded, write
  pending"),
  `pass_criteria` (list[PassCriterion] with an 11-value `kind`
  enum + `expected` value + `description`),
  `verification_script` (ONE complete script — replaces the
  v1→v2→v3→v4 iteration pattern),
  `validation_outcome` (pass|warn|fail|in_progress|blocked — set
  ONCE, not iterated),
  `verification_timing` (read_after_s ≥ 2 / poll_attempts ≥ 3 /
  poll_interval_s ≈ 1 — fixes the file-write race),
  `parallel_verification` (bool — drives the 4-persistence-point
  parallel batch),
  `cache_key` (composite key for re-runs — fixes "缺乏结果缓存"),
  `raw_evidence` (structured: proof_type + proof_content +
  captured_at — replaces ad-hoc `grep -o | head` mixing),
  `cleanup_difficulty` (trivial|easy|moderate|hard|irreversible),
  `cleanup_notes`,
  `discovered_by` + `discovered_at`,
  `manual_effort_minutes`,
  `depends_on_foothold` (foothold_id from pentest-v1).
  Top-level new fields: `antipattern_log`, `parallel_verification_used`,
  `cache_keys_emitted`. The W7 sub-track brief is now backed by
  `_build_w7_persist_brief` in `executor.py`, which surfaces W6
  pivot points + W4 footholds as inline hints, followed by
  `_W7_PERSIST_BRIEF_FOOTER` (extracted to
  `_templates/persistence_brief_footer.md`) that names every
  field the LLM must fill, includes a 10-step pre-flight
  checklist, and ends with a strong RESULT MARKER reminder. The
  runtime auto-appends a synthetic marker if the LLM forgets
  (synthesize_marker in attack_dispatch.envelope), so the parent
  never gets stuck — but a real marker with a real schema is
  always preferred. Schema name stays `persist-v1` for backward
  compat; old dict-shaped options are coerced by Pydantic into
  the new typed sub-model, so previously-serialized artifacts
  load unchanged.
- 2026-06-07: **pentest-v1 v3.2** — full schema rewrite of the W4
  penetration evidence to be the strongest possible pentest contract.
  Triggered by the 2026-06-07 hack-deep W4.1 V001 IDOR incident
  (a penetration subagent ran out of patience mid-attack, never
  emitted a RESULT MARKER, and left the parent waiting indefinitely).
  Findings now carry: `cvss` (CVSS 3.1 base + full vector), structured
  `classification` (CWE ID + OWASP Top 10 2021 + MITRE ATT&CK T-codes +
  40+ exploitation_technique enum), `auth_context` (anonymous /
  authed_low / authed_user / authed_admin / internal_only), structured
  `request`+`response` (full PoC capture, not free-text), `reproduce_steps`
  as typed list (NOT free-text — each step's `command` field is
  captured verbatim for the W8 report), `chain_id` / `follows_from` /
  `enables`, `roe_violation` flag + scope_violations, `tool_used` +
  `manual_effort_minutes`, `cleanup_*` fields (drives W8.1), `discovered_by`
  + `discovered_at`. `footholds` is now typed with `type` (40+ enum
  including rce_shell / credential / file_read / ssrf / ...) +
  `persistence_level` + `cleanup_difficulty`. New top-level fields:
  `methodology_steps` (PTES-aligned audit), `coverage_gaps`,
  `suggested_drill_in`, `out_of_scope_hits`, `rate_limit_per_vector`.
  Schema name stays `pentest-v1` for backward compat; the data shape
  is fully typed. The W4 sub-track brief now ends with a 15-field
  mandatory-fill checklist + a strong RESULT MARKER reminder, and
  the runtime auto-appends a synthetic marker if the LLM forgets
  (so the parent never gets stuck again). 51ifind.com-style pressure
  test scenarios (IDOR / SSRF / RCE / chain exploitation) all
  construct cleanly under the new schema.
