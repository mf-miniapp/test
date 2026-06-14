# Attribution — hack-deep-ex (Post-Exploitation, 3-harness split v1.0)

Created **2026-06-15** as the post-exploitation owner in the 3-harness
split (see `opensquilla.attack_dispatch.waves.OwnerAgent`). Cloned
from `hack-deep` v3.3 (2026-06-08) by stripping W0-W4 attack waves
and keeping W5-W8 post-exploitation only.

## 5 Specialist `evidence_schema` Reference

| agent_id | evidence_schema | Notes |
| --- | --- | --- |
| privilege-escalation | `privesc-v1` | (unchanged from hack-deep) — read W4 footholds[], output `escalation_vectors[]` + `safe_validation_plan[]`. |
| lateral-movement | `lateral-v1` | (unchanged from hack-deep) — reads W1 `infra_sharing` for cross-subdomain pivot, plus W5 privesc creds. |
| persistence-maintenance | `persist-v1` | (v3.3 2026-06-08 fully typed) — see PersistEvidence: `topology_map` (list[TopologyHop] = client→edge→...→backend), `options` (list[PersistenceOption] with 16 fields incl. `mechanism` enum 40+ values, `output_target` (OutputTarget: location = response_header\|body\|error_log\|access_log\|written_file\|jwt_token\|cookie\|database_row\|external_artifact\|process_state\|kernel_object, path, expected_marker), `expected_behavior` (map: connect=403 / http_proxy=301 etc. — fixes the CONNECT false-negative), `antipatterns` (list[str] — things that LOOK like failures but are not), `pass_criteria` (list[PassCriterion] with kind enum 11 values + expected + description), `verification_script` (ONE complete script — no v1→v2→v3→v4 iteration), `validation_outcome` (pass\|warn\|fail\|in_progress\|blocked — set ONCE, not iterated), `verification_timing` (read_after_s ≥ 2 / poll_attempts ≥ 3 / poll_interval_s ≈ 1 — fixes the file-write race), `parallel_verification` (bool), `cache_key` (composite key for re-runs), `raw_evidence` (structured: proof_type + proof_content + captured_at — replaces grep/head mixing), `cleanup_difficulty` (trivial\|easy\|moderate\|hard\|irreversible), `cleanup_notes`, `discovered_by` + `discovered_at`, `manual_effort_minutes`, `depends_on_foothold` (foothold_id from pentest-v1). Top-level: `antipattern_log`, `parallel_verification_used`, `cache_keys_emitted`. |
| impact-exfiltration | `impact-v1` | (unchanged from hack-deep) — confidentiality / integrity / availability impact model + typed exfil_steps + chain-of-custody. |
| cleanup-rollback | `cleanup-v1` | (unchanged from hack-deep) — per-persistence-option cleanup status + before/after state diff + risk_residual. |
| reporting-remediation | `report-v1` | (v1.0 2026-06-15) — adds `gate_engagement_type` / `gate_pass_rate` / `gate_failed_entry_ids` from 7-Question Gate (mirrors `SevenQuestionGate` applied per finding in W4). W8 reports roll up the gate verdict set from W4 footholds + W5/W6/W7 evidence into a single pass-rate summary. |

## 5 Granular Fix Markers (carried from hack-deep)

1. `safe_validation_plan` — W5 privesc must be read-only (no real escalation on prod target)
2. `infra_sharing` — W6 lateral reads W1's cross-subdomain vector table
3. `topology_map` — W7 persistence requires topology BEFORE any curl
4. `parallel_verification` — W7 4-point parallel verification saves 4x runtime
5. `gate_*` — W8 report rolls up W4 7-Question Gate verdicts into a single audit metric

## 3-Harness Boundary Markers (2026-06-15)

1. **W5+ ownership** — only hack-deep-ex drives W5-W8 (enforced via `check_authorization`)
2. **No W0-W4 spawning** — hack-deep-ex cannot spawn `engagement-planning` /
   `vulnerability-triage` / `opsec-evasion` / `penetration`; if needed,
   issue a typed `POST-EXPLOIT-COMPLETE.ex.1 -> hack-deep` reverse-handoff
   and wait for it to re-issue.
3. **No W0.5-W3.5 spawning** — hack-deep-ex cannot spawn `recon` /
   `intel-collection` / `attack-surface-enumeration` / `subdomain-discoverer`
   / `ip-resolver` / `port-scanner` / `service-fingerprint` /
   `endpoint-crawler` / `leaf-verifier`; if a new asset is discovered
   during lateral movement, write it to `emit_new_target` and let
   hack-deep-find re-process on the next operator-driven run.

## Modification log

- 2026-06-15: **Initial 3-harness split release.** Cloned from
  hack-deep v3.3 (2026-06-08). Stripped W0-W4 attack surface;
  kept W5-W8 post-exploitation. The 5 specialists + 5 evidence
  schemas are unchanged from hack-deep; the only change is the
  owner_agent in the WaveSpec registry. The Typed Envelope +
  RESULT MARKER + Serial Mode contracts are inherited from
  hack-deep v3.2 (2026-06-07). The `subagents.allow_agents`
  allowlist is narrowed to the 5 post-exploitation specialists
  + the reporting-remediation + cleanup-rollback specialists.
