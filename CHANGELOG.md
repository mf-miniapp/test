# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **hack-deep-find complete asset surface** (Batches 1-5, 2026-06-15):
  extended asset discovery from 6 to 16 specialists, surfaced 9 new
  asset types (URL / API_SCHEMA / PARAMETER / STATIC_ASSET / COMPONENT
  / AUTH_SURFACE / COOKIE / HEADER / STORAGE / STORAGE_OBJECT / SECRET)
  in active production, added horizontal multi-seed expansion, and added
  time-dimension support (snapshot diff via cron). See
  `docs/plans/2026-06-15-hack-deep-find-batch-1-plan.md` for Batch 1
  RFC; Batches 2-5 follow the same pattern in the codebase.

  **Batch 1 (web surface + CVE component view, 5 specialists + 17 tools + 5 schemas)**:
  - Specialists: `service-detailed`, `webapp-discoverer`, `api-surface`,
    `parameter-extract`, `static-asset`.
  - Tools: `group:recon:webapp` (5), `group:recon:api` (5),
    `group:recon:component` (4), `group:recon:sensitive` (3).
  - Schemas: `component-v1`, `webapp-v1`, `api-surface-v1`,
    `parameter-v1`, `static-asset-v1`.
  - Orchestrator: Step N.5 layered loop with dual-specialist
    parallelism at SERVICE and URL layers.

  **Batch 2 (auth + cookie/header security posture, 2 specialists + 9 tools + 2 schemas)**:
  - Specialists: `auth-mapper` (URL → AUTH_SURFACE), `cookie-header`
    (URL → COOKIE + HEADER, dual-output).
  - Tools: `group:recon:auth` (5), `group:recon:header` (4).
  - Schemas: `auth-surface-v1`, `cookie-header-v1`.
  - URL layer now runs 4 specialist in parallel.

  **Batch 3 (cloud storage + cross-layer secret, 2 specialists + 12 tools + 2 schemas)**:
  - Specialists: `cloud-storage` (SUB_DOMAIN → STORAGE + STORAGE_OBJECT),
    `secret-scanner` (cross-layer → SECRET, scans 8 parent types).
  - Tools: `group:recon:storage` (6: S3/OSS/GCS/Azure + bucket naming +
    list), `group:recon:secret` (6: text scan + JS bundle + git history
    + env dump + classify + AWS validate).
  - Schemas: `cloud-storage-v1`, `secret-v1`.
  - SUB_DOMAIN layer now runs 2 specialist in parallel.

  **Batch 4 (horizontal seed expansion, 1 specialist + 5 tools + 1 schema + asset_tree tool layer changes)**:
  - Specialist: `seed-expander` (ROOT_DOMAIN → seed list, does NOT write
    to AssetTree; orchestrator feeds seeds into extra_seeds or merges).
  - Tools: `group:recon:seed` (5: WHOIS / ASN lookup / crt.sh CT enum /
    passive DNS / related-domain mining).
  - Schema: `seed-v1`.
  - `asset_tree_create` extended with `extra_seeds` parameter (multi-
    seed expansion under one tree).
  - New tool: `asset_tree_merge` (cross-tree consolidation; 8 → 9
    asset_tree tools).
  - ROOT_DOMAIN layer now runs 2 specialist in parallel (subdomain +
    seed-expander).
  - Orchestrator Step 0 extended with multi-seed flow + Step 0.5
    decision (same tree vs. multi-tree + merge).

  **Batch 5 (time-dimension: snapshot diff, 0 new specialists + 2 orchestrator tools + asset_tree_complete extension)**:
  - **0 new specialists** — Batch 5 is purely an orchestrator-level enhancement
    that reuses all 16 specialists from Batches 1-4 and the existing
    `opensquilla cron` scheduler. No new infrastructure.
  - **2 new tools in `group:recon:diff`**:
    - `recon_list_snapshots(root_domain_substr?, limit=50)` — list historical
      `~/.opensquilla/state/asset_trees/*.json`, with mtime-desc ordering
      and per-type node count summary.
    - `recon_diff_snapshots(snapshot_a_path, snapshot_b_path, sensitivity_field="risk", include_subtree_moves=True)` —
      diff two snapshots and bucket by added/removed/changed/moved +
      `sensitivity_escalations` (info<low<medium<high<critical ladder, one-way).
  - **`asset_tree_complete` extended with `snapshot_id` field**:
    now returns `{tree_id, tree_path, snapshot_id, snapshot_ts, stats}`
    where `snapshot_id = "<tree_id>--<iso_timestamp>"` (filesystem-safe).
    Each find-run produces a distinct snapshot for time-dimension diff.
  - **Docs**: `docs/operations/hack-deep-find-scheduled-scan.md` — cron
    usage guide (e.g. `opensquilla cron add --every "0 3 * * *" ...`).
  - **Total now**: 16 specialists + 53 recon tools + 13 tool groups.

  **Batch 5 followup: snapshot diff in web UI (2026-06-15)**:
  - 2 new web endpoints (in `asset_tree/web/`):
    - `GET /asset-tree/api/trees/{id}/snapshots` — list historical
      snapshots (newest first), with `node_count` + `is_cumulative`
      flags. Works in JSON-fallback mode.
    - `GET /asset-tree/api/trees/{id}/diff` — diff current tree
      against the previous snapshot. Returns `mode` (normal /
      first_snapshot / no_snapshots), full added/removed/changed/
      moved/sensitivity_escalations breakdown, and a per-type
      `by_type` summary.
  - The diff core (`diff_nodes` + `diff_snapshots`) is now a sync
    helper in `recon/diff.py`, called by both the LLM tool
    (`recon_diff_snapshots`) and the web store. No logic duplication.
  - "📊 Diff vs 上次" button added to the asset-tree web UI's
    `mainActions` row. Opens a modal showing the per-bucket
    diff with risk-escalations highlighted (purple) at the top.
    Button works in JSON-fallback mode (read-only, no DB needed).

  **Total impact (Batches 1-5)**:
  - Specialists: 6 → 16 (+10)
  - Recon tools: 10 → 53 (+43)
  - Recon tool groups: 3 → 13 (+10)
  - Evidence schemas: 7 → 12 (+5)
  - Asset tree tools: 8 → 9 (+1: asset_tree_merge)
  - Asset tree web endpoints: 9 → 11 (+2: /snapshots, /diff)
  - Asset tree types: 18 → 19 (+1: GENERIC, was already there)
  - Asset tree parent-child edges: extended (URL → AUTH_SURFACE/COOKIE/
    HEADER; SUB_DOMAIN → STORAGE; STORAGE → STORAGE_OBJECT; SECRET
    cross-layer across 8 parent types).

### Changed

- `asset_tree_create` signature extended: now accepts `extra_seeds`
  parameter (list of `{kind, value}` dicts) for multi-seed expansion.
- `asset_tree` tool list in SOUL_BODY: 8 → 9 (added asset_tree_merge).
- Orchestrator SOUL_BODY: specialist table extended with 10 new
  specialists, parallel rules extended at SUB_DOMAIN (2-way), URL
  (4-way), and ROOT_DOMAIN (2-way) layers; Step 0 now includes
  multi-seed flow.
- `asset_tree_complete` return shape extended: now includes
  `snapshot_id` (string, `<tree_id>--<iso_ts>`) and `snapshot_ts`
  (string) for time-dimension snapshot diff (Batch 5).
- `recon_diff_snapshots` and `recon_list_snapshots` are new
  orchestrator-level tools in `group:recon:diff` (Batch 5).
- `recon_diff_snapshots.sensitivity_field` default is `"risk"`
  (matches COOKIE/HEADER convention from the cookie-header specialist;
  use `"sensitivity"` for STATIC_ASSET).
- `asset_tree_complete` now also persists a snapshot copy at
  `<tree_id>--<iso_ts>.json` (in addition to the cumulative
  `<tree_id>.json`), so each find-run leaves a stable historical
  baseline for the web UI's "Diff vs 上次" view.
- Web UI exposes snapshot diff as `GET /asset-tree/api/trees/{id}/diff`
  and `GET /asset-tree/api/trees/{id}/snapshots` (Batch 5 wiring).
  Both work in JSON-fallback mode (no DB required). A "📊 Diff vs 上次"
  button in the main-actions row opens a modal with added/removed/
  changed/sensitivity_escalations breakdown.

### Fixed

- `recon_diff_snapshots` now detects ALL metadata field changes (not just
  the named `sensitivity_field`); the named field is only used to decide
  whether a metadata change is a ladder escalation (Batch 5).
- `_state_root()` in `recon/diff.py` resolves `OPEN_SQUILLA_STATE_DIR`
  lazily on every call (was cached at module import, breaking tests
  that monkeypatch the env var) (Batch 5).
- The `asset_tree_complete` `snapshot_id` field is now backed by a
  real on-disk file at `<tree_id>--<iso_ts>.json` (was metadata only);
  this is what the web UI's "Diff vs 上次" view actually reads.

## [0.3.1] - 2026-06-03

### Added

- Slack Socket Mode support now covers app mentions, self-targeting replies,
  channel metadata, and threaded response routing across onboarding and channel
  runtime paths.
- Short-drama and video helper workflows remain available in the bundled
  MetaSkill catalog, with stronger Windows-safe script handling and clearer
  review pauses for generated media flows.
- CI impact-surface gates classify docs, runtime, dependency, release, and test
  changes so pull requests can run the right checks without forcing the full
  matrix for every documentation-only edit.

### Changed

- WebChat and the Skills view now make MetaSkill readiness, active runs, and
  install visibility easier to inspect while workflows are being reviewed.
- Release install documentation and installer defaults now point to the 0.3.1
  wheel and Windows portable asset names.

### Fixed

- User chat bubbles preserve multiline text and read like authored messages
  instead of collapsing or visually blending with generated output.
- Slack onboarding and runtime paths now reject incomplete Socket Mode setup,
  preserve existing secrets, enforce webhook signing secrets where needed, and
  keep threaded reply channel context.
- Voice/audio workflows and clarification pauses are represented on the main
  release line, so release users get the same usable handoff and resume
  behavior already validated on integration branches.
- Provider request hardening keeps malformed tool-call history from reaching
  providers as invalid request state.

### Acknowledgements

- Thanks @openvictory for #123, #133, and #137, which helped bring visible
  running-state feedback plus short-drama and media helper workflows into the
  0.3.1 release line.
- Thanks @freeaccount-create for #142, which helped bring Slack Socket Mode and
  self-targeting replies into the channel workflow.
- Thanks @ruhook for #124, and thanks @qq712696307 for the authored commit in
  that pull request, which preserved user message newlines in WebChat.
- Thanks @Cola-Alex for #143, which increased tokenjuice summarize and
  failure-context windows for fallback tool-result projection.
- Thanks @nice-code-la for #165 and #166, which helped make voice workflows
  usable end to end and clarification pauses resume cleanly.

## [0.3.0] - 2026-05-31

### Added

- MetaSkills are now first-class workflow capabilities: bundled stable
  MetaSkills, composition parsing, step scheduling, pause/resume user-input
  flows, proposal gates, runtime history, and authoring documentation let
  repeatable multi-step work become reusable agent routines.
- `opensquilla doctor` and the WebUI Health view now provide actionable
  readiness diagnostics across provider, gateway, memory, logs, search, image
  generation, router, channels, sandbox, and embedding surfaces.
- Tokenjuice-backed tool-result projection now compacts large logs, diffs,
  JSON, test output, package-manager output, and other known tool shapes before
  they crowd out provider context.
- A task-oriented documentation set now covers quickstart, configuration,
  WebUI, CLI, tools and sandboxing, sessions, providers, usage and cost,
  memory, compaction, MetaSkills, tool compression, scheduling, channels, MCP,
  troubleshooting, and contribution guidance.

### Changed

- Tool-output context management now separates durable runtime results from
  provider-visible compact previews, records projection telemetry, and uses
  provider request proof/compaction before oversized payloads reach an LLM.
- WebChat, CLI chat, and terminal TUI internals now share more runtime-backed
  turn, stream, slash-command, artifact, attachment, and recovery behavior.
- Long-session memory and compaction flows now preserve raw archive evidence,
  checkpoint receipts, repair queues, and WebUI-safe compaction status instead
  of treating semantic memory quality and context safety as the same signal.
- Channel install extras now expose only real optional packages; Feishu,
  Telegram, DingTalk, WeCom, and QQ are included in the base install instead
  of being accepted as no-op extras.

### Fixed

- WebChat reliability fixes cover router replay, session restore gaps,
  duplicate compaction status, attachment and pasted-text rendering, artifact
  downloads, composer layout, model-router animation timing, and visible
  recovery during long turns.
- Provider and runtime hardening reduces malformed tool-call fallout, preserves
  configured model-switch intent, handles provider tool-choice requirements,
  and keeps oversized current-turn tool payloads from surfacing as bare
  internal failures.
- Cross-platform CI and Windows portability fixes stabilize CLI help rendering,
  sqlite fallback behavior, UTF-8 subprocess handling, Windows-only test
  fixtures, onboarding commands, and release-surface checks.

## [0.2.1] - 2026-05-21

### Changed

- WebUI diagnostics, transcript replay, and artifact presentation now retain
  more turn-usage evidence while keeping generated-file markers out of normal
  chat output.
- Long-running agent turns now expose softer recovery paths for exhausted tool
  budgets, repeated tool failures, large file-write attempts, and artifact
  delivery handoffs when the final model response degrades.
- Release metadata, installer defaults, and documented wheel URLs now point to
  the 0.2.1 release line.

### Fixed

- Windows portable startup now includes a stronger Visual C++ runtime bootstrap
  path for the bundled ONNX router.
- Memory semantic recall now normalizes stored and query embeddings before
  sqlite-vec search, and high-confidence lexical matches are preserved even
  when vector scoring is weak.
- Generated artifact placeholder text is removed from WebChat history and
  channel-facing output after files have already been delivered.
- Tool dispatch and result budgeting reduce bare internal budget failures by
  returning model-visible recovery context when a turn can still continue.

### Acknowledgements

- Thanks @nice-code-la for the portable Windows VC++ runtime bootstrap work in
  #52.

## [0.2.0] - 2026-05-20

### Added

- `opensquilla migrate` imports existing OpenClaw/Hermes homes into OpenSquilla
  with dry-run previews, explicit `--apply`, source auto-detection, migration
  reports, memory/persona conflict handling, skill compatibility reporting, and
  MCP/channel config mapping.
- `opensquilla chat` is now an early usable interactive CLI chat surface with a
  persistent terminal UI, streaming output, queued input, slash-mode discovery,
  prompt/status chrome, tool-call feedback, inline approval handling, and
  deterministic live prompt output.
- Cron automation now spans CLI, WebUI, RPC, channel, and webhook surfaces:
  structured schedule creation, timezone-aware cron/every/at schedules,
  exact/jitter controls, manual runs, channel delivery, webhook delivery, and
  failure destinations.
- Feishu and Discord channel support now includes capability manifests, safer
  DM/group policy metadata, native file/artifact paths, attachment ingestion,
  Feishu websocket/webhook handling, Discord thread/group handling, and clearer
  channel health/status reporting.
- OpenSquilla can run as an inbound MCP server bridge for session workflows:
  clients can list sessions, resolve/read conversation history, send messages,
  and wait for session events through the gateway.
- Generated artifact delivery is more complete across WebUI and channels,
  including traceable generated-file delivery, recovered fallback delivery,
  channel-safe artifact text, and Unicode-safe PDF report rendering.
- Memory surfaces now separate curated memory from raw transcript search, recall
  prior-session evidence, keep manual Dream runs on configured memory
  workspaces, and let compaction continue when memory flush degrades.
- Release/install support now includes versioned release URLs,
  latest-download aliases, reproducible wheel/portable release guidance,
  source install scripts, Windows portable hardening, ONNX/router recovery
  messaging, and Docker/compose alignment on the gateway port.

### Changed

- Release installation docs now use 0.2.0 release asset URLs and
  `/releases/latest/download/` aliases for the current wheel and Windows
  portable zip.
- Cron tool calls now require structured schedule input (`{kind, ...}`) instead
  of backend natural-language schedule parsing. CLI cron flags still accept
  standard user-facing forms such as `--cron`, `--every`, `--at`, and
  `--expression` through RPC compatibility paths.
- Tool dispatch now runs through a policy pipeline with side-effect-aware
  concurrency: safe/read-only tools can batch, while mutating or
  side-effecting tools stay serialized, keyed, or capped.
- Long-running agent turns now use staged `TurnRunner` execution, provider
  request-budget compaction, prompt-cache anchor preservation, bounded
  tool-result storage, approval-aware retry handling, and recovery paths for
  malformed or non-executable tool calls.
- Channel adapters now declare normalized capability and error-taxonomy
  metadata so unsupported, degraded, retryable, and fatal channel behavior is
  surfaced more consistently.
- WebUI chat, sessions, usage, setup, cron, and search surfaces now share more
  runtime-backed state for recency ordering, per-turn token metrics, provider
  badges, setup form behavior, and session cancellation/readback.
- The default gateway/release documentation now centers on port `18791`, and
  release download paths use the current 0.2.0 assets.

### Fixed

- Failed or aborted turns are kept out of later provider context, reducing
  cascading failures after a bad turn.
- Approval-gated tool retries wait for operator decisions instead of exposing
  pending approval state as ordinary model-visible tool output.
- Provider-context tool markers are protected from becoming executable tool
  state.
- High-volume tool and chat turns recover more reliably from request-tail bloat,
  current-turn tool overflow, and provider payload budget pressure.
- Channel replies avoid leaking provider compaction markers, and channel cron
  delivery now reports failures explicitly.
- WebUI reliability fixes cover recency ordering, table boundaries, mobile and
  composer layout, duplicate visible toasts, setup form resilience, search
  provider badges, and session cancellation counters.
- Generated files that were omitted from normal delivery can be recovered
  through the artifact fallback path.
- Feishu-delivered PDF reports now render Unicode text instead of black or
  placeholder glyph blocks.

## [0.1.0rc1] - 2026-05-12

### Added

- OOTB startup path: `compose.yaml` + `start.sh` + `start.ps1` + Quickstart section in README.
- Legacy `memory.*` config fields: 16 deprecated keys silently dropped with a single aggregated `DeprecationWarning`.
- Agent CLI no-key error: three-section actionable panel (Symptom / Cause / Next steps).
- Tool concurrency: same-turn safe `tool_calls` dispatched concurrently via `asyncio.gather` (22 safe tools enrolled in `_SAFE_TOOL_NAMES`; mutex tools remain serial).
- PID file lock to prevent two gateway instances from sharing the same state directory.
- Core observability counters: `opensquilla_queue_depth`, `in_flight_turns_total`, `turn_cancellations_total`, `queue_full_errors_total`.
- CI matrix on `ubuntu-latest` and `windows-latest` × Python 3.11/3.12, including a metric-name drift check and a tracemalloc leak smoke step.
- Per-channel-adapter in-flight reply cap (`_ChannelInFlightSet`) so a single channel cannot exhaust the global concurrency budget.
- Cross-session fair queueing: sessions sharing an `agent_id` round-robin available slots by completion count.
- Session epoch counter so events from a pre-reset turn are discarded by the frontend after `session.reset`.
- Atomic write helper for transcript attachments (`_atomic_write_bytes`): tmp + fsync + `os.replace`.
- Concurrency env overrides — `OPENSQUILLA_TASK_MAX_CONCURRENCY` and `OPENSQUILLA_CHANNEL_INFLIGHT_CAP` — with invalid-value fallback and warning logs.

### Changed

- Internal SquillaRouter package moved from `opensquilla.contrib.squilla_router`
  to `opensquilla.squilla_router`; bundled model assets now live under
  `src/opensquilla/squilla_router/models/`.
- `TurnRunner` and `TaskRuntime` share a single per-session `asyncio.Lock` (injected via `session_lock_provider`), removing the two-layer lock dictionary and the reverse-acquire risk it created.

### Fixed

- Channel adapter ghost-turn bug: a `TaskQueueFullError` no longer leaves a dangling user message in the transcript.
- `TaskRuntime` terminal-state dictionary leak across `_tasks`, `_session_locks`, and `_pending_by_session`.
