# Scheduled hack-deep-find Scans (Batch 5)

> Time-dimension support for `hack-deep-find`. Re-run the find pipeline
> on a schedule, diff the new tree against the previous snapshot, and
> surface new attack surface (or sensitivity escalations) over time.
>
> **Date**: 2026-06-15 · **Depends on**: hack-deep-find Batch 4 (multi-seed)
> + Batch 5 (snapshot_id + diff tools).

## What Batch 5 adds

1. **`asset_tree_complete`** now returns a `snapshot_id` of the form
   `<tree_id>--<iso_timestamp>` (e.g. `tree-acme-corp.com--2026-06-15T12-34-56Z`).
2. **Two new recon tools**:
   - `recon_list_snapshots(root_domain_substr?, limit?)` — list all on-disk
     AssetTree JSON snapshots, newest first.
   - `recon_diff_snapshots(snapshot_a_path, snapshot_b_path,
     sensitivity_field?, include_subtree_moves?)` — diff two snapshots
     and return added / removed / changed / moved / sensitivity-escalation
     nodes, plus a per-type summary.
3. **Recommended scheduling pattern**: re-use the existing
   `opensquilla cron` infrastructure (see
   [`docs/scheduling.md`](../scheduling.md)). No new scheduler is
   introduced — `hack-deep-find` is just an LLM-driven prompt that
   happens to call the diff tools at the end.

## How to schedule a recurring scan

### Every 6 hours — quick delta

```sh
opensquilla cron add \
  --every 6h \
  --text 'Run hack-deep-find on example.com. After asset_tree_complete, call recon_list_snapshots("example.com", limit=2), then recon_diff_snapshots(<older>, <newer>). Report only: (a) newly added nodes, (b) sensitivity escalations, (c) newly discovered critical-static-asset hits (/.env, /.git/HEAD, /backup.sql, /actuator/env). Do NOT re-run the full 16-specialist walk; just call asset_tree_get_subtree on the new tree. Deliver to the cron channel.' \
  --name example-com-delta-6h
```

### Daily at 09:00 — full re-scan with diff

```sh
opensquilla cron add \
  --cron "0 9 * * *" \
  --tz "Asia/Shanghai" \
  --text 'Run a full hack-deep-find on example.com (root_domain + 关联域 via seed-expander). After asset_tree_complete, list all snapshots, diff the new one against the previous one, and produce a short report covering: (1) new subdomains, (2) new IP/port/service combinations, (3) new STATIC_ASSET hits (especially critical), (4) sensitivity escalations on existing STATIC_ASSET / COOKIE / HEADER nodes, (5) new SECRET leaks. If a sensitivity_escalation count > 0 OR any new critical STATIC_ASSET is found, deliver immediately; otherwise suppress.' \
  --name example-com-daily-full
```

### Weekly — long-tail + cross-tree merge

```sh
opensquilla cron add \
  --cron "0 3 * * 0" \
  --tz "Asia/Shanghai" \
  --text 'Weekly recon on example.com + the 5 seed domains tracked in workspace. Use seed-expander to expand seeds, asset_tree_create(extra_seeds=...) for each, run the full pipeline, then asset_tree_merge into a single tree-weekly-N. Diff tree-weekly-N against tree-weekly-(N-1) (use recon_list_snapshots to find them). Summarize the net new attack surface; deliver the full snapshot_id and a per-type diff.' \
  --name example-com-weekly
```

## What the LLM does at runtime

Given the cron prompt, the LLM:

1. **Optionally runs the full pipeline** by calling the `hack-deep-find`
   agent (which produces a new AssetTree + `snapshot_id`).
2. **Lists existing snapshots** with `recon_list_snapshots(<root_domain_substr>)`.
3. **Picks the previous snapshot** (the second-newest, or one matching
   a specific date).
4. **Diffs** with `recon_diff_snapshots(<old_path>, <new_path>)`.
5. **Filters and summarizes** the diff per the cron prompt's instructions.
6. **Delivers** the result to the configured channel (default cron
   delivery destination).

### Example expected output (delivered to channel)

```
[hack-deep-find delta 2026-06-15T12:34:56Z vs 2026-06-15T06:34:56Z]
Snapshot: tree-acme-corp.com--2026-06-15T12-34-56Z
  Added: 3 nodes (2 sub_domain, 1 STATIC_ASSET critical)
  Removed: 0
  Changed: 1 (COOKIE: same_site Lax → None, risk medium → high)
  Sensitivity escalations: 1 (COOKIE as above)

⚠️ New critical static asset: https://api.example.com/.env (status 200,
   1234 bytes, contains AWS_ACCESS_KEY_ID=AKIA...).

🔍 New subdomains: staging-api.example.com, ci-runner.example.com
   (both resolved to 1.2.3.4, ports 443 / 22).
```

## Diff tool reference

### `recon_diff_snapshots`

```python
result = recon_diff_snapshots(
    snapshot_a_path="~/.opensquilla/state/asset_trees/tree-acme-corp.com--2026-06-15T06-34-56Z.json",
    snapshot_b_path="~/.opensquilla/state/asset_trees/tree-acme-corp.com--2026-06-15T12-34-56Z.json",
    sensitivity_field="sensitivity",  # default
    include_subtree_moves=True,        # default
)
# Returns:
# {
#   "summary": {"added": 3, "removed": 0, "changed": 1, "moved": 0,
#               "sensitivity_escalations": 1, "by_type": {...}},
#   "added": [...],
#   "removed": [...],
#   "changed": [...],          # includes parent_id moves
#   "moved": [...],
#   "sensitivity_escalations": [...],
# }
```

Sensitivity escalation detection uses a fixed risk ladder:
`info < low < medium < high < critical`. Only changes that climb
the ladder are flagged as escalations (e.g. `low → high` is; `high →
medium` is NOT).

### `recon_list_snapshots`

```python
result = recon_list_snapshots(
    root_domain_substr="acme-corp.com",
    limit=10,
)
# Returns the 10 newest snapshots for that substring, with mtime,
# size, and per-type node counts.
```

## Operational considerations

| Concern | Recommendation |
|---|---|
| Snapshot retention | `cron` does not auto-prune. Add a quarterly `find ~/.opensquilla/state/asset_trees/*.json -mtime +90 -delete` to clean up. |
| Disk usage | Each AssetTree JSON is ~10 KB – 1 MB depending on size. 100 snapshots ≈ 100 MB. |
| Diff performance | Pure-Python, O(n) over nodes. Snapshots up to ~50 K nodes diff in <1 s. |
| Concurrent scans | If two cron jobs run at once, each writes a unique `snapshot_id` (timestamp) — no conflict. |
| Cross-scan dedup | The `recon_diff_snapshots` tool uses (asset_type, value, parent_id) — so the same node appearing in both snapshots is naturally not counted as "added". |
| handoff to hack-deep | After diff, if the cron prompt calls `sessions_spawn(agent_id="hack-deep", ...)` with the new tree, hack-deep gets a fresh handoff per scan. |

## Why Batch 5 is "no new scheduler"

OpenSquilla already has a battle-tested cron infrastructure
(`opensquilla cron add/list/remove/status/runs`). Rather than building
a recon-specific scheduler, Batch 5 standardizes the *output*
(`snapshot_id`, `recon_list_snapshots`, `recon_diff_snapshots`) so
that **any** LLM prompt — via cron, manual run, or another agent —
can produce a time-dimension delta.

If you need a recon-specific scheduler (e.g. "scan every weekday at
9am but skip if last scan was <12h ago"), put that policy in the
cron `--text` prompt — the LLM will skip based on
`recon_list_snapshots`.

## Out of scope (Batch 5 does NOT do)

- **Alert routing** (PagerDuty / Slack / webhook on critical-only
  diffs): keep using `opensquilla cron --webhook-url` for delivery.
- **Historical visualization** (time-series charts of new
  subdomains per day): not a tool concern; consume `recon_list_snapshots`
  + `recon_diff_snapshots` output in your own dashboard.
- **Delta handoff to hack-deep**: a `find-complete-v1` schema
  extension with a `previous_snapshot_id` field is left for a
  follow-up Batch 5.x.

## See also

- [`docs/scheduling.md`](../scheduling.md) — general cron usage
- [`docs/features/asset-tree-asset-types.md`](../features/asset-tree-asset-types.md) — node type metadata
- [`docs/plans/2026-06-15-hack-deep-find-batch-1-plan.md`](../plans/2026-06-15-hack-deep-find-batch-1-plan.md) — Batch 1 RFC (Batch 5 builds on its tree / tool architecture)
