---
name: attack-dispatch
description: 'Fixed attack dispatch model (replaces the broken 7-phase checklist). Drives a 4-layer × 9-wave DAG with Typed Task Envelopes, wave barriers, dynamic fan-out, and Wn.5a/b/c drill-in triggers. Asset-agnostic: subdomain and port counts are never hardcoded. The Python module `opensquilla.attack_dispatch` is the canonical implementation; this SKILL.md is the LLM-readable contract an orchestrator must follow.'
metadata:
  {
    "opensquilla":
      {
        "risk": "high",
        "capabilities": ["network:read", "shell:execute"],
        "requires_tools": ["sessions_spawn"],
      },
  }
---

# Attack Dispatch — Fixed Model

This skill defines **how an orchestrator dispatches attack work**, not the
attack work itself. The 14 specialist agents (recon, penetration, …) live
elsewhere; this skill tells the orchestrator **when** to call them, **how**
to shape the handoff, **what** the evidence must look like, and **when** to
drill in.

## Why this exists

The previous 7-phase dispatch was a checklist, not a dispatch:

| Flaw | Why it broke | Fix in this skill |
|---|---|---|
| Hardcoded port list (e.g. `80/443/8080/...`) | Missed services on other ports | Recon discovers everything; no port list in the dispatch |
| Hardcoded "7 subdomains" | Skipped when count differed | Subdomain count is discovered, not declared |
| 7 phases overlap (recon vs sub-recon; exfil vs DB-triage) | Duplicated work, duplicated EDR noise | Single source of truth: W1 recon produces the asset map; downstream waves consume it |
| No exit criteria per phase | Worker never knew when to stop | Each wave's evidence schema declares its required outputs; thinness triggers drill-in |
| No barrier between waves | Evidence got lost between phases | Hard barrier — a wave's deps must all have evidence before it can start |
| No drill-in | Re-running the whole DAG was the only retry | `Wn.5a / Wn.5b / Wn.5c` per reason class |
| Opsec not gated | W4 fired with no stealth adjustment | W3 sits between W1 and W2; W2's priority ranking reads W3's per-target stealth |
| Mixed asset types in one worker | Worker had to switch mental models | Each wave has a single specialist (or a small static fanout) |

## Wave DAG (4 layers × 9 waves)

```
广度层 (Breadth)
  W0  engagement-planning                                          single
  W1  recon ‖ intel-collection ‖ attack-surface-enumeration        static_fanout (3)
  W2  vulnerability-triage                                         single
       ↓ barrier
隐蔽层 (Covert)
  W3  opsec-evasion                                                single (2 in-wave sub-calls allowed)
       ↓ barrier
深度层 (Depth)
  W4  penetration                                                  dynamic_fanout (count = entry_count / 8)
  W5  privilege-escalation                                         single
  W6  lateral-movement                                             single
  W7  persistence-maintenance ‖ impact-exfiltration                 static_fanout (2)
       ↓ barrier
收口层 (Synthesis)
  W8  cleanup-rollback ‖ reporting-remediation                      static_fanout (2)
```

Drill-in slots (only Breadth + Depth; Covert and Synthesis are excluded):

```
W1.5  W4.5  W6.5     each with reasons a / b / c
```

## Typed Task Envelope (mandatory on every dispatch)

Every `sessions_spawn` call from an orchestrator running this model MUST
start its `task` argument with this 4-field header line:

```
HANDOFF <handoff_id> | deps=<csv-or-"empty"> | schema=<evidence_schema> | eta=<seconds>

<natural-language brief>
```

Field reference:

| Field | Meaning | Example |
|---|---|---|
| `handoff_id` | wave + specialist + sub-index, or `Wn.5<r>` for drill-in | `W1.recon.1` / `W4.5a` |
| `input_dependencies` | comma-separated upstream handoff_ids, or literal `empty` | `W0.engagement-planning.1` |
| `evidence_schema` | the schema name the specialist must produce | `recon-v1` |
| `expected_runtime_s` | integer seconds, the orchestrator's budget for this call | `180` |

Validation: regex `^HANDOFF\s+\S+\s*\|\s*deps=\S+\s*\|\s*schema=\S+\s*\|\s*eta=\d+`
(strict start-of-line; leading whitespace tolerated).

## Evidence schemas (13)

Each wave's specialist MUST produce one of:

```
roe-v1         — engagement-planning
recon-v1       — recon
intel-v1       — intel-collection
surface-v1     — attack-surface-enumeration
triage-v1      — vulnerability-triage
opsec-v1       — opsec-evasion
pentest-v1     — penetration
privesc-v1     — privilege-escalation
lateral-v1     — lateral-movement
persist-v1     — persistence-maintenance
impact-v1      — impact-exfiltration
cleanup-v1     — cleanup-rollback
report-v1      — reporting-remediation
```

All schemas live in `opensquilla.attack_dispatch.evidence` as Pydantic v2
models. **No field has a fixed size** — subdomain / port / finding / sub-track
counts are unbounded `list[...]`.

## Drill-in: Wn.5a / b / c

| Reason | When | Action |
|---|---|---|
| `a` swap_vector | Parent evidence lacks a vector_class pivot | Re-spawn with a different attack vector (web → API → service) |
| `b` swap_entry | One entry in a class was tried; others weren't | Re-spawn on a sibling entry in the same class |
| `c` expand_scan | Parent missed an expected output bucket | Re-spawn with broader scope |

Trigger: the parent's evidence thinness score (1 − populated_fields / total_fields)
exceeds the executor's threshold (default 0.5). When triggered, all 3 reasons
fire at score ≥ 0.9; only `c` fires at 0.5 ≤ score < 0.9.

## Barrier semantics

Before wave `Wn` can run, every `Wn.deps` wave's evidence must be present
in the blackboard. If a dep is missing, the executor records an error and
does NOT run `Wn` — it does NOT guess. This is the fix for "worker context
gets lost between phases".

## What this skill does NOT do

- It does **not** enumerate subdomains, ports, services, or any other asset.
  All asset counts come from W1 recon's evidence record.
- It does **not** define how to actually attack a target. That's the
  specialist's job (recon, penetration, etc.). This skill only governs
  **when** and **how** the orchestrator calls them.
- It does **not** issue real network requests. The Python executor takes a
  `specialist_fn` callable; in tests, the callable is an in-memory dict
  returner. In production, it wraps `sessions_spawn`.

## Use from a coordinator

Coordinator (e.g. `hack-deep` agent) runs:

```python
from opensquilla.attack_dispatch import DispatchExecutor

def my_specialist(envelope, brief):
    # call sessions_spawn here, parse the returned evidence dict
    return {...}

executor = DispatchExecutor(specialist_fn=my_specialist)
results = executor.run(target="51ifind.com")
```

The executor is sync, deterministic given the specialist function, and
fully testable in isolation. See `tests/test_attack_dispatch/` for examples.

## Out of scope (intentional)

- Persistence / cleanup / impact actions are encoded as data (evidence
  schemas) but NOT executed by this module. Those are the specialist's
  responsibility, gated by the orchestrator's ROE.
- This skill has no opinion on which LLM model runs each specialist.
- This skill does not manage authentication, transport, or web-UI; the
  orchestrator handles that.
