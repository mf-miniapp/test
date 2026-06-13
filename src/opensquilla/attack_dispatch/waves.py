"""Wave DAG: 4 layers × 11 waves (W0..W8 + W0.5 target-expansion + W1.5 per-subdomain).

Replaces the broken 7-phase checklist with a real DAG:

  广度层 (Breadth):  W0   engagement-planning
                    W0.5 target-expansion           (NEW: subdomain enumeration, static fanout)
                    W1   recon ‖ intel-collection ‖ attack-surface-enumeration  (main domain)
                    W1.5 per-subdomain fan-out      (NEW: dynamic fanout by subdomain count)
                    W2   vulnerability-triage
  隐蔽层 (Covert):  W3 opsec-evasion  (allows 2 in-wave sub-calls, no new wave name)
  深度层 (Depth):   W4 penetration  (fan-out = entry_count // 8, dynamic)
                    W5 privilege-escalation
                    W6 lateral-movement
                    W7 persistence-maintenance ‖ impact-exfiltration
  收口层 (Synthesis): W8 cleanup-rollback ‖ reporting-remediation

Drill-in slots (only in Breadth + Depth):
  W1.5 广度层侦察补探
  W4.5 深度层入口补攻
  W6.5 深度层横向补探
  Each with reasons a (swap vector) / b (swap entry) / c (expand scan)

Feedback loop (NEW 2026-06-07):
  Drill-in reason class d=EMIT_NEW_TARGET — when W4/W5/W6 raw output contains
  ``emit_new_target: list[str]``, the executor pushes those targets back to
  ``state.target_queue`` and W1.5 (or a W1.5b incremental pass) consumes them.

This module exposes the DAG as a frozen registry, not a flowchart.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


# ---------------------------------------------------------------------------
# Layer / wave enums
# ---------------------------------------------------------------------------


class LayerName(str, Enum):
    BREADTH = "广度层"
    COVERT = "隐蔽层"
    DEPTH = "深度层"
    SYNTHESIS = "收口层"


LAYER_NAMES: tuple[str, ...] = tuple(m.value for m in LayerName)

LAYERS: dict[str, tuple[str, ...]] = {
    LayerName.BREADTH.value: ("W0", "W0.5", "W0.6", "W1", "W1.5", "W1.5c", "W2", "W2.5", "W3", "W3.5"),
    LayerName.COVERT.value: (),
    LayerName.DEPTH.value: ("W4", "W5", "W6", "W7"),
    LayerName.SYNTHESIS.value: ("W8",),
}


# ---------------------------------------------------------------------------
# WaveSpec
# ---------------------------------------------------------------------------


FanoutMode = Literal["single", "static_fanout", "dynamic_fanout"]


@dataclass(frozen=True)
class WaveSpec:
    """One wave in the DAG.

    Fields:
      wave:           the wave id, e.g. "W0" or "W1.5" or "W4.5a"
      layer:          which of the 4 layers
      specialist:     the agent_id of the specialist (None for fan-out waves
                      whose specialist is determined at run time)
      fanout:         "single" (one call), "static_fanout" (fixed list), or
                      "dynamic_fanout" (computed from upstream evidence count)
      fanout_agents:  for static_fanout, the fixed list of agents
      evidence_schema: the schema name specialists must produce
      deps:           list of wave ids whose evidence must be present
      drill_in_allowed: True iff this wave can spawn a `.5*` drill-in
    """

    wave: str
    layer: str
    specialist: str | None
    fanout: FanoutMode
    fanout_agents: tuple[str, ...]
    evidence_schema: str
    deps: tuple[str, ...]
    drill_in_allowed: bool

    def is_drill_in(self) -> bool:
        return ".5" in self.wave


# ---------------------------------------------------------------------------
# 9-wave registry
# ---------------------------------------------------------------------------


def _w(
    wave: str,
    layer: str,
    specialist: str | None,
    evidence_schema: str,
    deps: tuple[str, ...] = (),
    fanout: FanoutMode = "single",
    fanout_agents: tuple[str, ...] = (),
    drill_in_allowed: bool = False,
) -> WaveSpec:
    return WaveSpec(
        wave=wave,
        layer=layer,
        specialist=specialist,
        fanout=fanout,
        fanout_agents=fanout_agents,
        evidence_schema=evidence_schema,
        deps=deps,
        drill_in_allowed=drill_in_allowed,
    )


# Breadth layer ----------------------------------------------------------------
WAVES: dict[str, WaveSpec] = {
    "W0": _w(
        "W0", LayerName.BREADTH.value, "engagement-planning",
        "roe-v1", deps=(),
    ),
    "W0.5": _w(
        "W0.5", LayerName.BREADTH.value, None,
        "sub_target_handle-v1",  # NEW: produces list of SubTargetHandle
        deps=("W0",),
        fanout="static_fanout",
        fanout_agents=("recon", "intel-collection", "attack-surface-enumeration"),
        drill_in_allowed=False,
    ),
    "W0.6": _w(
        "W0.6", LayerName.BREADTH.value, None,
        "resource-v1",  # NEW 2026-06-10 (R3 P0 S24): W0.6 resource-checkpoint
                         # static fanout of 3 specialists (recon / penetration /
                         # engagement-planning) each enumerating their own
                         # ~/.opensquilla/{skills, wordlists, payloads} dir
                         # and which bins. Fail-open: missing items produce
                         # warnings + missing entries, but the wave itself
                         # never blocks downstream waves.
        deps=("W0",),
        fanout="static_fanout",
        fanout_agents=("recon", "penetration", "engagement-planning"),
        drill_in_allowed=False,
    ),
    "W1": _w(
        "W1", LayerName.BREADTH.value, None,
        "recon-v1",  # base schema; intel-v1 / surface-v1 share bucket
        deps=("W0",),  # 2026-06-10 R3 S24: W0.6 is FAIL-OPEN soft reference
                        # (read state.evidence["W0.6"] if present, but never
                        # block W1 if W0.6 missing or failed)
        fanout="static_fanout",
        fanout_agents=("recon", "intel-collection", "attack-surface-enumeration"),
        drill_in_allowed=True,
    ),
    "W1.5": _w(
        "W1.5", LayerName.BREADTH.value, "recon",
        "recon-v1",  # NEW: dynamic fanout by subdomain count
        deps=("W0.5",),
        fanout="dynamic_fanout",
        drill_in_allowed=False,  # feedback loop is at orchestrator level, not drill-in
    ),
    "W1.5c": _w(
        "W1.5c", LayerName.BREADTH.value, "recon",
        "recon-v1",  # NEW 2026-06-10: conditional expand scan triggered when
                     # W1 evidence lacks port_scan_complete or dir_bust_evidence.
                     # Specialist re-runs naabu/nmap for missing ports and
                     # ffuf/feroxbuster/gobuster for missing paths. Single
                     # specialist (recon) — not a fanout — because the work is
                     # bounded to the same target, just deeper.
        deps=("W1",),
        fanout="single",
        drill_in_allowed=False,
    ),
    "W2": _w(
        "W2", LayerName.BREADTH.value, "vulnerability-triage",
        "triage-v1",
        deps=("W1",),  # W2 reads W1's asset map; W3 opsec gates W4, not W2
    ),
    "W2.5": _w(
        "W2.5", LayerName.BREADTH.value, "vulnerability-triage",
        "port-attack-plan-v1",  # NEW 2026-06-11 (v4.0 R3): per-port + vector
                                # 拆端口攻击计划。读 ReconEvidence.services,
                                # bucket=6,每个 sub-track 处理 ~6 个端口;
                                # 输出 AttackVectorPlan 列表,供 W4 拆 sub-track。
                                # 若 services 为空,fail-fast 跳到 W3。
        deps=("W2", "W1.5c"),
        fanout="dynamic_fanout",
        drill_in_allowed=False,
    ),
    # Covert layer -------------------------------------------------------------
    "W3": _w(
        "W3", LayerName.COVERT.value, "opsec-evasion",
        "opsec-v1",
        deps=("W2.5",),
    ),
    "W3.5": _w(
        "W3.5", LayerName.BREADTH.value, "recon",
        "web-crawl-v1",  # NEW 2026-06-11 (v4.0 R4): 全 web service 端口
                         # 并发爬虫 (katana + waybackurls + subjs + jsluice)。
                         # bucket=4,每个 sub-track 处理 ~4 个 web 端口。
                         # 产出 CrawlEvidence (urls / js_files / hidden_paths /
                         # extracted_endpoints / auth_required_paths)。
                         # 若无 web service,fail-fast 跳到 W4。
        deps=("W3",),
        fanout="dynamic_fanout",
        drill_in_allowed=False,
    ),
    # Depth layer --------------------------------------------------------------
    "W4": _w(
        "W4", LayerName.DEPTH.value, "penetration",
        "pentest-v1",
        deps=("W2", "W3"),  # 2026-06-10 R3 S24: W0.6 is FAIL-OPEN soft reference
                              # (read state.evidence["W0.6"] if present, but never
                              # block W4 if W0.6 missing or failed)
        fanout="dynamic_fanout",  # count = entry_count // 8
        drill_in_allowed=True,
    ),
    "W5": _w(
        "W5", LayerName.DEPTH.value, "privilege-escalation",
        "privesc-v1",
        deps=("W4",),
    ),
    "W6": _w(
        "W6", LayerName.DEPTH.value, "lateral-movement",
        "lateral-v1",
        deps=("W5",),
        drill_in_allowed=True,
    ),
    "W7": _w(
        "W7", LayerName.DEPTH.value, None,
        "persist-v1",  # also produces impact-v1 in parallel fan-out
        deps=("W6",),
        fanout="static_fanout",
        fanout_agents=("persistence-maintenance", "impact-exfiltration"),
    ),
    # Synthesis layer ---------------------------------------------------------
    "W8": _w(
        "W8", LayerName.SYNTHESIS.value, None,
        "cleanup-v1",  # also produces report-v1
        deps=("W7",),
        fanout="static_fanout",
        fanout_agents=("cleanup-rollback", "reporting-remediation"),
    ),
}


WAVE_NAMES: tuple[str, ...] = tuple(WAVES.keys())


# Drill-in slot table — drill-ins are *not* pre-registered waves; they are
# *opened* in response to thin evidence in a parent wave. We expose the table
# of allowed drill-in slot names so the orchestrator can validate.
DRILL_IN_SLOTS: dict[str, tuple[str, ...]] = {
    # parent wave -> allowed drill-in names (canonical order: a, b, c).
    # W1's drill-in slots are intentionally W1.6a/b/c (not W1.5a/b/c) because
    # W1.5 is now a registered wave (per-subdomain fan-out). The numeric
    # suffix .5 is reserved for registered sub-waves; drill-in slots of a
    # parent P use suffix .(P+1).N to stay distinguishable.
    "W1": ("W1.6a", "W1.6b", "W1.6c"),
    "W4": ("W4.5a", "W4.5b", "W4.5c"),
    "W6": ("W6.5a", "W6.5b", "W6.5c"),
}


def is_drill_in_allowed(parent_wave: str) -> bool:
    """True iff a drill-in slot is allowed for the given parent wave."""
    return parent_wave in DRILL_IN_SLOTS


def list_drill_in_slots(parent_wave: str) -> tuple[str, ...]:
    """All allowed drill-in slot names for a parent wave, or empty tuple."""
    return DRILL_IN_SLOTS.get(parent_wave, ())


def get_wave(wave: str) -> WaveSpec:
    """Look up a wave by id; raise KeyError if not registered.

    Note: drill-in names like ``W1.5a`` are NOT in ``WAVES``; they are
    constructed on demand by the orchestrator. This function only returns
    parent waves and pre-registered sub-waves.
    """
    if wave not in WAVES:
        raise KeyError(f"wave {wave!r} not registered (drill-ins must be constructed)")
    return WAVES[wave]
