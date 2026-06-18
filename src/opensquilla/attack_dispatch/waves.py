"""Wave DAG: 4 layers × 11 waves, split across 3 LLM owners.

**2026-06-15 refactor**: the 4-layer × 9-wave DAG that previously
drove a single ``hack-deep`` orchestrator is now split across
**3 owner LLMs**. The split enforces a clean separation of concerns
so each LLM has a single responsibility:

================  ==============================================
Owner              Waves it owns
================  ==============================================
hack-deep-find     asset discovery only
                   W0.5 W1 W1.5 W1.5c W2.5 W3.5
hack-deep          attack only
                   W0 W1.6* W2 W3 W4 W4.5*
hack-deep-ex       post-exploitation only
                   W5 W6 W6.5* W7 W8
================  ==============================================

The 3-harness rationale (full version in
``docs/agent_system_3harness.md``):

* **hack-deep-find** is the *only* LLM authorized to drive DNS
  / port / endpoint / fingerprint / web-crawl specialists. It
  consumes a root domain (or an explicit ``find-complete-v1``
  handoff from the main agent) and produces the asset tree.
* **hack-deep** is the *only* LLM authorized to drive ROE
  generation, vulnerability triage, opsec evasion, and
  penetration. It consumes the asset tree (or a directly-passed
  target with an asset map) and produces the
  ``pentest-v1.footholds[]``.
* **hack-deep-ex** is the *only* LLM authorized to drive
  post-exploitation. It consumes the footholds + the typed
  ``post-exploit-complete-v1`` handoff and produces the
  ``privesc-v1`` / ``lateral-v1`` / ``persist-v1`` /
  ``impact-v1`` / ``cleanup-v1`` / ``report-v1`` evidence
  bundle.

Drill-in slots inherit the parent wave's owner (e.g. ``W4.5a``
is owned by hack-deep; ``W6.5a`` is owned by hack-deep-ex).

The DAG itself is unchanged:

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
  W1.6* (hack-deep)         — attack-surface prep drill-in
  W4.5* (hack-deep)         — attack vector expansion drill-in
  W6.5* (hack-deep-ex)      — lateral pivot expansion drill-in
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

# v5 (2026-06-18) DiscoveryStrategy: hack-deep-find 编排器对每个 wave 选用
# 的扇出形状。两个策略明确区分 L0..L3 (全部一起逐层并行) 和 L4+ (单链
# 深度, 避免 context 爆炸):
#
#   BULK_LAYER    L0..L3 (W0.5 / W1): 一次取全层 UNSEEN, 多 batch 并发
#                                  (port-scanner 10 IP / batch 等)。
#                                  同层多 specialist 同时跑, 资源利用率高。
#   CHAIN_FANOUT  L4+  (W1.5 / W1.5c / W2.5 / W3.5): 按 parent chain
#                                  分组, 每条 chain 1 specialist 深度下钻,
#                                  避免 1 个 service 出 1000+ endpoint
#                                  时 specialist context 爆掉。
DiscoveryStrategy = Literal["bulk_layer", "chain_fanout"]


# 2026-06-15 (3-harness split): each wave has a single owner_agent.
# The owner is the LLM orchestrator authorized to drive that wave's
# envelope. The 3-harness split is:
#
#   hack-deep-find  : asset discovery only (W0.5 W1 W1.5 W1.5c W2.5 W3.5)
#   hack-deep       : attack only (W0 ROE + W2 triage + W3 opsec + W4 pentest)
#   hack-deep-ex    : post-exploitation (W5 privesc + W6 lateral + W7 persist+impact + W8 cleanup+report)
#
# W1.6* drill-in slots are owned by hack-deep (operator-driven W2-W4 prep);
# W6.5* drill-in slots are owned by hack-deep-ex. The W4.5* slots are
# owned by hack-deep (W4 is the attack surface, drill-in is attack expansion).
OwnerAgent = Literal["hack-deep-find", "hack-deep", "hack-deep-ex"]
"""
The 3-harness split (2026-06-15) maps each wave to a single owner LLM.

The owner of a wave is the LLM orchestrator authorized to issue the
``sessions_spawn`` for that wave. The Typed Envelope is unchanged
(``agent_id`` is still the *target* specialist, not the *owner*).
The owner is enforced at the registry level via
``subagents.allow_agents`` on each LLM's workspace config (see
``scripts/clone_hack_deep.py`` /
``scripts/clone_hack_deep_ex.py`` /
``scripts/clone_hack_deep_find.py``).

The split rationale is in
``docs/agent_system_3harness.md`` (forthcoming). Short version:

* **hack-deep-find** is the *only* agent that may drive DNS / port /
  endpoint / fingerprint scans. The 6 recon specialists live in its
  allowlist.
* **hack-deep** is the *only* agent that may drive W0 ROE / W2
  triage / W3 opsec / W4 penetration. It produces the
  ``pentest-v1`` evidence with ``footholds[]`` for the next stage.
* **hack-deep-ex** is the *only* agent that may drive W5-W8. It
  consumes ``pentest-v1.footholds[]`` and ``privesc-v1`` /
  ``lateral-v1`` / ``persist-v1`` / ``impact-v1`` / ``cleanup-v1`` /
  ``report-v1``.

The Typed Envelope between the 3 owners is the existing
``find-complete-v1`` (hack-deep-find → hack-deep) plus the new
``post-exploit-complete-v1`` (hack-deep → hack-deep-ex, see
``evidence.py`` for the schema).
"""


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
      owner_agent:    2026-06-15. The LLM orchestrator authorized to drive
                      this wave. One of: "hack-deep-find" / "hack-deep" /
                      "hack-deep-ex". The Typed Envelope is unchanged;
                      owner_agent is enforced at the registry level via
                      subagents.allow_agents on each LLM workspace.
    """

    wave: str
    layer: str
    specialist: str | None
    fanout: FanoutMode
    fanout_agents: tuple[str, ...]
    evidence_schema: str
    deps: tuple[str, ...]
    drill_in_allowed: bool
    owner_agent: OwnerAgent = "hack-deep"
    # v5 (2026-06-18): 本波次允许写入的最深节点 depth (含).
    # 编排器在派发 specialist 之前, 必须确保目标 node 的 path_depth
    # <= max_path_depth, 否则该 specialist 不会入树 (避免越界到 L8+)。
    # 业务硬上限由 asset_tree.models.MAX_TREE_DEPTH (= 8) 提供。
    max_path_depth: int = 8

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
    owner_agent: OwnerAgent = "hack-deep",
    max_path_depth: int = 8,
) -> WaveSpec:
    return WaveSpec(
        wave=wave,
        layer=layer,
        max_path_depth=max_path_depth,
        specialist=specialist,
        fanout=fanout,
        fanout_agents=fanout_agents,
        evidence_schema=evidence_schema,
        deps=deps,
        drill_in_allowed=drill_in_allowed,
        owner_agent=owner_agent,
    )


# Breadth layer ----------------------------------------------------------------
WAVES: dict[str, WaveSpec] = {
    "W0": _w(
        "W0", LayerName.BREADTH.value, "engagement-planning",
        "roe-v1", deps=(),
        owner_agent="hack-deep",
    ),
    "W0.5": _w(
        "W0.5", LayerName.BREADTH.value, None,
        "sub_target_handle-v1",  # v3 name retained; v4 still produces
                                  # SubTargetHandleList on the surface
                                  # even though the 2 v4 specialists
                                  # internally use domain-expansion-v1
                                  # and osint-v1 evidence shapes.
        deps=("W0",),
        fanout="static_fanout",
        # v4 (2026-06-17): W0.5 fanout is now the 2 v4 specialists
        # that own the root_domain tier:
        #   - domain-expander:  in-tree DNS + IP + extra_seeds (was v3's
        #                       3-way split subdomain-discoverer +
        #                       ip-resolver + seed-expander)
        #   - osint-collector:  external-source breadth (Shodan / Censys
        #                       / FOFA / VirusTotal); v3's legacy
        #                       intel-collection promoted to the v4
        #                       specialist contract.
        # Net: -1 specialist in this wave (3 -> 2) with no
        # coverage loss (domain-expander internally does what
        # the v3 trio did; osint-collector covers the Shodan/Censys
        # use case the v3 trio did not).
        fanout_agents=("domain-expander", "osint-collector"),
        drill_in_allowed=False,
        owner_agent="hack-deep-find",
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
        owner_agent="hack-deep-find",
    ),
    "W1": _w(
        "W1", LayerName.BREADTH.value, None,
        "recon-v1",  # base schema; intel-v1 / surface-v1 share bucket
        deps=("W0",),  # 2026-06-10 R3 S24: W0.6 is FAIL-OPEN soft reference
                        # (read state.evidence["W0.6"] if present, but never
                        # block W1 if W0.6 missing or failed)
        fanout="static_fanout",
        # v4 (2026-06-17): W1 fanout is now 3 v4 specialists that
        # own the IP-tier / Port-tier / Service-tier recon:
        #   - port-scanner:         121.52.252.15 -> [21,22,80,443,8001,...]
        #   - service-fingerprint:  1.2.3.4:443 -> [nginx 1.21, kong 3.0, ...]
        #   - endpoint-crawler:     https://host:port -> [/api, /admin, ...]
        # 3 legacy_recon (recon / intel-collection / attack-surface-
        # enumeration) move to FALLBACK_AGENTS for v3 3-tier fallback
        # when v4 specialists are unavailable. See SOUL_BODY.md
        # "自适应执行 (v3, 2026-06-17)".
        fanout_agents=("port-scanner", "service-fingerprint", "endpoint-crawler"),
        drill_in_allowed=True,
        owner_agent="hack-deep-find",
    ),
    "W1.5": _w(
        "W1.5", LayerName.BREADTH.value, "recon",
        "recon-v1",  # NEW: dynamic fanout by subdomain count
        deps=("W0.5",),
        fanout="dynamic_fanout",
        drill_in_allowed=False,  # feedback loop is at orchestrator level, not drill-in
        owner_agent="hack-deep-find",
    ),
    "W1.5c": _w(
        "W1.5c", LayerName.BREADTH.value, "recon",
        "recon-v1",  # NEW 2026-06-10: conditional expand scan triggered when
                     # W1 evidence lacks port_scan_complete or dir_bust_evidence.
                     # Specialist re-runs naabu/nmap for missing ports and
                     # ffuf/feroxbuster/gobuster for missing paths. Single
                     # specialist (recon) — not a fanout — because the work is
                     # bounded to the same target, just deeper.
                     #
                     # 2026-06-16 v2 protocol note: W1.5c is a REGISTERED
                     # sub-wave that find EXECUTES itself in its F1.5c step
                     # (see agents/hack-deep-find/SOUL_BODY.md). It is NOT
                     # the same as W1.6c drill-in (which is declared via
                     # drill-in-request-v1 and executed by hack-deep). The
                     # two live in different namespaces by design:
                     #   W1.5c = ".5c" suffix = registered sub-wave, find-executed
                     #   W1.6c = ".6c" suffix = drill-in slot, deep-executed
        deps=("W1",),
        fanout="single",
        drill_in_allowed=False,
        owner_agent="hack-deep-find",
    ),
    "W2": _w(
        "W2", LayerName.BREADTH.value, "vulnerability-triage",
        "triage-v1",
        deps=("W1",),  # W2 reads W1's asset map; W3 opsec gates W4, not W2
        owner_agent="hack-deep",
    ),
    "W2.5": _w(
        "W2.5", LayerName.BREADTH.value, "vulnerability-triage",
        "port-attack-plan-v1",  # NEW 2026-06-11 (v4.0 R3): per-port + vector
                                # 拆端口攻击计划。读 ReconEvidence.services,
                                # bucket=6,每个 sub-track 处理 ~6 个端口;
                                # 输出 AttackVectorPlan 列表,供 W4 拆 sub-track。
                                # 若 services 为空,fail-fast 跳到 W3。
                                #
                                # 2026-06-16 v2 cross-owner dispatch:
                                # owner_agent stays "hack-deep-find" (the
                                # planning logic is find-side) but the
                                # specialist vulnerability-triage lives in
                                # hack-deep's allow_agents. find does NOT
                                # sessions_spawn(vulnerability-triage, ...)
                                # directly — it emits a w2.5-dispatch-v1
                                # evidence and spawns hack-deep, which
                                # relays to vulnerability-triage sub-tracks.
                                # See agents/hack-deep-find/SOUL_BODY.md
                                # Step F2.5 and agents/hack-deep/SOUL_BODY.md
                                # "W2.5 Cross-Owner Dispatch Handling".
        deps=("W2", "W1.5c"),
        fanout="dynamic_fanout",
        drill_in_allowed=False,
        owner_agent="hack-deep-find",  # 2026-06-15: per-port planning is recon-side
    ),
    # Covert layer -------------------------------------------------------------
    "W3": _w(
        "W3", LayerName.COVERT.value, "opsec-evasion",
        "opsec-v1",
        deps=("W2.5",),
        owner_agent="hack-deep",
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
        owner_agent="hack-deep-find",  # 2026-06-15: web crawl is recon-side
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
        owner_agent="hack-deep",
    ),
    "W5": _w(
        "W5", LayerName.DEPTH.value, "privilege-escalation",
        "privesc-v1",
        deps=("W4",),
        owner_agent="hack-deep-ex",
    ),
    "W6": _w(
        "W6", LayerName.DEPTH.value, "lateral-movement",
        "lateral-v1",
        deps=("W5",),
        drill_in_allowed=True,
        owner_agent="hack-deep-ex",
    ),
    "W7": _w(
        "W7", LayerName.DEPTH.value, None,
        "persist-v1",  # also produces impact-v1 in parallel fan-out
        deps=("W6",),
        fanout="static_fanout",
        fanout_agents=("persistence-maintenance", "impact-exfiltration"),
        owner_agent="hack-deep-ex",
    ),
    # Synthesis layer ---------------------------------------------------------
    "W8": _w(
        "W8", LayerName.SYNTHESIS.value, None,
        "cleanup-v1",  # also produces report-v1
        deps=("W7",),
        fanout="static_fanout",
        fanout_agents=("cleanup-rollback", "reporting-remediation"),
        owner_agent="hack-deep-ex",
    ),
}


WAVE_NAMES: tuple[str, ...] = tuple(WAVES.keys())


# Drill-in slot table — drill-ins are *not* pre-registered waves; they are
# *opened* in response to thin evidence in a parent wave. We expose the table
# of allowed drill-in slot names so the orchestrator can validate.
DRILL_IN_SLOTS: dict[str, tuple[str, ...]] = {
    # parent wave -> allowed drill-in names (canonical order: a, b, c).
    #
    # Naming convention (2026-06-10):
    #   - The numeric suffix ``.5`` is reserved for **registered sub-waves**
    #     (W0.5 / W1.5 / W1.5c / W2.5 / W3.5 / W4.5 / W6.5 ...).
    #   - Drill-in slots of a parent P use the suffix ``.(P+1).N`` so they
    #     stay distinguishable from registered sub-waves.
    #
    # Concretely: W1's drill-in slots are W1.6a/b/c (NOT W1.5a/b/c)
    # because W1.5 is a registered wave (per-subdomain fan-out). The
    # W1.5c entry further reserves the suffix .5c for the W1 follow-up
    # expand scan, leaving no room for W1.5a / W1.5b drill-ins.
    #
    # 3-harness split (2026-06-15) and v2 cross-owner protocol (2026-06-16):
    #   Each drill-in inherits its parent wave's ``owner_agent`` at the
    #   code layer. At the protocol layer, the actual spawn may be
    #   RELAYED across owners via the cross-owner evidence schemas
    #   (``w2.5-dispatch-v1`` / ``drill-in-request-v1`` in
    #   ``attack_dispatch.evidence``). The table below lists the
    #   code-layer owner; the protocol-layer actor is documented in
    #   the relevant SOUL_BODY.md.
    #
    #   W1.6* (W1 attack-surface prep)        -> code: hack-deep-find
    #                                            protocol: hack-deep (relay
    #                                            from drill-in-request-v1)
    #   W4.5* (W4 attack vector expansion)    -> hack-deep
    #   W6.5* (W6 lateral pivot expansion)     -> hack-deep-ex
    #
    #   W1.5c distinction: W1.5c is a registered sub-wave (not a drill-in)
    #   that find EXECUTES itself in its F1.5c step. W1.6c is a drill-in
    #   slot that find DECLARES (via drill-in-request-v1) for hack-deep
    #   to execute later. The two have different owners at the protocol
    #   layer; this table only governs the code layer.
    "W1": ("W1.6a", "W1.6b", "W1.6c"),
    "W4": ("W4.5a", "W4.5b", "W4.5c"),
    "W6": ("W6.5a", "W6.5b", "W6.5c"),
}


class UnauthorizedOwnerError(Exception):
    """Raised when sessions_spawn is called from the wrong owner LLM.

    3-harness split (2026-06-15): the LLM that drives a wave must
    match the wave's owner_agent. For example, hack-deep-find cannot
    drive W5 (privilege-escalation); only hack-deep-ex can. This
    check is enforced at the executor / envelope-parse layer; the
    LLM is expected to follow the contract but the runtime is
    defense-in-depth.
    """

    def __init__(self, wave: str, calling_agent: str, expected_owner: str) -> None:
        self.wave = wave
        self.calling_agent = calling_agent
        self.expected_owner = expected_owner
        super().__init__(
            f"wave {wave!r} is owned by {expected_owner!r} but "
            f"caller is {calling_agent!r}; the 3-harness split "
            f"(hack-deep-find / hack-deep / hack-deep-ex) prohibits "
            f"this call. See attack_dispatch/waves.py:OwnerAgent."
        )


def owner_of_wave(wave: str) -> OwnerAgent:
    """Return the owner_agent for a wave or drill-in slot name.

    Drill-in slots (e.g. ``W4.5a``) inherit their parent wave's
    owner (W4.5a -> W4 -> hack-deep). Unknown waves raise
    KeyError (caller is expected to validate the wave name first).
    """
    if wave in WAVES:
        return WAVES[wave].owner_agent
    # Drill-in: strip the suffix (W4.5a -> W4, W1.6b -> W1)
    for parent in DRILL_IN_SLOTS:
        if wave in DRILL_IN_SLOTS[parent]:
            return WAVES[parent].owner_agent
    raise KeyError(f"wave {wave!r} is not a registered wave or drill-in slot")


def check_authorization(wave: str, calling_agent: str) -> None:
    """Raise UnauthorizedOwnerError if calling_agent can't drive wave.

    The 3-harness split (2026-06-15) assigns each wave to exactly
    one of the 3 LLM owners:

      hack-deep-find : asset discovery (W0.5 W1 W1.5 W1.5c W2.5 W3.5)
      hack-deep      : attack         (W0 W1.6* W2 W3 W4 W4.5*)
      hack-deep-ex   : post-exploit   (W5 W6 W6.5* W7 W8)

    This function is called by the executor's
    ``_resolve_dispatch`` (or the gateway's session spawn handler)
    BEFORE issuing the specialist call. The check is one-line and
    O(1) (just a dict lookup).
    """
    expected = owner_of_wave(wave)
    if calling_agent != expected:
        raise UnauthorizedOwnerError(wave, calling_agent, expected)


def is_drill_in_allowed(parent_wave: str) -> bool:
    """True iff a drill-in slot is allowed for the given parent wave."""
    return parent_wave in DRILL_IN_SLOTS


def list_drill_in_slots(parent_wave: str) -> tuple[str, ...]:
    """All allowed drill-in slot names for a parent wave, or empty tuple."""
    return DRILL_IN_SLOTS.get(parent_wave, ())


# v5 (2026-06-18): 每波次允许写出的最深节点 path_depth。
# - W0.5 / W1   (Tier 1 网络层):   写 SUB_DOMAIN / IP / PORT / SERVICE  → L1..L3
# - W1.5       (Tier 1 fan-out):  继承 W1 max_path_depth
# - W1.5c      (URL/endpoint):    写到 URL/ENDPOINT/PARAMETER          → L4..L6
# - W2.5       (Tier 2 web):      写到 L5..L7                            → L5..L7
# - W3.5       (Tier 3 横向):     SECRET (跨层), 不增加主链 depth      → L0..L7
# - W4         (攻击面, hack-deep) 不写资产树, 只是消费 → 不限
# - W4.5* / W6.5*  drill-in:       继承父波次 max_path_depth
WAVE_MAX_PATH_DEPTH: dict[str, int] = {
    # 值是 path_depth 索引 (节点 depth ∈ [0, 8])。
    # 与 workflow 文档严格一致:
    #   W0.5   = 2 (L2 IP, 网络起点)
    #   W1     = 4 (L4 SERVICE, 不写 URL — URL 由 W1.5 webapp-discoverer 派生)
    #   W1.5   = 5 (L5 URL, 派生 endpoint 留给 W1.5c)
    #   W1.5c  = 7 (L7 PARAMETER, 闭环 url→endpoint→parameter)
    #   W2.5   = 8 (L8 INJECTION_VECTOR, 业务最深, 跨 owner dispatch)
    #   W3.5   = 6 (L6 ENDPOINT, 派生 STATIC_ASSET/COOKIE/HEADER/SECRET 等 L5 跨层)
    #   W4     = 8 (攻击面读取, 不写)
    "W0.5": 2,    # ROOT(0) → SUB(1) → IP(2)
    "W1": 4,      # PORT(3)/SERVICE(4)
    "W1.5": 5,    # URL(5) — 派生 url_candidates, 跨 sub_domain 拿 storage
    "W1.5c": 7,   # url(5)/endpoint(6)/parameter(7) 都在 W1.5c 闭环
    "W2.5": 8,    # injection_vector(8) 跨 owner dispatch
    "W3.5": 6,    # endpoint(6) 派生 STATIC_ASSET/COOKIE/HEADER/SECRET (跨层挂载)
    "W4": 8,      # 攻击面读取, 不写
}

# v5 (2026-06-18) 探测策略映射 — hack-deep-find 编排器按 wave 选用扇出形状。
# 硬约束: L0..L3 (path_depth 0..3) 全部一起逐层并行 = bulk_layer;
#        L4+   (path_depth 4..8) 单链深度探测 = chain_fanout。
DISCOVERY_STRATEGY_MAP: dict[str, DiscoveryStrategy] = {
    # L0..L3 bulk_layer
    "W0.5": "bulk_layer",   # root -> sub -> ip (横向 + 网络层全量)
    "W0.6": "bulk_layer",   # resource-checkpoint, 静态 fanout, 不写资产树
    "W1": "bulk_layer",     # ip -> port -> service (网络层全量逐层)
    # L4+ chain_fanout
    "W1.5": "chain_fanout",  # service / url / sub_domain -> web / 组件 / 存储
    "W1.5c": "chain_fanout", # url -> endpoint / parameter (per-url 链)
    "W2.5": "chain_fanout",  # endpoint -> injection_vector (per-port 链)
    "W3.5": "chain_fanout",  # url / endpoint / component -> secret / cookie / header
    "W4": "chain_fanout",    # 攻击面读取, 沿用 chain_fanout 形状
}


def strategy_of_wave(wave: str) -> DiscoveryStrategy:
    """Return the discovery strategy for a wave. Falls back to chain_fanout."""
    if wave in DISCOVERY_STRATEGY_MAP:
        return DISCOVERY_STRATEGY_MAP[wave]
    for parent, slots in DRILL_IN_SLOTS.items():
        if wave in slots:
            return strategy_of_wave(parent)
    return "chain_fanout"


def is_bulk_layer_wave(wave: str) -> bool:
    """True iff the wave uses bulk_layer (L0..L3, all-together)."""
    return strategy_of_wave(wave) == "bulk_layer"


def is_chain_fanout_wave(wave: str) -> bool:
    """True iff the wave uses chain_fanout (L4+, per-chain depth)."""
    return strategy_of_wave(wave) == "chain_fanout"


def wave_owns_depth(wave: str, target_depth: int) -> bool:

    """判断某 wave 是否"拥有"指定 depth 的写入权。

    v5 (2026-06-18): 编排器在派发 specialist 之前, 必须用此函数判断
    目标 node 的 path_depth 是否在 wave 允许范围内。如果不在, 跳过
    该 node (或者下放到下一个 wave), 避免写入 L8+ 越界节点。

    Lookup 顺序:
      1) WAVE_MAX_PATH_DEPTH 显式表 (覆盖大多数)
      2) WaveSpec.max_path_depth (注册波次自带字段, 兜底)
      3) 未知 wave / drill-in slot: 沿父波次上溯
      4) 全部失败: 拒绝 (保守拒绝, 等于 MAX_TREE_DEPTH 8 也允许)
    """
    if wave in WAVE_MAX_PATH_DEPTH:
        return target_depth <= WAVE_MAX_PATH_DEPTH[wave]
    try:
        spec = get_wave(wave)
    except KeyError:
        spec = None
    if spec is not None:
        return target_depth <= spec.max_path_depth
    # drill-in slot: 沿父波次上溯 (W1.6a -> W1 -> 4; W4.5a -> W4 -> 7)
    for parent, slots in DRILL_IN_SLOTS.items():
        if wave in slots:
            return wave_owns_depth(parent, target_depth)
    # 兜底: 业务硬上限 (新节点 depth <= 8)
    from opensquilla.asset_tree.models import MAX_TREE_DEPTH
    return target_depth <= MAX_TREE_DEPTH


def get_wave(wave: str) -> WaveSpec:
    """Look up a wave by id; raise KeyError if not registered.

    Note: drill-in names like ``W1.5a`` are NOT in ``WAVES``; they are
    constructed on demand by the orchestrator. This function only returns
    parent waves and pre-registered sub-waves.
    """
    if wave not in WAVES:
        raise KeyError(f"wave {wave!r} not registered (drill-ins must be constructed)")
    return WAVES[wave]
