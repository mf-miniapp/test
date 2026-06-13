"""Drill-in trigger logic.

A drill-in is **NOT** a pre-registered wave — it is a re-spawn of the parent
wave with a tighter scope, decided at run time when the parent's evidence is
thin. There are 4 reason classes (2026-06-07 added ``emit_new_target``):

  swap_vector    — change attack vector class          (web → API → service)
  swap_entry     — try a different entry_id in the same class
  expand_scan    — re-spawn with broader scope (parent missed something)
  emit_new_target — specialist on the parent discovered new targets
                    (subdomains / hidden services / pivots) that the
                    executor pushes back to ``state.target_queue`` for
                    a re-run of W1.5 (or W1 incremental).

Drill-in slots are only allowed for the parent waves whose spec carries
``drill_in_allowed=True`` (currently W1, W4, W6 — Breadth + Depth layers).

The trigger decision is **deterministic** given the parent's evidence record
and a thinness threshold. This module exposes the decision function; the
executor calls it after every parent wave.

The 4 reason classes are identified by their **class name** (not single
letters like "a"/"b"/"c"). This is the 2026-06-07 refactor: ``a/b/c`` were
ambiguous once ``emit_new_target`` joined, and class names read more clearly
in audit logs / transcript messages.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from opensquilla.attack_dispatch.evidence import EvidenceBase
from opensquilla.attack_dispatch.waves import (
    DRILL_IN_SLOTS,
    WaveSpec,
    get_wave,
)


class DrillInReason(str, Enum):
    """The 4 reason classes for any drill-in. fix 4 + 2026-06-07 extension."""

    SWAP_VECTOR = "swap_vector"
    SWAP_ENTRY = "swap_entry"
    EXPAND_SCAN = "expand_scan"
    EMIT_NEW_TARGET = "emit_new_target"


DRILL_IN_REASONS: tuple[str, ...] = tuple(r.value for r in DrillInReason)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DrillInSpec:
    """A single drill-in instruction produced by the decision function.

    Fields:
      slot:          the full slot name. For thinness-triggered drill-ins
                     this is one of the parent wave's DRILL_IN_SLOTS entries
                     (e.g. ``"W1.6a"``). For emit_new_target it's
                     ``f"{parent_wave}.emit"``.
      parent_wave:   the wave that produced thin evidence, e.g. ``"W4"``
      reason:        class name (e.g. ``"swap_vector"``) — same as
                     ``reason_class``; kept on the dataclass for ergonomics
      reason_class:  same as ``reason``; explicit for audit logs
      target_agent:  which specialist to re-spawn
      reason_detail: string the orchestrator should pass as brief context
    """

    slot: str
    parent_wave: str
    reason: str
    reason_class: str
    target_agent: str
    reason_detail: str

    def render(self) -> str:
        return (
            f"{self.slot} (parent={self.parent_wave}, "
            f"reason={self.reason}, "
            f"agent={self.target_agent})"
        )


@dataclass(frozen=True)
class DrillInDecision:
    """The orchestrator's call after a parent wave.

    ``specs`` may be empty (no drill-in needed); it never has more than 3
    elements from the thinness-driven reason classes. ``emit_new_target``
    specs are added separately by the executor (see
    :func:`build_emit_new_target_spec`) and are recorded under a different
    mechanism (state.target_queue, not this tuple).
    """

    parent_wave: str
    thinness_score: float        # 0.0 = rich evidence, 1.0 = totally thin
    specs: tuple[DrillInSpec, ...]

    @property
    def triggered(self) -> bool:
        return bool(self.specs)


# ---------------------------------------------------------------------------
# Thinness scoring
# ---------------------------------------------------------------------------


# A "thinness threshold" — anything above this triggers at least one drill-in.
# Tunable by the executor; default is 0.5 (half-empty).
DEFAULT_THINNESS_THRESHOLD = 0.5


def _score_thinness(parent: WaveSpec, evidence: EvidenceBase) -> float:
    """Compute a thinness score in [0, 1] for the parent's evidence.

    The score is the *complement* of how much of the parent's expected output
    is present. We don't try to be clever — we just count the number of
    populated list / dict fields and divide by the number of list / dict
    fields the schema declares.

    A score of 0.0 means "fully populated" (no drill-in needed).
    A score of 1.0 means "completely empty" (max drill-in eagerness).
    """
    # Collect all list/dict-typed fields on the evidence model
    populated = 0
    total = 0
    # Use the class's model_fields, not the instance's
    # (instance access is deprecated in Pydantic v2.11+).
    for name, field in type(evidence).model_fields.items():
        # Heuristic: list / dict / model fields count as "outputs".
        annotation = str(field.annotation)
        is_collectable = (
            annotation.startswith("list[")
            or annotation.startswith("dict[")
            or annotation.startswith("Optional[list[")
            or annotation.startswith("Optional[dict[")
        )
        if not is_collectable:
            continue
        total += 1
        value = getattr(evidence, name, None)
        if value:  # truthy → non-empty
            populated += 1
    if total == 0:
        return 0.0
    return 1.0 - (populated / total)


# ---------------------------------------------------------------------------
# Spec construction
# ---------------------------------------------------------------------------


def _build_specs(
    parent_wave: str,
    reason_classes: tuple[str, ...],
    parent: WaveSpec,
    evidence: EvidenceBase,
) -> tuple[DrillInSpec, ...]:
    """Materialize one DrillInSpec per requested reason class.

    The target agent is taken from the parent's ``fanout_agents`` (for
    static_fanout parents) or the parent's ``specialist`` (for single /
    dynamic_fanout). If neither is set, the spec still has a name but
    ``target_agent=""`` and the executor must resolve it from upstream context.
    """
    if parent.fanout == "static_fanout":
        candidates = parent.fanout_agents
    elif parent.specialist:
        candidates = (parent.specialist,)
    else:
        candidates = ()

    reason_class_map: dict[str, tuple[str, str]] = {
        DrillInReason.SWAP_VECTOR.value: (
            "swap_vector",
            f"parent {parent_wave} evidence lacks a vector_class pivot; re-spawn with a different attack vector",
        ),
        DrillInReason.SWAP_ENTRY.value: (
            "swap_entry",
            f"parent {parent_wave} found one entry but other entries in the same vector_class were not tried; re-spawn on a sibling entry",
        ),
        DrillInReason.EXPAND_SCAN.value: (
            "expand_scan",
            f"parent {parent_wave} missed at least one expected output bucket; re-spawn with broader scope",
        ),
        # EMIT_NEW_TARGET is intentionally not in this map; it is built
        # by :func:`build_emit_new_target_spec` from raw output, not from
        # the thinness score.
    }

    out: list[DrillInSpec] = []
    # The slot *name* comes from DRILL_IN_SLOTS, indexed by the canonical
    # order swap_vector / swap_entry / expand_scan.
    slot_names = list(DRILL_IN_SLOTS.get(parent_wave, ()))
    reason_order: tuple[str, ...] = (
        DrillInReason.SWAP_VECTOR.value,
        DrillInReason.SWAP_ENTRY.value,
        DrillInReason.EXPAND_SCAN.value,
    )
    reason_to_index: dict[str, int] = {r: i for i, r in enumerate(reason_order)}

    for reason in reason_classes:
        target = candidates[0] if candidates else ""
        cls, detail = reason_class_map[reason]
        idx = reason_to_index[reason]
        slot = slot_names[idx] if idx < len(slot_names) else f"{parent_wave}.5{reason}"
        out.append(
            DrillInSpec(
                slot=slot,
                parent_wave=parent_wave,
                reason=reason,
                reason_class=cls,
                target_agent=target,
                reason_detail=detail,
            )
        )
    return tuple(out)


def build_emit_new_target_spec(
    parent_wave: str,
    new_targets: list[str],
    target_agent: str = "recon",
) -> DrillInSpec:
    """Construct a drill-in spec for the ``emit_new_target`` reason class.

    This is called by the executor (see ``executor._scan_emit_new_target``)
    when W4/W5/W6 raw output contains ``emit_new_target: list[str]``. The
    spec is recorded in ``state.drill_ins`` for audit, and the new targets
    are pushed to ``state.target_queue`` so the orchestrator (LLM) can
    decide to re-spawn W1.5 / W1 on them.

    Raises:
      ValueError: if parent_wave has no drill-in slot.
    """
    if parent_wave not in DRILL_IN_SLOTS:
        raise ValueError(
            f"parent_wave {parent_wave!r} has no drill-in slot; "
            f"allowed: {sorted(DRILL_IN_SLOTS)}"
        )
    if not new_targets:
        raise ValueError("new_targets must be a non-empty list")
    target_summary = ", ".join(new_targets[:5])
    if len(new_targets) > 5:
        target_summary += f" ... (+{len(new_targets) - 5} more)"
    return DrillInSpec(
        slot=f"{parent_wave}.emit",
        parent_wave=parent_wave,
        reason=DrillInReason.EMIT_NEW_TARGET.value,
        reason_class=DrillInReason.EMIT_NEW_TARGET.value,
        target_agent=target_agent,
        reason_detail=(
            f"specialist on {parent_wave} discovered {len(new_targets)} "
            f"new target(s): {target_summary}"
        ),
    )


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def decide_drill_in(
    parent_wave: str,
    evidence: EvidenceBase,
    *,
    threshold: float = DEFAULT_THINNESS_THRESHOLD,
) -> DrillInDecision:
    """Decide whether and how to drill into a parent wave (thinness-driven).

    This is the thinness-driven decision. It may produce 0..3 specs from
    the swap_vector / swap_entry / expand_scan reason classes. The
    ``emit_new_target`` class is generated separately from raw output
    (see :func:`build_emit_new_target_spec`) and never by this function.

    Args:
      parent_wave:  e.g. "W4"
      evidence:     the parent's evidence record (used to compute thinness)
      threshold:    thinness score above which drill-in is triggered;
                    default 0.5

    Returns:
      DrillInDecision with 0..3 specs.

    Raises:
      KeyError: if parent_wave is not registered.
      ValueError: if parent_wave has no drill-in slot (caller should
        not have invoked this function).
    """
    if parent_wave not in DRILL_IN_SLOTS:
        raise ValueError(
            f"parent_wave {parent_wave!r} has no drill-in slot; "
            f"allowed: {sorted(DRILL_IN_SLOTS)}"
        )
    parent = get_wave(parent_wave)
    score = _score_thinness(parent, evidence)
    if score < threshold:
        return DrillInDecision(
            parent_wave=parent_wave, thinness_score=score, specs=()
        )
    # Trigger all 3 reason classes when evidence is fully thin; the executor
    # can dedupe / suppress duplicates. For partial thinness, only the
    # ``expand_scan`` reason fires by default.
    if score >= 0.9:
        reasons: tuple[str, ...] = (
            DrillInReason.SWAP_VECTOR.value,
            DrillInReason.SWAP_ENTRY.value,
            DrillInReason.EXPAND_SCAN.value,
        )
    else:
        reasons = (DrillInReason.EXPAND_SCAN.value,)
    specs = _build_specs(parent_wave, reasons, parent, evidence)
    return DrillInDecision(
        parent_wave=parent_wave,
        thinness_score=score,
        specs=specs,
    )
