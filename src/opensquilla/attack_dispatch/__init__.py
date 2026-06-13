"""Attack dispatch model — fixed v1.

Replaces the broken 7-phase checklist with a wave-DAG model that:
- Discovers assets dynamically (no hardcoded port / subdomain / service lists)
- Forces Typed Task Envelopes on every wave handoff
- Gates every wave transition with a barrier (evidence join)
- Allows drill-in (Wn.5a / Wn.5b / Wn.5c) only in Breadth + Depth layers
- Computes penetration fan-out from the recon asset count
- Keeps all evidence schemas asset-count-agnostic (lists, not fixed-size)

The package is **synchronous and testable in isolation** — the actual
subagent execution is delegated to ``sessions_spawn`` in production; here
we expose the dispatch model + executor that can be driven by either real
sessions or in-memory test doubles.
"""

from opensquilla.attack_dispatch.envelope import (
    HandoffEnvelope,
    ResultFormatError,
    ResultMarker,
    RESULT_REGEX,
    RESULT_REGEX_LEGACY,
    ResultPhase,
    ResultStatus,
    append_synthetic_marker_if_missing,
    envelope_to_text,
    parse_envelope,
    parse_result_marker,
    result_marker_to_text,
    synthesize_marker,
    validate_envelope_format,
    validate_result_marker_format,
)
from opensquilla.attack_dispatch.waves import (
    LAYER_NAMES,
    LAYERS,
    WAVE_NAMES,
    WAVES,
    LayerName,
    WaveSpec,
    get_wave,
    is_drill_in_allowed,
    list_drill_in_slots,
)
from opensquilla.attack_dispatch.evidence import (
    EVIDENCE_SCHEMAS,
    EVIDENCE_SCHEMA_NAMES,
    EvidenceBase,
    GlobalFinding,
    PerTargetFinding,
    ReconEvidence,
    ResultStatus as EvidenceResultStatus,
    ROEEvidence,
    OPSECEvidence,
    PenetrationEvidence,
    PenetrationFinding,
    LateralEvidence,
    ReportEvidence,
    SubTargetHandle,
    SubTargetHandleList,
    make_evidence,
)
from opensquilla.attack_dispatch.drill_in import (
    DRILL_IN_REASONS,
    DrillInDecision,
    DrillInSpec,
    decide_drill_in,
)
from opensquilla.attack_dispatch.executor import (
    DispatchExecutor,
    DispatchMode,
    DispatchState,
    WaveResult,
)
from opensquilla.attack_dispatch.trail import (
    TRAIL_FILENAME,
    TrailRow,
    TrailSnapshot,
    rebuild_trail_markdown,
)

__all__ = [
    # envelope
    "HandoffEnvelope",
    "ResultFormatError",
    "ResultMarker",
    "RESULT_REGEX",
    "RESULT_REGEX_LEGACY",
    "ResultPhase",
    "ResultStatus",
    "append_synthetic_marker_if_missing",
    "envelope_to_text",
    "parse_envelope",
    "parse_result_marker",
    "result_marker_to_text",
    "synthesize_marker",
    "validate_envelope_format",
    "validate_result_marker_format",
    # waves
    "LAYER_NAMES",
    "LAYERS",
    "WAVE_NAMES",
    "WAVES",
    "WaveSpec",
    "get_wave",
    "is_drill_in_allowed",
    # evidence
    "EVIDENCE_SCHEMAS",
    "EVIDENCE_SCHEMA_NAMES",
    "EvidenceBase",
    "EvidenceResultStatus",
    "GlobalFinding",
    "PerTargetFinding",
    "ReconEvidence",
    "ROEEvidence",
    "OPSECEvidence",
    "PenetrationEvidence",
    "PenetrationFinding",
    "LateralEvidence",
    "ReportEvidence",
    "SubTargetHandle",
    "SubTargetHandleList",
    "make_evidence",
    # drill-in
    "DRILL_IN_REASONS",
    "DrillInDecision",
    "DrillInSpec",
    "decide_drill_in",
    # executor
    "DispatchExecutor",
    "DispatchMode",
    "DispatchState",
    "WaveResult",
    # trail
    "TRAIL_FILENAME",
    "TrailRow",
    "TrailSnapshot",
    "rebuild_trail_markdown",
]
