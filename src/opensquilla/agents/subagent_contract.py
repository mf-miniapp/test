"""Subagent contract — the leaf-level subagent grounding text.

Lives in ``opensquilla.agents`` next to ``limits`` because both modules are
imported from many different call sites (engine steps, builtin tools, the
gateway, runtime, etc.) and must NEVER pull in heavier dependencies like
``gateway.routing`` or ``pydantic`` evidence models.

Three constants are exported:

- ``SUBAGENT_RESULT_MARKER_INSTRUCTION`` — the canonical text that tells a
  subagent to emit the Result Marker footer on its final assistant message.
  This text is embedded in both ``tools.builtin.sessions._SUBAGENT_SYSTEM_PROMPT``
  (first-user-turn injection) and
  ``engine.steps.inject_subagent_grounding._SUBAGENT_GROUNDING`` (per-turn
  fallback) and ``engine.runtime._SUBAGENT_TASK_PROTOCOL`` (ToolContext extra
  context). Keeping a single source of truth in a leaf module makes the
  "must be identical across all three sites" invariant easy to maintain
  without risking circular imports.

- ``SUBAGENT_GROUNDING_PREAMBLE`` — the original single-sentence preamble
  the codebase has shipped since the v0.1 subagent contract landed.

- ``build_subagent_system_prompt()`` — concatenates the two so callers do
  not have to repeat the join. The order is fixed: preamble first, marker
  instruction second. A test pins both the order and the literal text.
"""

from __future__ import annotations

SUBAGENT_GROUNDING_PREAMBLE: str = (
    "You are a subagent. Execute the delegated task faithfully and return "
    "a structured result to your parent session."
)

# Canonical Result Marker footer instruction. Parsed by
# ``opensquilla.attack_dispatch.envelope.RESULT_REGEX`` — the literal
# regex tokens ``schema:``, ``phase:``, ``wave:`` and ``deps:`` MUST
# appear verbatim so a defensive copy of the parser is not required.
#
# The old form used ``status: complete|partial|failed`` which read like
# a final commit message. LLM orchestrators would emit
# ``status: complete`` after a single evidence-collection wave and stop
# there, even when the parent task spec said "4-layer × 9-wave". The
# new form uses ``phase: <evidence-collection|synthesis|exploitation|
# complete>`` plus ``wave: <N/M>`` so the LLM can see at a glance that
# "phase: evidence-collection" still has synthesis and exploitation
# ahead. Only emit ``phase: complete`` on the final wave of the final
# layer.
SUBAGENT_RESULT_MARKER_INSTRUCTION: str = (
    "RESULT MARKER — REQUIRED FOOTER. At the end of your final assistant "
    "message, you MUST output exactly one line of this exact form:\n"
    "  schema: <evidence_schema> | phase: <phase> | wave: <N/M> | deps: <csv-or-'empty'>\n"
    "where <evidence_schema> is the schema the parent told you to produce "
    "(e.g. recon-v1, intel-v1), <phase> is one of\n"
    "  - evidence-collection (raw recon / intel / vuln enumeration output)\n"
    "  - synthesis             (cross-wave aggregation, prioritization, scoring)\n"
    "  - exploitation          (active probing, payload delivery, post-exploit)\n"
    "  - complete              (ONLY on the final wave of the final layer —\n"
    "                            mid-DAG output of ``complete`` makes the\n"
    "                            parent orchestrator stop spawning the\n"
    "                            remaining waves and abandons the run)\n"
    "<wave> is the zero-based wave index and total (e.g. ``0/8`` for "
    "the first of nine), and <deps> is the comma-separated handoff_ids "
    "you actually consumed from the input (or the literal token 'empty' "
    "if none). The parent parses this line to verify you finished the "
    "wave and to know whether the run is over. If you cannot produce the "
    "evidence at all, still output the marker with phase=evidence-"
    "collection (or the latest phase you reached) and the deps you did "
    "manage to inspect. A missing or malformed marker is treated as "
    "incomplete contract by the parent and the wake is downgraded — do "
    "not omit it."
)


def build_subagent_system_prompt() -> str:
    """Return the canonical subagent system prompt text.

    Order: preamble first, then the Result Marker instruction. Used by
    ``tools.builtin.sessions._SUBAGENT_SYSTEM_PROMPT`` and by
    ``engine.steps.inject_subagent_grounding`` (which re-injects the same
    string on every turn to defend against compaction erasure).
    """
    return f"{SUBAGENT_GROUNDING_PREAMBLE}\n\n{SUBAGENT_RESULT_MARKER_INSTRUCTION}"
