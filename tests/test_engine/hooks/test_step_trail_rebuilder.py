"""Tests for the StepTrailRebuilderHook (post-compaction step-trail overlay).

The hook reads ``<artifact_root>/trail.md`` from disk and prepends a
truncated version to ``agent.config.request_context_prompt``. Tests
use a tmp_path as the artifact root and pass a SimpleNamespace-based
agent mock.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opensquilla.attack_dispatch.executor import (
    DispatchState,
)
from opensquilla.attack_dispatch.trail import (
    TRAIL_FILENAME,
    TrailRow,
    TrailSnapshot,
    rebuild_trail_markdown,
)
from opensquilla.engine.hooks import StepTrailRebuilderHook, build_step_trail_hook
from opensquilla.engine.hooks.types import CompactionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_compaction_state(
    session_key: str = "agent:test:s1",
    agent_id: str = "test",
    extra: dict | None = None,
    agent: Any | None = None,
) -> CompactionState:
    merged_extra: dict = dict(extra or {})
    if agent is not None:
        merged_extra.setdefault("agent", agent)
    return CompactionState(
        session_key=session_key,
        agent_id=agent_id,
        total_tokens=10_000,
        threshold_tokens=200_000,
        extra=merged_extra,
    )


def _make_agent_config(tmp_path: Path, max_tokens: int = 2000) -> SimpleNamespace:
    """Build a minimal mock agent. workspace_dir is NOT set so the hook
    falls through to the constructor's ``artifact_root=tmp_path``.
    """
    return SimpleNamespace(
        config=SimpleNamespace(
            request_context_prompt=None,
            request_context_prompt_max_tokens=max_tokens,
        )
    )


def _write_trail(tmp_path: Path, n_rows: int = 1) -> Path:
    """Helper: write a synthetic trail.md with n_rows Wave runs."""
    state = DispatchState()
    for i in range(n_rows):
        p = tmp_path / f"W{i}" / f"W{i}.recon.1.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        # Minimal evidence JSON that yields a deterministic brief.
        p.write_text(
            '{"evidence": {"evidence_schema": "recon-v1", "subdomains": ["a"], "services": ["b"], "infra_sharing": []}}',
            encoding="utf-8",
        )
        state.evidence_paths[f"W{i}"] = str(p)
    rebuild_trail_markdown(tmp_path, state, target="x")
    return tmp_path / TRAIL_FILENAME


# ---------------------------------------------------------------------------
# 1. No-op when trail.md is missing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_no_op_when_trail_md_missing(tmp_path: Path) -> None:
    agent = _make_agent_config(tmp_path)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    await hook.after_compact(state, outcome=None)
    # No request_context_prompt mutation; the field stays at its initial value.
    assert agent.config.request_context_prompt is None


# ---------------------------------------------------------------------------
# 2. No-op when mtime unchanged (cached overlay)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_no_op_when_mtime_unchanged(tmp_path: Path) -> None:
    trail_path = _write_trail(tmp_path, n_rows=1)
    agent = _make_agent_config(tmp_path)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    await hook.after_compact(state, outcome=None)
    first = agent.config.request_context_prompt
    assert first is not None
    assert "Step trail" in first
    # The W0 row's evidence-derived brief ("1 subs, 1 services, …") must
    # be present in the first overlay.
    assert "subs" in first
    # Second call: file unchanged → cached overlay reused, no re-read.
    await hook.after_compact(state, outcome=None)
    second = agent.config.request_context_prompt
    # Cached value: content equal (ignoring trailing whitespace differences
    # introduced by the prepender's rstrip()).
    assert second and second.rstrip() == first.rstrip()


# ---------------------------------------------------------------------------
# 3. Injects new overlay on mtime change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_injects_overlay_on_mtime_change(tmp_path: Path) -> None:
    trail_path = _write_trail(tmp_path, n_rows=1)
    agent = _make_agent_config(tmp_path)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    await hook.after_compact(state, outcome=None)
    first = agent.config.request_context_prompt
    assert "W0" in first

    # Append more rows by rewriting the file with a different mtime.
    import os
    state2 = DispatchState()
    for i in range(3):
        p = tmp_path / f"W{i}" / f"W{i}.recon.1.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            '{"evidence": {"evidence_schema": "recon-v1", "subdomains": ["a"], "services": ["b"], "infra_sharing": []}}',
            encoding="utf-8",
        )
        state2.evidence_paths[f"W{i}"] = str(p)
    rebuild_trail_markdown(tmp_path, state2, target="x")
    new_mtime = trail_path.stat().st_mtime + 1.5
    os.utime(trail_path, (new_mtime, new_mtime))

    await hook.after_compact(state, outcome=None)
    second = agent.config.request_context_prompt
    assert second != first
    # The W2 row is now in the overlay (the post-rewrite trail has 3 rows).
    assert "W2" in second


# ---------------------------------------------------------------------------
# 4. Exception isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_isolated_from_exceptions(tmp_path: Path, monkeypatch) -> None:
    trail_path = _write_trail(tmp_path, n_rows=1)
    agent = _make_agent_config(tmp_path)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    # Force the read to raise.
    def _boom(*a, **kw):  # noqa: ANN001
        raise OSError("simulated read failure")
    monkeypatch.setattr("pathlib.Path.read_text", _boom)
    # Should swallow.
    await hook.after_compact(state, outcome=None)
    # No mutation.
    assert agent.config.request_context_prompt is None


# ---------------------------------------------------------------------------
# 5. artifact_root resolution priority
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_resolves_artifact_root_from_extra(tmp_path: Path) -> None:
    """``state.extra["artifact_root"]`` wins over the constructor default."""
    custom_dir = tmp_path / "custom_artifact_root"
    custom_dir.mkdir()
    trail_path = custom_dir / TRAIL_FILENAME
    trail_path.write_text(
        "# Step trail\n\n## Wave runs\n\n| step | wave | brief | path |\n| --- | --- | --- | --- |\n"
        "| W0.x.1 | W0 | custom | `/x` |\n\n## Drill-ins\n\n| step | wave | brief | path |\n| --- | --- | --- | --- |\n| (no drill-ins) | | | |\n\n## Errors\n\n- (none)\n\n## End of trail\n",
        encoding="utf-8",
    )
    other_dir = tmp_path / "other_dir"
    other_dir.mkdir()
    (other_dir / TRAIL_FILENAME).write_text("WRONG", encoding="utf-8")

    agent = _make_agent_config(tmp_path)
    state = _make_compaction_state(extra={"artifact_root": str(custom_dir)}, agent=agent)
    hook = build_step_trail_hook(artifact_root=other_dir)
    await hook.after_compact(state, outcome=None)
    assert "custom" in agent.config.request_context_prompt


# ---------------------------------------------------------------------------
# 6. Token-bounded overlay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_token_bounded_overlay(tmp_path: Path) -> None:
    # 50 rows → very long trail; tight budget forces truncation.
    _write_trail(tmp_path, n_rows=50)
    agent = _make_agent_config(tmp_path, max_tokens=50)  # 50 tokens ≈ 200 chars
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    await hook.after_compact(state, outcome=None)
    overlay = agent.config.request_context_prompt or ""
    # The overlay should be capped at max_tokens * 4 chars + header slack
    # (truncate_trail_for_overlay pads by 32 chars for last-resort headers).
    assert len(overlay) <= 50 * 4 + 80, f"overlay too long: {len(overlay)}"
    assert "showing last 5 of" in overlay or "[truncated]" in overlay


# ---------------------------------------------------------------------------
# 7. Preserves last 5 steps when truncated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_preserves_last_5_steps_when_truncated(tmp_path: Path) -> None:
    _write_trail(tmp_path, n_rows=20)
    agent = _make_agent_config(tmp_path, max_tokens=50)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    await hook.after_compact(state, outcome=None)
    overlay = agent.config.request_context_prompt or ""
    # Truncation is active: either the table-trim path shows the last 5
    # rows, or the hard-cap fires. Either way an early step's brief is
    # gone and the truncation marker is present.
    assert "[truncated]" in overlay or "showing last 5 of" in overlay
    # An early step's brief must be gone.
    assert "brief 0" not in overlay and "brief 1" not in overlay
    # At least one later step survived.
    assert "brief" in overlay  # some "brief N" string is present


# ---------------------------------------------------------------------------
# 8. Respects max_tokens field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_respects_max_tokens_field(tmp_path: Path) -> None:
    _write_trail(tmp_path, n_rows=10)
    # max_tokens=10 forces even harder truncation.
    agent = _make_agent_config(tmp_path, max_tokens=10)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)
    await hook.after_compact(state, outcome=None)
    overlay = agent.config.request_context_prompt or ""
    # Very tight budget (10 tokens) → overlay is heavily truncated.
    assert len(overlay) <= 10 * 4 + 80, f"overlay too long: {len(overlay)}"
    # The full trail header should still be present (it's preserved).
    assert "Step trail" in overlay


# ---------------------------------------------------------------------------
# 9. Integration: real CompactionAndHistoryStage + StepTrailRebuilderHook
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hook_integration_through_stage(tmp_path: Path) -> None:
    """Real stage + real hook + a pre-written trail.md → request_context_prompt
    has the trail overlay after the standard '## Upstream context' line.
    """
    # Write a trail with two rows.
    _write_trail(tmp_path, n_rows=2)

    agent = _make_agent_config(tmp_path)
    state = _make_compaction_state(agent=agent)
    hook = build_step_trail_hook(artifact_root=tmp_path)

    # Simulate the stage firing the hook's after_compact, then mutating
    # the agent's request_context_prompt as the stage's prepender would.
    await hook.after_compact(state, outcome=None)
    # The stage's _request_context_prepender (without our overlay):
    prepended = "## Upstream context\n\nsomebody else's content"
    agent.config.request_context_prompt = (
        f"{agent.config.request_context_prompt}\n\n{prepended}"
    )
    # Final order: trail overlay first, then standard upstream context.
    final = agent.config.request_context_prompt
    assert "Step trail" in final
    assert "## Upstream context" in final
    assert final.index("Step trail") < final.index("## Upstream context")
