"""Producer tests for the step-trail Markdown writer.

The trail is a derived view over the on-disk evidence JSONs and the
manifest that the executor already writes. These tests drive the
executor through ``_make_specialist_double`` (re-imported from
``test_attack_dispatch``) to a real tmp_path, then assert on
``<root>/trail.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opensquilla.attack_dispatch import trail as trail_mod
from opensquilla.attack_dispatch.executor import (
    DEFAULT_ARTIFACT_ROOT,  # noqa: F401 — referenced by docstring only
    DispatchExecutor,
    DispatchMode,
    DispatchState,
)
from opensquilla.attack_dispatch.trail import (
    TRAIL_FILENAME,
    TrailRow,
    TrailSnapshot,
    rebuild_trail_markdown,
    truncate_trail_for_overlay,
)
from opensquilla.attack_dispatch.waves import WAVE_NAMES
from opensquilla.engine.turn_runner.outcome import StageOutcome  # noqa: F401

# Re-use the canned specialist from the existing test file.
from tests.test_attack_dispatch import _make_specialist_double


def _run_executor(tmp_path: Path, **kwargs) -> DispatchState:
    """Drive the executor with the canned specialist on tmp_path; return state."""
    state = DispatchState()
    ex = DispatchExecutor(
        specialist_fn=_make_specialist_double(**kwargs),
        artifact_root=tmp_path,
    )
    ex.run(target="example.com", state=state)
    return state


# ---------------------------------------------------------------------------
# 1. trail.md is created on run start
# ---------------------------------------------------------------------------


def test_trail_md_created_on_run_start(tmp_path: Path) -> None:
    """After ex.run(), trail.md exists as a sibling of manifest.json."""
    _run_executor(tmp_path)
    assert (tmp_path / TRAIL_FILENAME).is_file()
    assert (tmp_path / "manifest.json").is_file()


# ---------------------------------------------------------------------------
# 2. trail.md has the expected header and table
# ---------------------------------------------------------------------------


def test_trail_md_has_header_and_table(tmp_path: Path) -> None:
    _run_executor(tmp_path)
    content = (tmp_path / TRAIL_FILENAME).read_text(encoding="utf-8")
    assert content.startswith("# Step trail — hack-deep run")
    assert "## Wave runs" in content
    assert "## Drill-ins" in content
    assert "## Errors" in content
    assert "## End of trail" in content  # integrity marker


# ---------------------------------------------------------------------------
# 3. Wave runs table has one row per parent wave that produced evidence
# ---------------------------------------------------------------------------


def test_trail_md_wave_runs_row_count_matches_produced_waves(tmp_path: Path) -> None:
    state = _run_executor(tmp_path)
    content = (tmp_path / TRAIL_FILENAME).read_text(encoding="utf-8")
    # Count the rows between "## Wave runs" and "## Drill-ins".
    section = content.split("## Wave runs", 1)[1].split("## Drill-ins", 1)[0]
    rows = [
        line for line in section.splitlines()
        if line.startswith("| ") and not line.startswith("| ---") and not line.startswith("| step ")
    ]
    data_rows = len(rows)
    # The trail should render at least one row per evidence_paths entry
    # that's a real parent wave (not W0_peer_attach, etc.). The exact
    # count is implementation-detail; assert at least the canned
    # specialist's known output count.
    assert data_rows >= 9, f"expected at least 9 wave rows, got {data_rows}"
    # Every row in the Wave runs table corresponds to a real produced wave.
    wave_column = [
        line.split("|")[2].strip() for line in rows if line.startswith("| ")
    ]
    for w in wave_column:
        assert w in WAVE_NAMES, f"unexpected wave in trail: {w!r}"


# ---------------------------------------------------------------------------
# 4. Briefs are deterministic and bounded
# ---------------------------------------------------------------------------


def test_trail_md_brief_is_deterministic_and_bounded(tmp_path: Path) -> None:
    state1 = _run_executor(tmp_path)
    content1 = (tmp_path / TRAIL_FILENAME).read_text(encoding="utf-8")
    # Force a rebuild on a different path to confirm determinism (no clock-dependent content).
    state2 = _run_executor(tmp_path)
    content2 = (tmp_path / TRAIL_FILENAME).read_text(encoding="utf-8")
    # Timestamps differ between runs; strip them before comparing.
    def _strip_ts(c: str) -> str:
        return "\n".join(
            line for line in c.splitlines()
            if not line.startswith("- produced:") and not line.startswith("- started:")
        )
    assert _strip_ts(content1) == _strip_ts(content2)
    # Every brief cell is <= 200 chars (validator cap).
    for line in content1.splitlines():
        if not line.startswith("| "):
            continue
        if line.startswith("| ---") or line.startswith("| step "):
            continue
        # Brief is the third column; trim the path column (backticked).
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) < 3:
            continue
        # Strip escaped pipes and backticks for length measurement.
        brief = cells[2].replace("\\|", "|").replace("`", "")
        assert len(brief) <= 200, f"brief too long: {brief!r}"


# ---------------------------------------------------------------------------
# 5. Drill-ins go into their own section, not Wave runs
# ---------------------------------------------------------------------------


def test_trail_md_drill_in_separate_section(tmp_path: Path) -> None:
    # Use a non-trivial specialist double: W1.6a drill-in gets triggered
    # by the canned specialist when W1 is in empty_waves.
    state = _run_executor(tmp_path)
    # Inspect the snapshot directly to assert structure.
    snap = trail_mod.build_snapshot(state, target="example.com")
    # Drill-in rows are produced from specialist_artifacts + drill_ins.
    # In the canned test, SERIAL mode is not used, so the per-specialist
    # list is empty. drill_ins is empty for an all-default canned run.
    # Assert the section exists and is well-formed regardless of content.
    md = trail_mod._format_markdown(snap)  # noqa: SLF001 — internal use in test
    assert "## Drill-ins" in md
    # Even if no drill-ins fire, the section is rendered with a placeholder.
    if not snap.drill_ins:
        assert "| (no drill-ins) | | | |" in md


# ---------------------------------------------------------------------------
# 6. SERIAL mode lists per-specialist files under Drill-ins
# ---------------------------------------------------------------------------


def test_trail_md_serial_mode_lists_per_specialist(tmp_path: Path) -> None:
    state = _run_executor(tmp_path)
    # Simulate a SERIAL run by populating specialist_artifacts directly.
    specialist_path = tmp_path / "W1" / "W1.recon.1.json"
    if not specialist_path.exists():
        # Force a write so the file exists.
        from opensquilla.attack_dispatch.executor import DispatchState as _DS
        specialist_path.parent.mkdir(parents=True, exist_ok=True)
        specialist_path.write_text(
            json.dumps({
                "stage": "W1",
                "agent": "recon",
                "session_id": "W1.recon.1",
                "target": "example.com",
                "evidence": {
                    "target": "example.com",
                    "produced_at": "2026-06-07T00:00:00Z",
                    "evidence_version": "v1",
                    "evidence_schema": "recon-v1",
                    "subdomains": ["a.example.com"],
                    "services": [],
                    "infra_sharing": [],
                },
            }),
            encoding="utf-8",
        )
    state.specialist_artifacts["W1.recon.1"] = str(specialist_path)
    rebuild_trail_markdown(tmp_path, state, target="example.com")
    content = (tmp_path / TRAIL_FILENAME).read_text(encoding="utf-8")
    drill_section = content.split("## Drill-ins", 1)[1].split("## Errors", 1)[0]
    assert "W1.recon.1" in drill_section
    assert "serial:" in drill_section


# ---------------------------------------------------------------------------
# 7. Atomic write: failure leaves no .tmp behind
# ---------------------------------------------------------------------------


def test_trail_md_atomic_write_no_tmp_leftover(tmp_path: Path, monkeypatch) -> None:
    state = _run_executor(tmp_path)
    # Force os.replace to fail so the writer must clean up its tmp.
    real_replace = trail_mod.os.replace
    def _boom(src, dst):  # noqa: ANN001 — match os.replace signature
        raise OSError("simulated rename failure")
    monkeypatch.setattr(trail_mod.os, "replace", _boom)
    result = rebuild_trail_markdown(tmp_path, state, target="example.com")
    assert result is None
    # No .tmp leftover.
    leftovers = list(tmp_path.glob(f"{TRAIL_FILENAME}.tmp*"))
    assert leftovers == [], f"leftover tmp files: {leftovers}"
    monkeypatch.setattr(trail_mod.os, "replace", real_replace)


# ---------------------------------------------------------------------------
# 8. Empty run still produces a valid trail.md
# ---------------------------------------------------------------------------


def test_trail_md_empty_run_still_has_header(tmp_path: Path) -> None:
    state = DispatchState()  # no evidence
    rebuild_trail_markdown(tmp_path, state, target="x")
    content = (tmp_path / TRAIL_FILENAME).read_text(encoding="utf-8")
    assert content.startswith("# Step trail — hack-deep run")
    assert "(no waves yet)" in content
    assert "(no drill-ins)" in content
    assert "- (none)" in content  # empty errors section
    assert "## End of trail" in content


# ---------------------------------------------------------------------------
# 9. Truncation: oversize trail collapses to last 5 rows + pointer
# ---------------------------------------------------------------------------


def test_truncate_trail_for_overlay_keeps_last_rows() -> None:
    content = "\n".join([
        "# Step trail — hack-deep run",
        "",
        "- target: x",
        "- started: 2026-06-07T00:00:00+00:00",
        "- produced: 2026-06-07T00:00:00+00:00",
        "- waves: 1",
        "- step_count: 10",
        "- source: trail.md",
        "",
        "## Wave runs",
        "",
        "| step | wave | brief | path |",
        "| --- | --- | --- | --- |",
        *(f"| step-{i} | W1 | brief {i} | `/tmp/{i}.json` |" for i in range(10)),
        "",
        "## Drill-ins",
        "",
        "| step | wave | brief | path |",
        "| --- | --- | --- | --- |",
        "| (no drill-ins) | | | |",
        "",
        "## Errors",
        "",
        "- (none)",
        "",
        "## End of trail",
        "",
    ])
    # Budget a few hundred chars to force table truncation but keep header.
    out = truncate_trail_for_overlay(content, max_tokens=200)  # ~800 chars
    # The pointer indicates the table was trimmed.
    assert "showing last 5 of" in out
    # The first 5 data rows (step-0..step-4) must be gone; later rows kept.
    assert "step-9" in out
    assert "step-0" not in out and "step-3" not in out
