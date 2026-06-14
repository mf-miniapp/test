"""End-to-end handoff: hack-deep-find → hack-deep.

Verifies the Phase 3 wiring:

1. ``FindCompleteEvidence`` registered in attack_dispatch.evidence
2. Round-trip construction + JSON serialization
3. ``asset_tree_complete`` returns a path that the receiver can re-load
4. The handoff envelope header format matches the SOUL contract
5. SOUL has the handoff turn wired (sessions_spawn → hack-deep)
6. Clone script lists `hack-deep` in the coordinator's allow_agents

These tests do NOT spawn real LLM agents — they validate the data-plane
contracts that the LLM-coordinator would use at the end of a find run.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest

# 2026-06-15 (unified-naming): package renamed to use hyphens;
# Python's `from X import Y` syntax rejects hyphens, so we use
# importlib.
import importlib
_hack_deep_find_pkg = importlib.import_module("opensquilla.agents.hack-deep-find")
ATTRIBUTION_BODY = _hack_deep_find_pkg.ATTRIBUTION_BODY
SOUL_BODY = _hack_deep_find_pkg.SOUL_BODY
from opensquilla.asset_tree.models import AssetState, AssetType
from opensquilla.asset_tree.tree import AssetTree
from opensquilla.attack_dispatch.evidence import (
    EVIDENCE_SCHEMAS,
    FindCompleteEvidence,
    FindFrontierNode,
)


# ── EVIDENCE SCHEMA REGISTRATION ──────────────────────────────


class TestFindCompleteEvidenceRegistration:
    def test_find_complete_v1_in_registry(self):
        assert "find-complete-v1" in EVIDENCE_SCHEMAS
        assert EVIDENCE_SCHEMAS["find-complete-v1"] is FindCompleteEvidence

    def test_schema_count_is_19(self):
        """19 evidence schemas after Phase 3 adds find-complete-v1."""
        assert len(EVIDENCE_SCHEMAS) == 19


# ── FIND COMPLETE EVIDENCE CONSTRUCTION ──────────────────────────────


class TestFindCompleteEvidenceConstruction:
    def test_minimal_construction(self):
        ev = FindCompleteEvidence(
            tree_id="t1",
            root_domain="example.com",
            tree_path="/tmp/t1.json",
        )
        assert ev.evidence_schema == "find-complete-v1"
        assert ev.target == "example.com"  # auto-filled from root_domain
        assert ev.tree_id == "t1"
        assert ev.tree_stats == {}
        assert ev.frontier_summary == []
        assert ev.duration_s == 0
        assert ev.specialists_invoked == []

    def test_full_construction_with_frontier(self):
        frontier = [
            FindFrontierNode(
                node_id="abc",
                asset_type="sub_domain",
                value="api.example.com",
                state="discovered",
                parent_value="example.com",
            ),
            FindFrontierNode(
                node_id="def",
                asset_type="ip",
                value="1.2.3.4",
                state="triaged",
                parent_value="api.example.com",
            ),
        ]
        ev = FindCompleteEvidence(
            tree_id="t1",
            root_domain="example.com",
            tree_path="/tmp/t1.json",
            tree_stats={"total_nodes": 5, "by_type": {"sub_domain": 2}},
            frontier_summary=frontier,
            duration_s=120,
            specialists_invoked=["ip-resolver", "port-scanner"],
        )
        assert len(ev.frontier_summary) == 2
        assert ev.frontier_summary[0].value == "api.example.com"
        assert ev.duration_s == 120
        assert "ip-resolver" in ev.specialists_invoked

    def test_explicit_target_overrides_root_domain(self):
        """If caller explicitly sets target, don't override it."""
        ev = FindCompleteEvidence(
            tree_id="t1",
            target="engagement-42",
            root_domain="example.com",
            tree_path="/tmp/t1.json",
        )
        assert ev.target == "engagement-42"

    def test_json_round_trip(self):
        ev = FindCompleteEvidence(
            tree_id="t1",
            root_domain="example.com",
            tree_path="/tmp/t1.json",
            duration_s=60,
            specialists_invoked=["ip-resolver"],
        )
        payload = ev.model_dump(mode="json")
        restored = FindCompleteEvidence.model_validate(payload)
        assert restored.tree_id == ev.tree_id
        assert restored.root_domain == ev.root_domain
        assert restored.duration_s == ev.duration_s


# ── TREE ↔ EVIDENCE PATH ──────────────────────────────


class TestAssetTreePersistenceForHandoff:
    """The `tree_path` in FindCompleteEvidence must be a valid re-loadable path."""

    def test_asset_tree_round_trip_preserves_structure(self, tmp_path):
        # Build a small tree and save it where handoff expects
        tree = AssetTree("example.com")
        sub_id = tree.add_node(
            AssetType.SUB_DOMAIN, "api.example.com", parent_id=tree.root_id
        )
        tree.add_node(AssetType.IP, "1.2.3.4", parent_id=sub_id)
        tree.update_state(sub_id, AssetState.DISCOVERED)

        target_path = tmp_path / "tree.json"
        target_path.write_text(tree.to_json(), encoding="utf-8")

        # Receiver reloads
        restored = AssetTree.from_json(target_path.read_text(encoding="utf-8"))
        assert restored.root_domain == "example.com"
        assert restored.find_nodes_by_value("api.example.com")[0].state == (
            AssetState.DISCOVERED
        )

        # And the evidence wraps this path correctly
        ev = FindCompleteEvidence(
            tree_id="handoff-1",
            root_domain="example.com",
            tree_path=str(target_path),
        )
        assert Path(ev.tree_path).exists()
        assert Path(ev.tree_path).read_text(encoding="utf-8") == tree.to_json()


# ── HANDOFF ENVELOPE FORMAT ──────────────────────────────


class TestHandoffEnvelopeFormat:
    """The SOUL contract specifies a 4-field HANDOFF header with artifacts."""

    def _build_artifacts_field(self, tree_path: str) -> str:
        return urllib.parse.quote(json.dumps({"find_tree": tree_path}))

    def test_artifacts_urlencoded_json(self):
        tree_path = "/Users/x/.opensquilla/state/asset_trees/t1.json"
        encoded = self._build_artifacts_field(tree_path)
        decoded = json.loads(urllib.parse.unquote(encoded))
        assert decoded == {"find_tree": tree_path}

    def test_handoff_envelope_format(self):
        """Verify the envelope string the LLM-coordinator would build."""
        tree_path = "/Users/x/.opensquilla/state/asset_trees/t1.json"
        artifacts = self._build_artifacts_field(tree_path)
        envelope = (
            "HANDOFF FIND-COMPLETE.find.1 | deps=empty "
            "| schema=find-complete-v1 | eta=60 "
            f"| artifacts={artifacts}"
        )
        # All 4 mandatory fields
        assert "HANDOFF FIND-COMPLETE.find.1" in envelope
        assert "deps=empty" in envelope
        assert "schema=find-complete-v1" in envelope
        assert "eta=60" in envelope
        # artifacts optional but required for handoff
        assert "artifacts=" in envelope
        # Round-trip parse via attack_dispatch.envelope.parse_envelope
        from opensquilla.attack_dispatch.envelope import parse_envelope
        parsed = parse_envelope(envelope)
        assert parsed.evidence_schema == "find-complete-v1"
        assert parsed.expected_runtime_s == 60
        assert "find_tree" in parsed.input_artifacts
        assert parsed.input_artifacts["find_tree"] == tree_path


# ── SOUL WIRING ──────────────────────────────


class TestSoulWiringForHandoff:
    """SOUL_BODY.md must encode the handoff turn the LLM should execute."""

    def test_soul_documents_handoff_step(self):
        # The new "Step FINAL" section with handoff
        assert "Step FINAL" in SOUL_BODY
        assert "handoff" in SOUL_BODY.lower()

    def test_soul_constructs_handoff_envelope(self):
        # The literal envelope template
        assert "HANDOFF FIND-COMPLETE.find.1" in SOUL_BODY
        assert "schema=find-complete-v1" in SOUL_BODY
        assert "artifacts=" in SOUL_BODY

    def test_soul_spawns_hack_deep(self):
        # The handoff target agent id
        assert "sessions_spawn" in SOUL_BODY
        assert 'agent_id="hack-deep"' in SOUL_BODY or "agent_id='hack-deep'" in SOUL_BODY

    def test_soul_calls_asset_tree_complete(self):
        # Must touch asset_tree_complete to obtain tree_path
        assert "asset_tree_complete" in SOUL_BODY

    def test_soul_has_hack_deep_collaboration_section(self):
        assert "与 hack-deep 的协作" in SOUL_BODY
        assert "Phase 3" in SOUL_BODY


# ── CLONE SCRIPT ALLOWLIST ──────────────────────────────


class TestCloneScriptHackDeepAllowAgent:
    def test_hack_deep_in_coordinator_allow_agents(self):
        """The clone script must list 'hack-deep' in the coordinator's allow_agents."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "clone_hack_deep_find",
            "/Users/zlpc/data/zspace/hack/opensquilla/scripts/clone_hack_deep_find.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert "hack-deep" in mod.SPECIALIST_AGENTS
        # Plus all 6 recon specialists
        for sid in (
            "subdomain-discoverer",
            "ip-resolver",
            "port-scanner",
            "service-fingerprint",
            "endpoint-crawler",
            "leaf-verifier",
        ):
            assert sid in mod.SPECIALIST_AGENTS, f"missing {sid}"


# ── ATTRIBUTION ──────────────────────────────


class TestAttributionForHandoff:
    def test_find_complete_v1_in_attribution(self):
        assert "find-complete-v1" in ATTRIBUTION_BODY

    def test_attribution_describes_artifacts_field(self):
        """The handoff carries an artifacts= urlencoded JSON with find_tree."""
        # ATTRIBUTION should mention artifacts and tree_path
        assert "tree_path" in ATTRIBUTION_BODY
        assert "artifact" in ATTRIBUTION_BODY.lower()

    def test_attribution_documents_hack_deep_consumer(self):
        assert "hack-deep" in ATTRIBUTION_BODY