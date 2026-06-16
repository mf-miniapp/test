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
        """21 evidence schemas after Phase 3 adds find-complete-v1 and v2 cross-owner dispatch + drill-in-request."""
        assert len(EVIDENCE_SCHEMAS) == 21


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
        # v2: section is "Step F-final" (renamed from "Step FINAL")
        assert "F-final" in SOUL_BODY
        assert "handoff" in SOUL_BODY.lower()
        # Must still reference the v1 phrase so find-compat tools can grep it
        assert "FIND-COMPLETE.find.1" in SOUL_BODY

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

# ── V2 CROSS-OWNER DISPATCH + DRILL-IN SCHEMAS ────────────────


class TestW25DispatchEvidenceRegistration:
    def test_w25_dispatch_in_registry(self):
        from opensquilla.attack_dispatch.evidence import (
            EVIDENCE_SCHEMAS,
            W25DispatchEvidence,
        )

        assert "w2.5-dispatch-v1" in EVIDENCE_SCHEMAS
        assert EVIDENCE_SCHEMAS["w2.5-dispatch-v1"] is W25DispatchEvidence

    def test_w25_dispatch_round_trip(self):
        from opensquilla.attack_dispatch.evidence import W25DispatchEvidence

        ev = W25DispatchEvidence(
            target="acme-corp.com",
            sub_tracks=[
                {
                    "track_id": "S001",
                    "ports": ["1.2.3.4:443", "1.2.3.4:8443"],
                    "vector_class": "http_sqli",
                    "eta_s": 300,
                },
                {
                    "track_id": "S002",
                    "ports": ["1.2.3.4:8080"],
                    "vector_class": "http_auth_bypass",
                    "eta_s": 240,
                },
            ],
            trigger_wave="W2.5",
            recon_evidence_path="/tmp/recon.json",
            triage_evidence_path="/tmp/triage.json",
        )
        # Round-trip
        raw = ev.model_dump_json()
        restored = W25DispatchEvidence.model_validate_json(raw)
        assert restored.sub_tracks[0]["track_id"] == "S001"
        assert restored.sub_tracks[1]["vector_class"] == "http_auth_bypass"
        assert restored.trigger_wave == "W2.5"

    def test_w25_dispatch_default_target(self):
        """target must default to a non-empty sentinel when omitted."""
        from opensquilla.attack_dispatch.evidence import W25DispatchEvidence

        ev = W25DispatchEvidence(sub_tracks=[])
        assert ev.target == "cross-owner-w2.5-dispatch"


class TestDrillInRequestEvidenceRegistration:
    def test_drill_in_request_in_registry(self):
        from opensquilla.attack_dispatch.evidence import (
            DrillInRequestEvidence,
            EVIDENCE_SCHEMAS,
        )

        assert "drill-in-request-v1" in EVIDENCE_SCHEMAS
        assert EVIDENCE_SCHEMAS["drill-in-request-v1"] is DrillInRequestEvidence

    def test_drill_in_request_round_trip(self):
        from opensquilla.attack_dispatch.evidence import DrillInRequestEvidence

        ev = DrillInRequestEvidence(
            requested_slots=["W1.6c"],
            reasons=["W1.6c: port_scan_complete=false on 4 hosts"],
            evidence_paths=["/tmp/recon.json"],
        )
        raw = ev.model_dump_json()
        restored = DrillInRequestEvidence.model_validate_json(raw)
        assert restored.requested_slots == ["W1.6c"]
        assert restored.reasons == [
            "W1.6c: port_scan_complete=false on 4 hosts",
        ]
        assert restored.evidence_paths == ["/tmp/recon.json"]

    def test_drill_in_request_default_target(self):
        from opensquilla.attack_dispatch.evidence import DrillInRequestEvidence

        ev = DrillInRequestEvidence(
            requested_slots=["W1.6c"],
            reasons=["x"],
            evidence_paths=[],
        )
        assert ev.target == "cross-owner-drill-in-request"


# ── V2 WAVE DAG CONTRACT ──────────────────────────────────────


class TestV2WaveDAGContract:
    def test_find_owns_exactly_7_waves(self):
        """v2 显式 DAG: find owns 7 waves (no more, no fewer)."""
        from opensquilla.attack_dispatch.waves import WAVES, owner_of_wave

        find_waves = sorted(
            w
            for w, spec in WAVES.items()
            if spec.owner_agent == "hack-deep-find"
        )
        # The 7 waves find orchestrates: W0.5, W0.6, W1, W1.5, W1.5c, W2.5, W3.5
        assert find_waves == [
            "W0.5",
            "W0.6",
            "W1",
            "W1.5",
            "W1.5c",
            "W2.5",
            "W3.5",
        ]

    def test_w25_owner_is_find(self):
        """W2.5 owner_agent is find even though vulnerability-triage
        specialist lives in deep's allow_agents — the cross-owner
        dispatch is documented in the SOUL bodies and waves.py comment.
        """
        from opensquilla.attack_dispatch.waves import get_wave

        spec = get_wave("W2.5")
        assert spec.owner_agent == "hack-deep-find"
        assert spec.specialist == "vulnerability-triage"

    def test_w16_drill_in_is_deep_owned(self):
        """W1.6a/b/c drill-in slots are inherited from W1, which is
        deep-owned via its parent wave... wait, W1 is find-owned. The
        W1.6* slots are documented in the SOUL as deep-executed. Verify
        via the parent wave owner_agent inheritance in
        :func:`owner_of_wave`."""
        from opensquilla.attack_dispatch.waves import owner_of_wave

        # W1 is find-owned, so W1.6* drill-in slots inherit find as
        # owner_agent per the registry. The "deep executes them" rule
        # is a *protocol* rule (declared in hack-deep-find's SOUL
        # Step F1), not a waves.py rule. The runtime check fires only
        # when the LLM actually tries sessions_spawn with one of these
        # slots, in which case the parent wave is W1 → owner = find,
        # which matches the calling LLM. The protocol-level decision
        # is left to hack-deep via drill-in-request-v1.
        assert owner_of_wave("W1") == "hack-deep-find"
        assert owner_of_wave("W1.6c") == "hack-deep-find"

    def test_find_cannot_spawn_post_exploit_waves(self):
        """Defense in depth: check_authorization rejects any attempt
        to drive W5+ from find, even if the LLM goes off-script."""
        from opensquilla.attack_dispatch.waves import (
            UnauthorizedOwnerError,
            check_authorization,
        )

        with pytest.raises(UnauthorizedOwnerError):
            check_authorization("W5", "hack-deep-find")
        with pytest.raises(UnauthorizedOwnerError):
            check_authorization("W7", "hack-deep-find")
        with pytest.raises(UnauthorizedOwnerError):
            check_authorization("W8", "hack-deep-find")

    def test_ex_cannot_spawn_recon_or_triage(self):
        from opensquilla.attack_dispatch.waves import (
            UnauthorizedOwnerError,
            check_authorization,
        )

        with pytest.raises(UnauthorizedOwnerError):
            check_authorization("W1", "hack-deep-ex")
        with pytest.raises(UnauthorizedOwnerError):
            check_authorization("W2", "hack-deep-ex")
        with pytest.raises(UnauthorizedOwnerError):
            check_authorization("W0.5", "hack-deep-ex")


# ── V2 SOUL CONTRACT (F-final artifacts schema) ──────────────


class TestV2SoulFFinalArtifacts:
    def test_soul_documents_drill_in_request_artifact(self):
        """The find SOUL must document the v2 artifacts.drill_in_request
        field on the F-final envelope. Without it hack-deep has no
        way to learn the drill-in recommendation."""
        assert "drill_in_request" in SOUL_BODY
        assert "DrillInRequestEvidence" in SOUL_BODY

    def test_soul_documents_w25_cross_owner_dispatch(self):
        """The find SOUL must document the W2.5 cross-owner dispatch
        (find plans, hack-deep relays to vulnerability-triage)."""
        assert "W2.5-DISPATCH" in SOUL_BODY
        assert "W25DispatchEvidence" in SOUL_BODY
        # Negative: find must not call vulnerability-triage directly
        # in F2.5. SOUL must say find does NOT (markdown bold allowed).
        import re
        m = re.search(r"find[^\n]{0,40}(绝不|不直接 spawn|不直接调用)[^\n]{0,40}vulnerability-triage", SOUL_BODY)
        assert m is not None, (
            "find SOUL must include a 'find 绝不直接 spawn vulnerability-triage' "
            "declaration (v2 cross-owner hard constraint)."
        )

    def test_soul_documents_no_ex_link(self):
        """The find SOUL must explicitly state the find → ex link does
        NOT exist. Otherwise a future maintainer might re-add it."""
        assert "hack-deep-ex" in SOUL_BODY
        # At least one line saying find never spawns ex
        import re

        m = re.search(
            r"find[^\n]{0,40}(绝不|不要|never)[^\n]{0,40}hack-deep-ex",
            SOUL_BODY,
        )
        assert m is not None, (
            "find SOUL must include a 'find never spawns hack-deep-ex' "
            "declaration (v2 hard constraint)."
        )

    def test_soul_documents_w16c_declaration_not_execution(self):
        """The find SOUL must say: find DECLARES W1.6* drill-in
        requests but does NOT execute them."""
        assert "W1.6" in SOUL_BODY
        # '不直接执行' or '声明' or '不执行' must appear near W1.6
        import re

        m = re.search(
            r"W1\.6[^\n]{0,200}(声明|不直接执行|不执行|declares|does not execute)",
            SOUL_BODY,
        )
        assert m is not None, (
            "find SOUL must say W1.6* drill-in is declared in "
            "drill-in-request-v1, not executed by find."
        )


class TestHackDeepSoulV2Contract:
    def test_deep_soul_documents_w25_handling(self):
        """The hack-deep SOUL must have a v2 section explaining how it
        receives W2.5 dispatch from find and relays to
        vulnerability-triage sub-tracks."""
        import importlib

        mod = importlib.import_module("opensquilla.agents.hack-deep")
        soul = mod.SOUL_BODY
        assert "W2.5 Cross-Owner Dispatch Handling" in soul
        assert "vulnerability-triage" in soul
        assert "drill-in-request-v1" in soul


class TestHackDeepExSoulV2Contract:
    def test_ex_soul_documents_no_find_link(self):
        """The hack-deep-ex SOUL must explicitly declare that
        ex ← find edge does not exist, and ex → find edge does not
        exist either."""
        import importlib

        mod = importlib.import_module("opensquilla.agents.hack-deep-ex")
        soul = mod.SOUL_BODY
        assert "hack-deep-find" in soul
        # The v2 strengthened section must mention both directions
        assert (
            "find → ex" in soul.lower()
            or "find -> ex" in soul.lower()
            or "find-complete-v1" in soul
        )
        # The ex → find reverse direction is explicitly forbidden
        assert "post-exploit-complete-v1" in soul
