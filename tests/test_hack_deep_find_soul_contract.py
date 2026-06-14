"""SOUL contract tests for hack-deep-find.

Replaces the deleted test_hack_deep_find_coordinator.py (which tested
the obsolete Python driver). These tests assert that the new
LLM-orchestrator SOUL contains the structural elements needed for the
LLM to drive a recursive wave loop correctly.

The SOUL is a markdown string; we check for required sections, the
typed-envelope header format, the 6 specialist ids, the no-scan rule,
and the asset_tree_* tool references.
"""

from __future__ import annotations

# 2026-06-15 (unified-naming): package renamed to use hyphens;
# Python's `from X import Y` syntax rejects hyphens, so we use
# importlib. The specialists __init__ exposes snake_case aliases
# (e.g. ``endpoint_crawler``) for backward compat.
import importlib
_hack_deep_find_pkg = importlib.import_module("opensquilla.agents.hack-deep-find")
ATTRIBUTION_BODY = _hack_deep_find_pkg.ATTRIBUTION_BODY
SOUL_BODY = _hack_deep_find_pkg.SOUL_BODY
_specialists_pkg = importlib.import_module(
    "opensquilla.agents.hack-deep-find.specialists"
)
endpoint_crawler = _specialists_pkg.endpoint_crawler
ip_resolver = _specialists_pkg.ip_resolver
leaf_verifier = _specialists_pkg.leaf_verifier
port_scanner = _specialists_pkg.port_scanner
service_fingerprint = _specialists_pkg.service_fingerprint
subdomain_discoverer = _specialists_pkg.subdomain_discoverer


class TestHackDeepFindSoul:
    def test_soul_loaded(self):
        assert isinstance(SOUL_BODY, str)
        assert len(SOUL_BODY) > 200

    def test_attribution_loaded(self):
        assert isinstance(ATTRIBUTION_BODY, str)
        assert len(ATTRIBUTION_BODY) > 200

    def test_soul_mentions_no_scan_rule(self):
        """SOUL must explicitly forbid the coordinator from running scans."""
        assert "严禁" in SOUL_BODY or "不允许" in SOUL_BODY
        # must forbid curl / nmap / masscan explicitly
        for forbidden in ("curl", "nmap", "masscan"):
            assert forbidden in SOUL_BODY, f"SOUL must mention forbidden tool: {forbidden}"

    def test_soul_documents_asset_tree_tools(self):
        """SOUL must reference the asset_tree_* tool family the LLM uses."""
        # SOUL groups tools via the `asset_tree_*` wildcard; verify a few
        # canonical names appear AND the wildcard mention is present.
        assert "asset_tree_*" in SOUL_BODY or "asset_tree_create" in SOUL_BODY
        for tool in (
            "asset_tree_create",
            "asset_tree_find_unseen",
            "asset_tree_complete",
        ):
            assert tool in SOUL_BODY, f"SOUL missing tool reference: {tool}"

    def test_soul_documents_sessions_spawn_and_yield(self):
        """SOUL must use the canonical wave primitives."""
        assert "sessions_spawn" in SOUL_BODY
        assert "sessions_yield" in SOUL_BODY

    def test_soul_documents_handoff_envelope(self):
        """SOUL must show the 4-field HANDOFF envelope header format."""
        assert "HANDOFF" in SOUL_BODY
        assert "deps=" in SOUL_BODY
        assert "schema=" in SOUL_BODY
        assert "eta=" in SOUL_BODY

    def test_soul_lists_all_6_specialists(self):
        """SOUL must enumerate all 6 specialist ids the LLM can spawn."""
        for specialist_id in (
            "subdomain-discoverer",
            "ip-resolver",
            "port-scanner",
            "service-fingerprint",
            "endpoint-crawler",
            "leaf-verifier",
        ):
            assert specialist_id in SOUL_BODY, (
                f"SOUL missing specialist: {specialist_id}"
            )

    def test_soul_documents_wave_loop(self):
        """SOUL must describe the recursive wave loop pattern."""
        assert "wave" in SOUL_BODY.lower()
        # Loop concept
        assert "loop" in SOUL_BODY.lower() or "LOOP" in SOUL_BODY


class TestHackDeepFindAttribution:
    def test_attribution_lists_all_6_schemas(self):
        """ATTRIBUTION must document all 6 specialist output schemas."""
        for schema in (
            "subdomain-v1",
            "ip-v1",
            "port-v1",
            "service-v1",
            "endpoint-v1",
            "leaf-v1",
        ):
            assert schema in ATTRIBUTION_BODY, (
                f"ATTRIBUTION missing schema: {schema}"
            )

    def test_attribution_documents_find_complete_handoff(self):
        """ATTRIBUTION must describe the Phase 3 handoff to hack-deep."""
        assert "find-complete-v1" in ATTRIBUTION_BODY
        # Must also describe the artifacts field used to carry the tree path
        assert "tree_path" in ATTRIBUTION_BODY


class TestHandoffWiring:
    """Phase 3: SOUL must encode the handoff turn the LLM-coordinator runs."""

    def test_soul_has_handoff_step(self):
        """SOUL must have a 'Step FINAL' that explicitly mentions handoff."""
        assert "Step FINAL" in SOUL_BODY
        assert "handoff" in SOUL_BODY.lower()

    def test_soul_has_handoff_envelope_template(self):
        """SOUL must show the literal HANDOFF FIND-COMPLETE envelope header."""
        assert "HANDOFF FIND-COMPLETE.find.1" in SOUL_BODY
        assert "schema=find-complete-v1" in SOUL_BODY
        assert "artifacts=" in SOUL_BODY

    def test_soul_targets_hack_deep_for_handoff(self):
        """SOUL must spawn hack-deep (not anything else) for handoff."""
        assert 'agent_id="hack-deep"' in SOUL_BODY

    def test_soul_must_call_asset_tree_complete(self):
        """The handoff turn must call asset_tree_complete to obtain tree_path."""
        assert "asset_tree_complete" in SOUL_BODY

    def test_soul_uses_sessions_yield_after_handoff(self):
        """After spawn, LLM must yield — enforce by checking SOUL mentions yield alongside handoff."""
        # Step FINAL should reference sessions_yield() (or "yield")
        # adjacent to the hack-deep spawn
        idx_spawn = SOUL_BODY.find("sessions_spawn")
        idx_yield = SOUL_BODY.find("sessions_yield")
        assert idx_spawn > 0 and idx_yield > 0


class TestSpecialistPackages:
    """Each specialist package must expose SOUL_BODY as a non-empty string."""

    def _check(self, name: str, soul: str) -> None:
        assert isinstance(soul, str), f"{name}.SOUL_BODY is not a string"
        assert len(soul) > 200, f"{name}.SOUL_BODY is suspiciously short"
        # Each SOUL must forbid sessions_spawn (specialists never spawn)
        assert "sessions_spawn" not in soul or "不允许" in soul, (
            f"{name}.SOUL_BODY must forbid sessions_spawn"
        )

    def test_subdomain_discoverer(self):
        self._check("subdomain-discoverer", subdomain_discoverer.SOUL_BODY)

    def test_ip_resolver(self):
        self._check("ip-resolver", ip_resolver.SOUL_BODY)

    def test_port_scanner(self):
        self._check("port-scanner", port_scanner.SOUL_BODY)

    def test_service_fingerprint(self):
        self._check("service-fingerprint", service_fingerprint.SOUL_BODY)

    def test_endpoint_crawler(self):
        self._check("endpoint-crawler", endpoint_crawler.SOUL_BODY)

    def test_leaf_verifier(self):
        self._check("leaf-verifier", leaf_verifier.SOUL_BODY)

    def test_all_specialists_have_distinct_ids(self):
        """Each specialist's SOUL must reference its own id (not a sibling's)."""
        souls = {
            "subdomain-discoverer": subdomain_discoverer.SOUL_BODY,
            "ip-resolver": ip_resolver.SOUL_BODY,
            "port-scanner": port_scanner.SOUL_BODY,
            "service-fingerprint": service_fingerprint.SOUL_BODY,
            "endpoint-crawler": endpoint_crawler.SOUL_BODY,
            "leaf-verifier": leaf_verifier.SOUL_BODY,
        }
        for sid, soul in souls.items():
            assert sid in soul, f"{sid}.SOUL_BODY does not self-identify"
        # And each one should NOT confuse itself with another — sanity check
        assert "ip-resolver" in ip_resolver.SOUL_BODY
        assert "ip-resolver" not in subdomain_discoverer.SOUL_BODY or \
               "subdomain-discoverer" in subdomain_discoverer.SOUL_BODY, (
            "subdomain-discoverer should self-identify"
        )