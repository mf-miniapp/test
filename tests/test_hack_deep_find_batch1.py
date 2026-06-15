"""Batch 1 specialist + schema + asset tree wiring tests.

Validates:
  - All 5 new specialist subpackages import + load SOUL_BODY
  - All 5 new schemas are present in ATTRIBUTION_BODY
  - SOUL_BODY documents the new specialist table + Step N.5 layered loop
  - All 17 new tools are registered in default tool registry
  - Asset tree models accept Batch 1 parent-child relationships
"""

from __future__ import annotations

import importlib

import pytest

_pkg = importlib.import_module("opensquilla.agents.hack-deep-find")
SOUL_BODY = _pkg.SOUL_BODY
ATTRIBUTION_BODY = _pkg.ATTRIBUTION_BODY
_specialists_pkg = importlib.import_module(
    "opensquilla.agents.hack-deep-find.specialists"
)
service_detailed = _specialists_pkg.service_detailed
webapp_discoverer = _specialists_pkg.webapp_discoverer
api_surface = _specialists_pkg.api_surface
parameter_extract = _specialists_pkg.parameter_extract
static_asset = _specialists_pkg.static_asset


# ── SOUL_BODY contract ──────────────────────────────

class TestSoulMentionsBatch1:
    def test_soul_mentions_11_specialists(self):
        assert "11 个" in SOUL_BODY or "11 specialist" in SOUL_BODY

    def test_soul_lists_all_5_new_specialists(self):
        for sid in (
            "service-detailed",
            "webapp-discoverer",
            "api-surface",
            "parameter-extract",
            "static-asset",
        ):
            assert sid in SOUL_BODY, f"SOUL_BODY missing specialist: {sid}"

    def test_soul_documents_step_n5_layered_loop(self):
        assert "Step N.5" in SOUL_BODY
        assert "分层调度" in SOUL_BODY

    def test_soul_documents_dual_specialist_parallel(self):
        assert "双 specialist" in SOUL_BODY
        assert "service-detailed" in SOUL_BODY and "webapp-discoverer" in SOUL_BODY
        assert "api-surface" in SOUL_BODY and "static-asset" in SOUL_BODY

    def test_soul_documents_global_limits(self):
        assert "16" in SOUL_BODY
        assert "64" in SOUL_BODY

    def test_soul_documents_url_value_convention(self):
        assert "URL 节点 value 约定" in SOUL_BODY
        assert "{scheme}://{host}:{port}{base_path}" in SOUL_BODY

    def test_soul_documents_dedupe_rules(self):
        assert "dedupe" in SOUL_BODY.lower()

    def test_soul_documents_termination_with_11_layers(self):
        for layer in ("URL", "API_SCHEMA", "PARAMETER", "STATIC_ASSET", "COMPONENT"):
            assert layer in SOUL_BODY, f"Termination report missing: {layer}"


# ── ATTRIBUTION_BODY contract ───────────────────────

class TestAttributionMentionsBatch1:
    def test_attribution_has_5_new_schemas(self):
        for sname in (
            "component-v1",
            "webapp-v1",
            "api-surface-v1",
            "parameter-v1",
            "static-asset-v1",
        ):
            assert sname in ATTRIBUTION_BODY, f"Missing schema: {sname}"

    def test_attribution_documents_component_v1(self):
        assert "cve_relevant" in ATTRIBUTION_BODY

    def test_attribution_documents_webapp_v1(self):
        assert "discovery_mode" in ATTRIBUTION_BODY
        assert "vhost" in ATTRIBUTION_BODY
        assert "siblings_count" in ATTRIBUTION_BODY

    def test_attribution_documents_api_surface_v1(self):
        assert "api_schemas" in ATTRIBUTION_BODY
        assert "api_schema_id" in ATTRIBUTION_BODY

    def test_attribution_documents_parameter_v1(self):
        assert "inferred_type" in ATTRIBUTION_BODY
        assert "sensitivity" in ATTRIBUTION_BODY

    def test_attribution_documents_static_asset_v1(self):
        assert "aws_access_key_id" in ATTRIBUTION_BODY
        assert "vcs_exposed" in ATTRIBUTION_BODY

    def test_attribution_registry_has_11_specialists(self):
        phase2_ids = ["subdomain-discoverer", "ip-resolver", "port-scanner", "service-fingerprint", "endpoint-crawler", "leaf-verifier"]
        batch1_ids = ["service-detailed", "webapp-discoverer", "api-surface", "parameter-extract", "static-asset"]
        for sid in phase2_ids + batch1_ids:
            assert sid in ATTRIBUTION_BODY, f"Registry missing: {sid}"


# ── specialist subpackage contract ──────────────────

class TestBatch1SpecialistPackages:
    def test_service_detailed(self):
        assert isinstance(service_detailed.SOUL_BODY, str)
        assert "service-detailed" in service_detailed.SOUL_BODY
        assert "component-v1" in service_detailed.SOUL_BODY
        assert "严禁" in service_detailed.SOUL_BODY
        assert "RESULT MARKER" in service_detailed.SOUL_BODY

    def test_webapp_discoverer(self):
        assert isinstance(webapp_discoverer.SOUL_BODY, str)
        assert "webapp-discoverer" in webapp_discoverer.SOUL_BODY
        assert "webapp-v1" in webapp_discoverer.SOUL_BODY
        assert "vhost" in webapp_discoverer.SOUL_BODY

    def test_api_surface(self):
        assert isinstance(api_surface.SOUL_BODY, str)
        assert "api-surface" in api_surface.SOUL_BODY
        assert "api-surface-v1" in api_surface.SOUL_BODY

    def test_parameter_extract(self):
        assert isinstance(parameter_extract.SOUL_BODY, str)
        assert "parameter-extract" in parameter_extract.SOUL_BODY
        assert "parameter-v1" in parameter_extract.SOUL_BODY
        assert "不生产 INJECTION_VECTOR" in parameter_extract.SOUL_BODY

    def test_static_asset(self):
        assert isinstance(static_asset.SOUL_BODY, str)
        assert "static-asset" in static_asset.SOUL_BODY
        assert "static-asset-v1" in static_asset.SOUL_BODY


# ── Tool registry contract ──────────────────────────

class TestBatch1ToolsRegistered:
    def _expected_17(self):
        return [
            "recon_vhost_bruteforce", "recon_robots_sitemap",
            "recon_tech_detect", "recon_app_fingerprint", "recon_url_dedupe",
            "recon_openapi_parse", "recon_graphql_introspect",
            "recon_js_crawl_recursive", "recon_api_path_normalize", "recon_auth_probe",
            "recon_cpe_resolve", "recon_js_component_extract",
            "recon_tls_cert_parse", "recon_ico_hash_lookup",
            "recon_sensitive_fingerprint", "recon_sensitive_variants", "recon_secret_extract",
        ]

    def test_all_17_tools_in_registry(self):
        from opensquilla.tools.registry import get_default_registry

        reg = get_default_registry()
        names = set(reg.list_names())
        missing = [n for n in self._expected_17() if n not in names]
        assert not missing, f"Tools not registered: {missing}"


# ── Asset tree model contract ───────────────────────

class TestAssetTreeAcceptsBatch1Relationships:
    def test_service_can_have_component(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.SERVICE, AssetType.COMPONENT)

    def test_service_can_have_url(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.SERVICE, AssetType.URL)

    def test_url_can_have_endpoint(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.URL, AssetType.ENDPOINT)

    def test_url_can_have_api_schema(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.URL, AssetType.API_SCHEMA)

    def test_url_can_have_static_asset(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.URL, AssetType.STATIC_ASSET)

    def test_url_can_have_component(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.URL, AssetType.COMPONENT)

    def test_endpoint_can_have_parameter(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        validate_parent_child(AssetType.ENDPOINT, AssetType.PARAMETER)

    def test_invalid_parent_child_still_raises(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child

        with pytest.raises(ValueError):
            validate_parent_child(AssetType.ENDPOINT, AssetType.COMPONENT)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
