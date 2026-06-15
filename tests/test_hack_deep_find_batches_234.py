"""Batch 2/3/4 specialist + schema + asset tree + tool wiring tests.

Validates:
  - 6 new specialists (auth-mapper, cookie-header, cloud-storage,
    secret-scanner, seed-expander) import + load SOUL_BODY
  - 4 new schemas (auth-surface-v1, cookie-header-v1, cloud-storage-v1,
    secret-v1, seed-v1) present in ATTRIBUTION_BODY
  - SOUL_BODY documents the new specialist tables + Step 0 multi-seed
  - All 26 new tools registered (5 auth + 4 header + 6 storage +
    6 secret + 5 seed)
  - asset_tree_create accepts extra_seeds parameter
  - asset_tree_merge registered as a tool
  - Asset tree models accept Batch 2/3 parent-child relationships
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
auth_mapper = _specialists_pkg.auth_mapper
cookie_header = _specialists_pkg.cookie_header
cloud_storage = _specialists_pkg.cloud_storage
secret_scanner = _specialists_pkg.secret_scanner
seed_expander = _specialists_pkg.seed_expander


# ── SOUL_BODY contract ──────────────────────────────

class TestSoulMentionsBatches234:
    def test_soul_mentions_16_specialists(self):
        assert "16" in SOUL_BODY

    def test_soul_lists_5_new_specialists(self):
        for sid in ("auth-mapper", "cookie-header", "cloud-storage", "secret-scanner", "seed-expander"):
            assert sid in SOUL_BODY, f"SOUL_BODY missing specialist: {sid}"

    def test_soul_documents_step0_multi_seed(self):
        assert "extra_seeds" in SOUL_BODY
        assert "seed-expander" in SOUL_BODY

    def test_soul_documents_url_layer_4_parallel(self):
        # URL layer 4-specialist parallel: api-surface, static-asset, auth-mapper, cookie-header
        assert all(s in SOUL_BODY for s in ("api-surface", "static-asset", "auth-mapper", "cookie-header"))

    def test_soul_documents_subdomain_layer_2_parallel(self):
        # SUB_DOMAIN layer: ip-resolver + cloud-storage
        assert "ip-resolver" in SOUL_BODY and "cloud-storage" in SOUL_BODY

    def test_soul_documents_root_domain_layer_2(self):
        # ROOT_DOMAIN layer: subdomain-discoverer + seed-expander
        assert "subdomain-discoverer" in SOUL_BODY and "seed-expander" in SOUL_BODY

    def test_soul_documents_asset_tree_merge(self):
        assert "asset_tree_merge" in SOUL_BODY

    def test_soul_documents_termination_with_all_layers(self):
        for layer in ("AUTH_SURFACE", "COOKIE", "HEADER", "STORAGE", "STORAGE_OBJECT", "SECRET"):
            assert layer in SOUL_BODY, f"Termination report missing: {layer}"


# ── ATTRIBUTION_BODY contract ───────────────────────

class TestAttributionMentionsBatches234:
    def test_attribution_has_5_new_schemas(self):
        for sname in ("auth-surface-v1", "cookie-header-v1", "cloud-storage-v1", "secret-v1", "seed-v1"):
            assert sname in ATTRIBUTION_BODY, f"Missing schema: {sname}"

    def test_attribution_documents_auth_surface_v1(self):
        assert "auth_schemes" in ATTRIBUTION_BODY
        assert "default_creds" in ATTRIBUTION_BODY

    def test_attribution_documents_cookie_header_v1(self):
        assert "value_preview" in ATTRIBUTION_BODY
        assert "disclosure_kind" in ATTRIBUTION_BODY

    def test_attribution_documents_cloud_storage_v1(self):
        assert "objects_count" in ATTRIBUTION_BODY
        assert "sensitive_kind" in ATTRIBUTION_BODY

    def test_attribution_documents_secret_v1(self):
        assert "blast_radius" in ATTRIBUTION_BODY
        assert "internal_host" in ATTRIBUTION_BODY

    def test_attribution_documents_seed_v1(self):
        assert "extra_seeds" in ATTRIBUTION_BODY or "seeds" in ATTRIBUTION_BODY

    def test_attribution_registry_has_16_specialists(self):
        ids = [
            "subdomain-discoverer", "ip-resolver", "port-scanner",
            "service-fingerprint", "endpoint-crawler", "leaf-verifier",
            "service-detailed", "webapp-discoverer", "api-surface",
            "parameter-extract", "static-asset",
            "auth-mapper", "cookie-header",
            "cloud-storage", "secret-scanner",
            "seed-expander",
        ]
        for sid in ids:
            assert sid in ATTRIBUTION_BODY, f"Registry missing: {sid}"


# ── specialist subpackage contract ──────────────────

class TestBatch234SpecialistPackages:
    def test_auth_mapper(self):
        assert isinstance(auth_mapper.SOUL_BODY, str)
        assert "auth-mapper" in auth_mapper.SOUL_BODY
        assert "auth-surface-v1" in auth_mapper.SOUL_BODY
        assert "严禁" in auth_mapper.SOUL_BODY

    def test_cookie_header(self):
        assert isinstance(cookie_header.SOUL_BODY, str)
        assert "cookie-header" in cookie_header.SOUL_BODY
        assert "cookie-header-v1" in cookie_header.SOUL_BODY

    def test_cloud_storage(self):
        assert isinstance(cloud_storage.SOUL_BODY, str)
        assert "cloud-storage" in cloud_storage.SOUL_BODY
        assert "cloud-storage-v1" in cloud_storage.SOUL_BODY

    def test_secret_scanner(self):
        assert isinstance(secret_scanner.SOUL_BODY, str)
        assert "secret-scanner" in secret_scanner.SOUL_BODY
        assert "secret-v1" in secret_scanner.SOUL_BODY
        # Cross-layer specialist
        assert "跨层" in secret_scanner.SOUL_BODY or "cross-layer" in secret_scanner.SOUL_BODY.lower()

    def test_seed_expander(self):
        assert isinstance(seed_expander.SOUL_BODY, str)
        assert "seed-expander" in seed_expander.SOUL_BODY
        assert "seed-v1" in seed_expander.SOUL_BODY
        # Doesn't write to AssetTree
        assert "不写 AssetTree" in seed_expander.SOUL_BODY or "不进 AssetTree" in seed_expander.SOUL_BODY


# ── Tool registry contract ──────────────────────────

class TestBatch234ToolsRegistered:
    def _expected_26(self):
        return [
            # group:recon:auth (5)
            "recon_auth_endpoint_discover",
            "recon_oauth_flow_probe",
            "recon_jwt_analyze",
            "recon_default_creds_probe",
            "recon_auth_form_parse",
            # group:recon:header (4)
            "recon_cookie_security_parse",
            "recon_security_header_audit",
            "recon_info_disclosure_header_scan",
            "recon_cookie_jar_collect",
            # group:recon:storage (6)
            "recon_bucket_naming_variants",
            "recon_s3_check",
            "recon_oss_check",
            "recon_gcs_check",
            "recon_azure_blob_check",
            "recon_bucket_list_objects",
            # group:recon:secret (6)
            "recon_secret_scan_text",
            "recon_secret_scan_js_bundle",
            "recon_secret_scan_git_history",
            "recon_secret_scan_env_dump",
            "recon_secret_classify",
            "recon_secret_validate_aws_key",
            # group:recon:seed (5)
            "recon_whois_lookup",
            "recon_asn_lookup",
            "recon_ct_subdomain_enum",
            "recon_passive_dns",
            "recon_related_domain_mining",
        ]

    def test_all_26_new_tools_in_registry(self):
        from opensquilla.tools.registry import get_default_registry

        reg = get_default_registry()
        names = set(reg.list_names())
        missing = [n for n in self._expected_26() if n not in names]
        assert not missing, f"Tools not registered: {missing}"


# ── Asset tree contract ─────────────────────────────

class TestAssetTreeAcceptsBatch234:
    def test_url_can_have_auth_surface(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child
        validate_parent_child(AssetType.URL, AssetType.AUTH_SURFACE)

    def test_url_can_have_cookie(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child
        validate_parent_child(AssetType.URL, AssetType.COOKIE)

    def test_url_can_have_header(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child
        validate_parent_child(AssetType.URL, AssetType.HEADER)

    def test_sub_domain_can_have_storage(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child
        validate_parent_child(AssetType.SUB_DOMAIN, AssetType.STORAGE)

    def test_storage_can_have_storage_object(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child
        validate_parent_child(AssetType.STORAGE, AssetType.STORAGE_OBJECT)

    def test_secret_cross_layer_allowed_from_all(self):
        from opensquilla.asset_tree.models import AssetType, validate_parent_child
        for parent in (
            AssetType.SUB_DOMAIN, AssetType.IP, AssetType.SERVICE,
            AssetType.URL, AssetType.STATIC_ASSET, AssetType.API_SCHEMA,
            AssetType.STORAGE, AssetType.STORAGE_OBJECT,
        ):
            validate_parent_child(parent, AssetType.SECRET)


# ── asset_tree_create extended + asset_tree_merge ────

class TestAssetTreeToolsBatch4:
    def test_asset_tree_create_accepts_extra_seeds(self):
        import inspect
        from opensquilla.tools.builtin.asset_tree import tree as tree_tools
        sig = inspect.signature(tree_tools.asset_tree_create)
        assert "extra_seeds" in sig.parameters

    def test_asset_tree_merge_is_registered_tool(self):
        from opensquilla.tools.registry import get_default_registry
        from opensquilla.tools.builtin.asset_tree import tree as tree_tools

        # Function exists
        assert callable(tree_tools.asset_tree_merge)
        # Registered in default tool registry
        reg = get_default_registry()
        assert "asset_tree_merge" in reg.list_names()

    def test_asset_tree_merge_signature(self):
        import inspect
        from opensquilla.tools.builtin.asset_tree import tree as tree_tools
        sig = inspect.signature(tree_tools.asset_tree_merge)
        params = list(sig.parameters.keys())
        assert "target_tree_id" in params
        assert "source_tree_ids" in params
        assert "create_target_if_missing" in params


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
