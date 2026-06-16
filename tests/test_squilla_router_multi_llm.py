"""Tests for the squilla_router multi-endpoint feature.

When ``[squilla_router.tiers.<tier>]`` carries a ``provider`` /
``base_url`` / ``api_key`` override, the router must resolve the
routed tier into a ``ProviderConfig`` that swaps the active
endpoint. Tiers that don't override anything fall back to the
global baseline.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from opensquilla.provider.selector import (
    ModelSelector,
    ProviderConfig,
    resolve_tier_provider_config,
)


def _baseline() -> ProviderConfig:
    return ProviderConfig(
        provider="openai",
        model="qwen3.6-35b",
        api_key="local-dev-key",
        base_url="http://127.0.0.1:9091/v1",
        proxy="",
    )


def test_resolve_tier_provider_config_no_tier_returns_baseline() -> None:
    """No tier config → caller gets the baseline verbatim."""
    base = _baseline()
    out = resolve_tier_provider_config(None, base)
    assert out == base
    # copies, not the same object — so caller mutations don't leak
    assert out is not base


def test_resolve_tier_provider_config_empty_tier_returns_baseline() -> None:
    base = _baseline()
    out = resolve_tier_provider_config({}, base)
    assert out.provider == base.provider
    assert out.model == base.model
    assert out.base_url == base.base_url


def test_resolve_tier_provider_config_full_override() -> None:
    """Tier overrides provider + model + base_url + api_key."""
    base = _baseline()
    tier = {
        "provider": "mimo",
        "model": "mimo-v2.5-pro",
        "base_url": "https://token-plan-cn.xiaomimimo.com/v1",
        "api_key": "tp-secret",
    }
    out = resolve_tier_provider_config(tier, base)
    assert out.provider == "mimo"
    assert out.model == "mimo-v2.5-pro"
    assert out.base_url == "https://token-plan-cn.xiaomimimo.com/v1"
    assert out.api_key == "tp-secret"


def test_resolve_tier_provider_config_partial_override_inherits() -> None:
    """Tier overrides only the model; provider/base_url/api_key stay."""
    base = _baseline()
    tier = {"model": "qwen3.6-35b-fast"}
    out = resolve_tier_provider_config(tier, base)
    assert out.model == "qwen3.6-35b-fast"
    assert out.provider == base.provider
    assert out.base_url == base.base_url
    assert out.api_key == base.api_key


def test_resolve_tier_provider_config_accepts_object_form() -> None:
    """Tier may also arrive as a pydantic-ish object (not a dict)."""
    base = _baseline()
    tier = SimpleNamespace(
        provider="mimo",
        model="mimo-v2.5-pro",
        base_url="https://token-plan-cn.xiaomimimo.com/v1",
        api_key="tp-secret",
        api_key_env="",
        org_id="",
        proxy="",
        provider_routing={},
    )
    out = resolve_tier_provider_config(tier, base)
    assert out.provider == "mimo"
    assert out.base_url == "https://token-plan-cn.xiaomimimo.com/v1"


def test_model_selector_override_primary_config_swaps_provider() -> None:
    """override_primary_config replaces _chain[0] with a new ProviderConfig."""
    base = _baseline()
    selector = ModelSelector(_SelectorConfigStub(primary=base))
    new_pc = ProviderConfig(
        provider="mimo",
        model="mimo-v2.5-pro",
        api_key="tp-secret",
        base_url="https://token-plan-cn.xiaomimimo.com/v1",
    )
    selector.override_primary_config(new_pc)
    assert selector._chain[0] is new_pc
    # _config.primary is intentionally NOT mutated (that would leak
    # across clones).
    assert selector._config.primary is base


def test_model_selector_clone_independent_after_override() -> None:
    """Clones must not see per-tier overrides — that's the whole point."""
    base = _baseline()
    parent = ModelSelector(_SelectorConfigStub(primary=base))
    clone = parent.clone()

    parent.override_primary_config(
        ProviderConfig(
            provider="mimo",
            model="mimo-v2.5-pro",
            api_key="tp-secret",
            base_url="https://token-plan-cn.xiaomimimo.com/v1",
        )
    )
    assert parent._chain[0].provider == "mimo"
    assert clone._chain[0].provider == "openai"  # baseline still


def test_resolve_tier_provider_config_provider_routing_override() -> None:
    """Tier may also override provider_routing (dict merge)."""
    base = ProviderConfig(
        provider="openai",
        model="qwen3.6-35b",
        api_key="k",
        base_url="http://localhost/v1",
        provider_routing={"old/old": "old"},
    )
    tier = {
        "model": "mimo-v2.5-pro",
        "provider_routing": {"new/new": "new"},
    }
    out = resolve_tier_provider_config(tier, base)
    # provider_routing should be fully replaced (not merged) — the
    # tier is the source of truth for its own routing
    assert out.provider_routing == {"new/new": "new"}


class _SelectorConfigStub:
    """Minimal duck-typed stand-in for SelectorConfig.

    ModelSelector only reads ``primary`` and ``fallbacks``; we
    don't need the real dataclass here.
    """

    def __init__(self, primary: ProviderConfig, fallbacks: list | None = None) -> None:
        self.primary = primary
        self.fallbacks = list(fallbacks or [])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
