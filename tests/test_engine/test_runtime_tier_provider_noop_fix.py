"""Regression: per-tier no-op short-circuit must still apply per-agent ep overlay.

Bug: when a per-agent ``provider``/``base_url``/``api_key`` is configured
(such as hack-deep → openai / 127.0.0.1:9091) and the routed tier's
config matches those fields, the old code returned ``None`` from
``_build_tier_provider_config`` and the cloned selector kept the
global baseline (MiMo), causing ``Param Incorrect: Not supported
model qwen3.6-35b`` errors when the request actually went to MiMo
with a qwen3.6-35b model field swapped in by ``override_model``.

Fix: ``_build_tier_provider_config`` now returns
``(None, post_overlay_baseline_pc)`` for the no-op case so the
caller can still apply the post-overlay baseline to the cloned
selector. ``resolve_tier_provider_config`` returns a
``(ProviderConfig, ProviderConfig)`` tuple.
"""
from __future__ import annotations

import pytest

from opensquilla.provider.selector import (
    ModelSelector,
    ProviderConfig,
    SelectorConfig,
    resolve_tier_provider_config,
)


def _build_pc(provider, base_url, api_key, model=""):
    return ProviderConfig(
        provider=provider, model=model, api_key=api_key, base_url=base_url,
        org_id="", proxy="", provider_routing={},
    )


def test_resolve_tier_provider_config_returns_tuple():
    """The function must return (ProviderConfig, baseline) not a bare ProviderConfig."""
    baseline = _build_pc("openai", "http://127.0.0.1:9091/v1", "local-dev-key")
    tier_cfg = {
        "model": "qwen3.6-35b", "provider": "openai",
        "base_url": "http://127.0.0.1:9091/v1", "api_key": "local-dev-key",
    }
    tier_pc, returned_baseline = resolve_tier_provider_config(tier_cfg, baseline)
    assert isinstance(tier_pc, ProviderConfig)
    assert isinstance(returned_baseline, ProviderConfig)
    assert returned_baseline is baseline, "baseline should be passed through unchanged"


def test_resolve_tier_provider_config_empty_tier_returns_tuple():
    """Empty tier_cfg path also returns the (tier_pc, baseline) tuple."""
    baseline = _build_pc("mimo", "https://token-plan-cn.xiaomimimo.com/v1", "tk-mimo")
    tier_pc, returned_baseline = resolve_tier_provider_config(None, baseline)
    assert tier_pc.provider == "mimo"
    assert returned_baseline is baseline


def test_no_op_short_circuit_keeps_per_agent_ep_visible_to_caller():
    """When tier fields == post-overlay baseline fields, the caller still needs
    to be able to apply the post-overlay baseline. The fix is that the function
    returns ``(None, post_overlay_baseline)`` instead of just ``None``.

    The hack-deep scenario: tier c0 has provider=openai, base_url=127.0.0.1:9091;
    the post-overlay baseline (from resolve_agent_endpoint('hack-deep')) also
    has provider=openai, base_url=127.0.0.1:9091; but the global
    ``cloned_selector._chain[0]`` has provider=mimo, base_url=token-plan.
    Without the fix, the no-op short-circuit returns ``None`` and the cloned
    selector keeps the global mimo endpoint → request goes to MiMo with a
    qwen3.6-35b model field → ``Param Incorrect: Not supported model``.
    """
    global_pc = _build_pc("mimo", "https://token-plan-cn.xiaomimimo.com/v1", "tk-mimo", model="mimo-v2.5-pro")
    per_agent_pc = _build_pc("openai", "http://127.0.0.1:9091/v1", "local-dev-key", model="qwen3.6-35b")

    selector = ModelSelector(SelectorConfig(primary=global_pc, fallbacks=[]))
    cloned = selector.clone()

    # 1) override_model(turn.model) — only swaps model field on chain[0]
    cloned.override_model(per_agent_pc.model)
    assert cloned._chain[0].provider == "mimo", "provider NOT swapped by override_model"
    assert cloned._chain[0].model == "qwen3.6-35b"

    # 2) Build baseline_pc by copying chain[0] and overlaying per-agent ep
    baseline_pc = _build_pc(
        cloned._chain[0].provider, cloned._chain[0].base_url,
        cloned._chain[0].api_key, cloned._chain[0].model,
    )
    baseline_pc = _build_pc(per_agent_pc.provider, baseline_pc.base_url, baseline_pc.api_key, baseline_pc.model)
    baseline_pc = _build_pc(baseline_pc.provider, per_agent_pc.base_url, baseline_pc.api_key, baseline_pc.model)
    baseline_pc = _build_pc(baseline_pc.provider, baseline_pc.base_url, per_agent_pc.api_key, baseline_pc.model)

    # 3) Build the tier_cfg (mimics [squilla_router.tiers.c0] block)
    tier_cfg = {
        "model": per_agent_pc.model,
        "provider": per_agent_pc.provider,
        "base_url": per_agent_pc.base_url,
        "api_key": per_agent_pc.api_key,
    }

    # 4) Run the function — should return (tier_pc, baseline_pc) where tier_pc
    #    has same fields as baseline_pc (the no-op case)
    tier_pc, returned_baseline = resolve_tier_provider_config(tier_cfg, baseline_pc)
    no_op = (
        tier_pc.provider == returned_baseline.provider
        and tier_pc.model == returned_baseline.model
        and tier_pc.api_key == returned_baseline.api_key
        and tier_pc.base_url == returned_baseline.base_url
    )
    assert no_op, "test precondition: tier_pc and baseline_pc should be identical"

    # 5) Caller logic: if tier_pc is None but baseline_pc is not, apply baseline.
    #    The fix returns (None, baseline_pc) for the no-op case so the caller
    #    can still apply the post-overlay baseline.
    if tier_pc is not None:
        cloned.override_primary_config(tier_pc)
    elif returned_baseline is not None:
        cloned.override_primary_config(returned_baseline)

    # 6) chain[0] must now be the per-agent endpoint, not the global mimo
    assert cloned._chain[0].provider == "openai"
    assert cloned._chain[0].base_url == "http://127.0.0.1:9091/v1"
    assert cloned._chain[0].api_key == "local-dev-key"
    assert cloned._chain[0].model == "qwen3.6-35b"


def test_non_no_op_tier_still_uses_tier_pc():
    """When tier has its own override (e.g. c2 → mimo), tier_pc is not None
    and the caller applies it directly."""
    baseline_pc = _build_pc("openai", "http://127.0.0.1:9091/v1", "local-dev-key", model="qwen3.6-35b")
    tier_cfg = {
        "model": "mimo-v2.5-pro", "provider": "mimo",
        "base_url": "https://token-plan-cn.xiaomimimo.com/v1", "api_key": "tk-mimo",
    }
    tier_pc, returned_baseline = resolve_tier_provider_config(tier_cfg, baseline_pc)
    assert tier_pc is not None
    assert tier_pc.provider == "mimo"
    assert tier_pc.base_url == "https://token-plan-cn.xiaomimimo.com/v1"
    assert returned_baseline is baseline_pc


def test_no_op_short_circuit_semantics_in_build_tier_provider_config():
    """``_build_tier_provider_config`` is the function that performs the no-op
    short-circuit and returns (tier_pc, baseline_pc). It is the call site in
    TurnRunner that audits ``tier_override_applied = tier_pc is not None``.
    That audit must stay ``False`` when the tier config matches the
    post-overlay baseline fields."""
    # Simulate the TurnRunner._build_tier_provider_config body inline
    def _build_tier_provider_config(tier_cfg, baseline_pc):
        # Early returns + resolve_tier_provider_config
        tier_pc, baseline_pc = resolve_tier_provider_config(tier_cfg, baseline_pc)
        # No-op short-circuit
        if (
            tier_pc.provider == baseline_pc.provider
            and tier_pc.model == baseline_pc.model
            and tier_pc.api_key == baseline_pc.api_key
            and tier_pc.base_url == baseline_pc.base_url
            and tier_pc.proxy == baseline_pc.proxy
        ):
            return None, baseline_pc
        return tier_pc, None

    # Non-no-op: tier has its own override
    baseline_pc = _build_pc("openai", "http://127.0.0.1:9091/v1", "local-dev-key", model="qwen3.6-35b")
    tier_cfg_override = {
        "model": "mimo-v2.5-pro", "provider": "mimo",
        "base_url": "https://token-plan-cn.xiaomimimo.com/v1", "api_key": "tk-mimo",
    }
    tier_pc, baseline_out = _build_tier_provider_config(tier_cfg_override, baseline_pc)
    assert tier_pc is not None, "tier overrode → audit tier_override_applied must be True"
    assert baseline_out is None

    # No-op: tier fields == post-overlay baseline fields
    baseline_pc2 = _build_pc("openai", "http://127.0.0.1:9091/v1", "local-dev-key", model="qwen3.6-35b")
    tier_cfg_match = {
        "model": "qwen3.6-35b", "provider": "openai",
        "base_url": "http://127.0.0.1:9091/v1", "api_key": "local-dev-key",
    }
    tier_pc2, baseline_out2 = _build_tier_provider_config(tier_cfg_match, baseline_pc2)
    assert tier_pc2 is None, "tier did NOT override → audit tier_override_applied must be False"
    assert baseline_out2 is not None, "but caller still needs the post-overlay baseline to apply"
    assert baseline_out2.provider == "openai"
    assert baseline_out2.base_url == "http://127.0.0.1:9091/v1"
