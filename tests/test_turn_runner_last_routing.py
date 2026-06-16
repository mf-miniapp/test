"""Test the TurnRunner.last_routing audit snapshot.

The snapshot is what /healthz and /api/system/status read to surface
the routed endpoint. We verify the snapshot is set, is a copy (so
callers can't mutate runtime state), and survives the no-routed-tier
case.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from opensquilla.provider.selector import ModelSelector, ProviderConfig, SelectorConfig


class _FakeTurn:
    """Minimal duck-typed stand-in for TurnContext (we only read .model + .metadata)."""

    def __init__(self, model: str, tier: str | None = None) -> None:
        self.model = model
        self.metadata: dict = {"routed_tier": tier} if tier else {}


def _make_runner() -> object:
    """Return a bare object with the last_routing property.

    Avoids importing the real TurnRunner (which pulls in a heavy
    service graph). The property is just attribute access + copy.
    """
    from opensquilla.engine.runtime import TurnRunner

    # Bypass __init__ to skip service-graph wiring; only the property
    # matters here.
    runner = TurnRunner.__new__(TurnRunner)
    runner._last_routing = None
    return runner


def test_last_routing_none_initially() -> None:
    runner = _make_runner()
    assert runner.last_routing is None


def test_last_routing_returns_copy() -> None:
    runner = _make_runner()
    snapshot = {
        "tier": "c2",
        "model": "mimo-v2.5-pro",
        "provider": "mimo",
        "base_url": "https://token-plan-cn.xiaomimimo.com/v1",
        "tier_override_applied": True,
        "ts": 12345.0,
    }
    runner._last_routing = snapshot  # type: ignore[attr-defined]
    out = runner.last_routing
    assert out == snapshot
    # Mutating the returned dict must not affect the stored snapshot.
    out["tier"] = "MUTATED"
    assert runner._last_routing["tier"] == "c2"  # type: ignore[attr-defined]


def test_last_routing_field_shape() -> None:
    """Contract: the dict has exactly these keys."""
    runner = _make_runner()
    runner._last_routing = {  # type: ignore[attr-defined]
        "tier": "c3",
        "model": "mimo-v2.5-pro",
        "provider": "mimo",
        "base_url": "https://token-plan-cn.xiaomimimo.com/v1",
        "tier_override_applied": True,
        "ts": 999.0,
    }
    out = runner.last_routing
    assert set(out.keys()) == {
        "tier",
        "model",
        "provider",
        "base_url",
        "tier_override_applied",
        "ts",
    }
    assert out["tier"] == "c3"
    assert out["tier_override_applied"] is True


def test_model_selector_current_config_reflects_override() -> None:
    """End-to-end: override_primary_config flips current_config."""
    baseline = ProviderConfig(
        provider="openai",
        model="qwen3.6-35b",
        api_key="local-dev-key",
        base_url="http://127.0.0.1:9091/v1",
    )
    selector = ModelSelector(SelectorConfig(primary=baseline))
    assert selector.current_config.provider == "openai"
    assert selector.current_config.base_url == "http://127.0.0.1:9091/v1"

    selector.override_primary_config(
        ProviderConfig(
            provider="mimo",
            model="mimo-v2.5-pro",
            api_key="tp-secret",
            base_url="https://token-plan-cn.xiaomimimo.com/v1",
        )
    )
    assert selector.current_config.provider == "mimo"
    assert selector.current_config.base_url == "https://token-plan-cn.xiaomimimo.com/v1"
