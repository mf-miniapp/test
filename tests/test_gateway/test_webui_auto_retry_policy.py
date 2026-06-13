"""Tests for the WebUI auto-retry policy (webui_auto_retry_max_rounds +
webui_auto_retry_on_kinds).

The auto-retry is purely client-side (chat.js re-issues chat.send on the
same session) but its policy is server-issued via the WS HelloOk
``PolicyInfo`` block, mirroring the existing webui_stream_idle_grace
pattern. This file covers:

1. GatewayConfig defaults and env-var overrides.
2. Pydantic Field constraint enforcement (ge=0, le=8).
3. PolicyInfo defaults (wire format).
4. HelloOk builder plumbing (the websocket.py block that maps the config
   into the JSON the browser actually receives).
5. Lossless TOML round-trip via ``GatewayConfig.load_from_toml``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from opensquilla.gateway.config import GatewayConfig
from opensquilla.gateway.protocol import HelloOk, PolicyInfo


# Env-var prefix used by GatewayConfig (pydantic-settings env_prefix).
ENV_PREFIX = "OPENSQUILLA_GATEWAY_"
ENV_MAX = f"{ENV_PREFIX}WEBUI_AUTO_RETRY_MAX_ROUNDS"
ENV_KINDS = f"{ENV_PREFIX}WEBUI_AUTO_RETRY_ON_KINDS"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defaults: max_rounds=2, kinds covers the four user-confirmed buckets."""
    monkeypatch.delenv(ENV_MAX, raising=False)
    monkeypatch.delenv(ENV_KINDS, raising=False)
    config = GatewayConfig()
    assert config.webui_auto_retry_max_rounds == 2
    assert list(config.webui_auto_retry_on_kinds) == [
        "empty_response",
        "context_overflow",
        "timeout",
        "rate_limit",
        "5xx",
    ]


# ---------------------------------------------------------------------------
# Field validation (Pydantic Field constraints)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, 1, 2, 4, 8])
def test_max_rounds_constructor_accepted(value: int) -> None:
    """Field constraint ``le=8`` / ``ge=0`` accepts the inclusive range."""
    config = GatewayConfig(webui_auto_retry_max_rounds=value)
    assert config.webui_auto_retry_max_rounds == value


@pytest.mark.parametrize("value", [9, 100, 9999])
def test_max_rounds_above_max_rejected(value: int) -> None:
    """Field constraint ``le=8`` rejects values above 8."""
    with pytest.raises(ValidationError) as exc_info:
        GatewayConfig(webui_auto_retry_max_rounds=value)
    assert "less_than_equal" in str(exc_info.value).lower()


@pytest.mark.parametrize("value", [-1, -100])
def test_max_rounds_negative_rejected(value: int) -> None:
    """Field constraint ``ge=0`` rejects negative values."""
    with pytest.raises(ValidationError) as exc_info:
        GatewayConfig(webui_auto_retry_max_rounds=value)
    assert "greater_than_equal" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Env-var overrides (pydantic-settings)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "1", "2", "4", "8"])
def test_max_rounds_env_accepted(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Env-var override of max_rounds is honored within the inclusive range."""
    monkeypatch.setenv(ENV_MAX, value)
    config = GatewayConfig()
    assert config.webui_auto_retry_max_rounds == int(value)


def test_max_rounds_env_above_max_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Env-var path also enforces le=8 — invalid configs fail loud, not silent."""
    monkeypatch.setenv(ENV_MAX, "9")
    with pytest.raises(ValidationError):
        GatewayConfig()


def test_max_rounds_env_negative_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Env-var path also enforces ge=0."""
    monkeypatch.setenv(ENV_MAX, "-1")
    with pytest.raises(ValidationError):
        GatewayConfig()


def test_kinds_env_json_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pydantic-settings expects JSON for list fields. Operators that
    set this env var must use the JSON form."""
    monkeypatch.setenv(ENV_KINDS, '["empty_response", "timeout"]')
    config = GatewayConfig()
    assert list(config.webui_auto_retry_on_kinds) == ["empty_response", "timeout"]


# ---------------------------------------------------------------------------
# PolicyInfo wire format
# ---------------------------------------------------------------------------


def test_policy_info_defaults_match_gateway_defaults() -> None:
    """PolicyInfo (the WS hello payload) must carry the same defaults as
    GatewayConfig so an empty GatewayConfig still gives the browser a
    usable policy."""
    info = PolicyInfo()
    assert info.webui_auto_retry_max_rounds == 2
    assert info.webui_auto_retry_on_kinds == [
        "empty_response",
        "context_overflow",
        "timeout",
        "rate_limit",
        "5xx",
    ]


def test_policy_info_serialization_carries_both_fields() -> None:
    """Round-trip through JSON must preserve both new fields so the
    browser receives them on the hello frame."""
    info = PolicyInfo(
        webui_auto_retry_max_rounds=3,
        webui_auto_retry_on_kinds=["empty_response", "timeout"],
    )
    dumped = json.loads(info.model_dump_json())
    assert dumped["webui_auto_retry_max_rounds"] == 3
    assert dumped["webui_auto_retry_on_kinds"] == ["empty_response", "timeout"]


# ---------------------------------------------------------------------------
# HelloOk builder plumbing
# ---------------------------------------------------------------------------


def test_hello_ok_carries_auto_retry_fields() -> None:
    """The HelloOk model accepts the new fields on the policy block, so
    websocket.py's builder can populate them inline. We construct a
    minimal HelloOk (matching the structure websocket.py emits) and
    verify the JSON contains the new keys."""
    from opensquilla.gateway.protocol import (
        FeaturesInfo,
        ServerInfo,
        SnapshotInfo,
    )

    hello = HelloOk(
        protocol=1,
        server=ServerInfo(version="test", conn_id="cid"),
        features=FeaturesInfo(methods=[], events=[]),
        snapshot=SnapshotInfo(),
        policy=PolicyInfo(
            webui_auto_retry_max_rounds=2,
            webui_auto_retry_on_kinds=[
                "empty_response",
                "context_overflow",
                "timeout",
                "rate_limit",
                "5xx",
            ],
        ),
    )
    payload = json.loads(hello.model_dump_json())
    assert "policy" in payload
    assert payload["policy"]["webui_auto_retry_max_rounds"] == 2
    assert payload["policy"]["webui_auto_retry_on_kinds"] == [
        "empty_response",
        "context_overflow",
        "timeout",
        "rate_limit",
        "5xx",
    ]


# ---------------------------------------------------------------------------
# TOML round-trip
# ---------------------------------------------------------------------------


def test_toml_round_trip_preserves_auto_retry(tmp_path: Path) -> None:
    """Writing the two new keys to TOML and reloading yields the same
    values, so operators can tune them via opensquilla.toml."""
    toml_path = tmp_path / "opensquilla.toml"
    toml_path.write_text(
        'webui_auto_retry_max_rounds = 4\n'
        'webui_auto_retry_on_kinds = ["empty_response", "timeout", "5xx"]\n',
        encoding="utf-8",
    )
    cfg = GatewayConfig.load_from_toml(toml_path)
    assert cfg.webui_auto_retry_max_rounds == 4
    assert list(cfg.webui_auto_retry_on_kinds) == [
        "empty_response",
        "timeout",
        "5xx",
    ]


def test_toml_round_trip_with_zero_disables(
    tmp_path: Path,
) -> None:
    """``webui_auto_retry_max_rounds = 0`` disables auto-retry entirely."""
    toml_path = tmp_path / "opensquilla.toml"
    toml_path.write_text(
        'webui_auto_retry_max_rounds = 0\n',
        encoding="utf-8",
    )
    cfg = GatewayConfig.load_from_toml(toml_path)
    assert cfg.webui_auto_retry_max_rounds == 0
