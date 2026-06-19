"""Regression: local openai base_url proof budget must accommodate 128k models.

Bug: ``_LOCAL_CTX_CEILING_TOKENS = 14_000`` was hard-coded for
llama-server ``-c 16384``, capping every local openai endpoint's
proof budget to 56k chars. With hack-deep's ~145k-char payload
(system_prompt + 151 tools) running on a qwen3.6-35b llama-server
with ``n_ctx=131072``, this caused
``provider_request_budget_exhausted`` and the turn died with
"Request is too large for the provider context window" — even
though the model can comfortably fit the payload.

Fix: bump ``_LOCAL_CTX_CEILING_TOKENS`` to 128_000 to match the
qwen3.6-35b 128k context window exposed on ``127.0.0.1:9091``.
"""
from __future__ import annotations

from opensquilla.provider.openai import (
    _LOCAL_CTX_CEILING_TOKENS,
    _is_local_openai_base_url,
    _local_proof_budget_chars,
)


def test_local_ctx_ceiling_is_at_least_128k():
    """The local openai ceiling must accommodate 128k context models."""
    assert _LOCAL_CTX_CEILING_TOKENS >= 128_000, (
        f"_LOCAL_CTX_CEILING_TOKENS={_LOCAL_CTX_CEILING_TOKENS} < 128_000; "
        "local 128k models will be mis-clamped to a smaller budget."
    )


def test_is_local_openai_base_url_detects_loopback():
    assert _is_local_openai_base_url("http://127.0.0.1:9091/v1") is True
    assert _is_local_openai_base_url("http://localhost:9091/v1") is True
    assert _is_local_openai_base_url("https://token-plan-cn.xiaomimimo.com/v1") is False


def test_local_proof_budget_chars_scales_with_ceiling():
    """The proof budget for a 128k local model must be 4 * 128_000 = 512_000 chars."""
    # 128k tokens * 4 chars/token = 512_000
    expected = _LOCAL_CTX_CEILING_TOKENS * 4
    actual = _local_proof_budget_chars("http://127.0.0.1:9091/v1", original=10_000_000)
    assert actual == expected, (
        f"local proof budget = {actual}, expected {expected} (= 128k tokens * 4 chars)."
    )


def test_local_proof_budget_chars_min_of_original_and_ceiling():
    """Smaller upstream budgets must still be respected (don't inflate)."""
    actual = _local_proof_budget_chars("http://127.0.0.1:9091/v1", original=10_000)
    assert actual == 10_000, "smaller upstream budget must not be inflated"


def test_remote_proof_budget_unchanged():
    """Remote endpoints must not be affected by the local clamp."""
    actual = _local_proof_budget_chars(
        "https://token-plan-cn.xiaomimimo.com/v1", original=10_000_000
    )
    assert actual == 10_000_000, "remote endpoint must not be clamped"
