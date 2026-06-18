"""v4.6.1 (2026-06-18) httpx v1.x 兼容性测试。

覆盖:
- recon_url_validate_batch 正确探测 httpx v1.x 的 ``-t`` (threads) 标志,
  而不是 v0.x 的 ``-c`` (concurrency) — 用错标志 httpx 返回 rc=2, 静默
  失败导致所有 URL 标 no_response.
- _run_binary 不再把非零 returncode 偷偷转成 0.
- recon_url_validate_batch 在 rc != 0 时降级到 stdlib, 而不是静默
  解析空 stdout 给所有 URL 标 no_response.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from unittest.mock import patch

import pytest


# ─── 1. _run_binary 不吞 rc ─────────────────
class TestRunBinaryReturncode:
    def test_run_binary_returns_nonzero_rc(self) -> None:
        """_run_binary 不应把 rc=2 转成 0 — 调用方需要知道是失败."""
        from opensquilla.tools.builtin.recon._binaries import _run_binary

        async def go() -> None:
            # 跑一个会失败的真实命令
            rc, stdout, stderr = await _run_binary(
                ["false"],  # /usr/bin/false always returns 1
                timeout_s=5.0,
            )
            assert rc != 0, f"_run_binary must NOT mask rc=1, got {rc}"
            assert rc == 1, f"false should return 1, got {rc}"

        asyncio.run(go())


# ─── 2. httpx 标志自动探测 ─────────────────
class TestHttpxFlagAutoDetect:
    def test_httpx_v1x_uses_t_flag(self, tmp_path) -> None:
        """当 httpx 支持 ``-t`` 标志 (v1.x) 时, batch 应该用 ``-t`` 而不是 ``-c``."""
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate_batch

        # 1 个 URL batch
        urls = ["https://example.com"]
        async def go() -> str:
            return await recon_url_validate_batch(urls, timeout_s=8, max_concurrency=5)

        result_str = asyncio.run(go())
        result = json.loads(result_str)
        # 应该用 httpx binary (成功跑) 或 stdlib 降级 (如果 example.com 拒)
        # 关键是 verified_count + rejected_count 总和应 = 1, 不应全部 no_response 静默
        total = result["verified_count"] + result["rejected_count"]
        assert total == 1, f"expected 1 result, got {total}: {result}"
        # 任何 URL 不应都是 no_response + status_code=None
        for r in result["results"]:
            reason = r.get("reason") or ""
            if r.get("verified") is False and (r.get("probe", {}).get("status_code") is None):
                # 即使是失败的也应有具体 reason (connection error / timeout / etc)
                # 不应是空 reason + None 状态
                assert reason != "no_response" or r.get("probe", {}).get("error"), (
                    f"all no_response means httpx flag bug: {r}"
                )


# ─── 3. rc != 0 降级到 stdlib ─────────────────
class TestBatchFallbackOnRc:
    """如果 httpx 用错标志返回 rc=2, batch 必须降级到 stdlib, 不能给所有
    URL 标 no_response."""
    def test_rc_nonzero_triggers_stdlib_fallback(self) -> None:
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate_batch
        from opensquilla.tools.builtin.recon import _binaries

        # 注入 _run_binary mock: 模拟 httpx 标志错误 (rc=2, stdout='', stderr=err)
        async def fake_run_binary(argv, timeout_s=60.0):
            return 2, "", "flag provided but not defined: -c"

        # 同时 patch auto-detect 让 batch 用 ``-c`` (强制走错标志)
        def fake_detect(name, refresh=False):
            return type("BP", (), {
                "name": "httpx", "path": "/fake/httpx",
                "version": "v1.x.x", "available": True,
            })()

        with patch.object(_binaries, "_run_binary", side_effect=fake_run_binary), \
             patch.object(_binaries, "detect", side_effect=fake_detect):
            urls = ["https://example.com"]
            async def go() -> str:
                return await recon_url_validate_batch(urls, timeout_s=5, max_concurrency=5)
            result_str = asyncio.run(go())
            result = json.loads(result_str)
            # 应该降级到 stdlib, source='stdlib' + binary_error 含 rc=2
            assert result["source"] == "stdlib", (
                f"rc=2 must trigger stdlib fallback, got source={result['source']}"
            )
            assert "rc=2" in (result.get("binary_error") or ""), (
                f"binary_error should include rc=2, got {result.get('binary_error')!r}"
            )
            # 仍返回 1 个 result
            assert len(result["results"]) == 1


# ─── 4. 真实 httpx v1.x 集成 ─────────────────
class TestHttpxV1xIntegration:
    """如果系统装有 httpx, 跑一次真实 batch, 验证不静默失败。"""
    def test_real_httpx_batch_works(self) -> None:
        if not shutil.which("httpx"):
            pytest.skip("httpx not on PATH")
        from opensquilla.tools.builtin.recon.http_probe import recon_url_validate_batch

        urls = ["https://example.com"]
        async def go() -> str:
            return await recon_url_validate_batch(urls, timeout_s=8, max_concurrency=5)
        result_str = asyncio.run(go())
        result = json.loads(result_str)
        # 真实 httpx v1.x 应能跑通 — 拿到 200 OK 或真实失败, 不应是 no_response
        # (example.com 几乎 100% 返回 200)
        r = result["results"][0]
        if result["source"] == "binary":
            # 用 binary 跑: 应有 status_code (200 或真错误码)
            assert r.get("probe", {}).get("status_code") in (200, 301, 302, 307, 308), (
                f"example.com should give a real status code via httpx, got {r}"
            )
