"""v6 (2026-06-19) SessionsSpawnDispatcher 单测。

覆盖:
  - envelope 拼装正确 (handoff_id, schema, deps)
  - LLM response 收集 (流式 text_delta 拼接)
  - result marker 解析
  - 漏洞提取 + 写入 (用 stub vuln_extractor + stub vuln_writer)
  - 失败隔离: LLM error / marker missing / writer 抛异常 → AttackPathOutcome(failed)
  - 缺 vuln_extractor: 不报错, vuln_count=0
"""
from __future__ import annotations

import asyncio
import json
import pytest
from typing import Any, AsyncIterator

from opensquilla.attack_dispatch.envelope import (
    EnvelopeFormatError,
    parse_envelope,
)
from opensquilla.attack_dispatch.envelope import parse_result_marker, ResultFormatError
from opensquilla.attack_dispatch.envelope import (
    EnvelopeFormatError, parse_envelope,
    ResultStatus,
    parse_result_marker,
)
from opensquilla.orchestrator.dispatchers import (
    InlineDispatcher,
    InlineOutcome,
    SessionsSpawnDispatcher,
    SessionsSpawnDispatcherOptions,
)
from opensquilla.orchestrator.run_attack_paths import AttackPathOutcome
from opensquilla.provider.types import ChatConfig, Message, StreamEvent, TextDeltaEvent, DoneEvent, ErrorEvent


# ── Mock Provider ─────────────────────────────────────────


class _MockProvider:
    """根据 path_id 返回预设响应; 模拟流式 chat。"""

    def __init__(self, responses: dict[str, str] | None = None,
                 raise_error: Exception | None = None) -> None:
        self.responses = responses or {}
        self.raise_error = raise_error
        self.calls: list[dict] = []

    @property
    def provider_name(self) -> str:
        return "mock"

    async def list_models(self):
        return []

    async def chat(
        self,
        messages: list[Message],
        tools=None,
        config: ChatConfig | None = None,
    ) -> AsyncIterator[StreamEvent]:
        self.calls.append({
            "messages": messages, "config": config,
        })
        if self.raise_error:
            raise self.raise_error
        # 找 path_id from task (messages[1].content)
        task = messages[0].content if messages else ""
        # 找 hack-deep.attack-path.<path_id> 的 path_id
        import re
        m = re.search(r"hack-deep\.attack-path\.([0-9a-f]{12})", task)
        path_id = m.group(1) if m else "<unknown>"
        resp = self.responses.get(path_id, "")
        # 模拟流: 分多个 text_delta + done
        for chunk in [resp[i:i+10] for i in range(0, len(resp), 10)]:
            yield TextDeltaEvent(text=chunk)
        yield DoneEvent()


# ── 工具函数 ─────────────────────────────────────────────


def _result_marker(*, phase: str = "complete", wave: str = "1/1",
                   schema: str = "attack-path-v1",
                   deps: list[str] | None = None) -> str:
    deps = deps if deps is not None else ["find-complete-v1"]
    deps_repr = ",".join(deps)
    return f"schema: {schema} | phase: {phase} | wave: {wave} | deps: {deps_repr}"


def _marker_response(path_id: str, *,
                     phase: str = "complete",
                     extra_text: str = "",
                     vulns_json: str = "") -> str:
    """拼一个完整 hack-deep 响应, 含 result marker + (可选) vulns 段。"""
    body = f"Attack path {path_id} complete.\n"
    if vulns_json:
        body += f"\n## vulnerabilities\n{vulns_json}\n"
    if extra_text:
        body += f"\n{extra_text}\n"
    return f"{body}\n{_result_marker(phase=phase)}"


# ── Mock VulnerabilityExtractor ──────────────────────────


class _RecordingExtractor:
    def __init__(self, vulns: list[dict] | None = None,
                 raise_error: Exception | None = None) -> None:
        self.vulns = vulns or []
        self.raise_error = raise_error
        self.calls: list[dict] = []

    def extract(self, *, response_text, tree_id, path_id, leaf_node_id):
        self.calls.append({
            "tree_id": tree_id, "path_id": path_id,
            "leaf_node_id": leaf_node_id, "response_text": response_text,
        })
        if self.raise_error:
            raise self.raise_error
        return list(self.vulns)


class _RecordingVulnWriter:
    def __init__(self, raise_error: Exception | None = None) -> None:
        self.raise_error = raise_error
        self.calls: list[dict] = []

    async def write(self, *, vuln_payloads, tree_id, path_id,
                    leaf_node_id, ancestor_node_ids) -> int:
        self.calls.append({
            "vuln_payloads": vuln_payloads, "tree_id": tree_id,
            "path_id": path_id, "leaf_node_id": leaf_node_id,
            "ancestor_node_ids": ancestor_node_ids,
        })
        if self.raise_error:
            raise self.raise_error
        return len(vuln_payloads)


# ── 测试 ────────────────────────────────────────────────


class TestEnvelopeBuild:
    def test_envelope_in_task(self):
        prov = _MockProvider(responses={"a" * 12: _marker_response("a" * 12)})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
        )
        disp = SessionsSpawnDispatcher(opts)
        asyncio.run(disp.dispatch(
            path_id="a" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=2, ancestor_path=[],
        ))
        # 拿到 user message
        task = prov.calls[0]["messages"][0].content
        env = parse_envelope(task)
        assert env.handoff_id == f"hack-deep.attack-path.{'a' * 12}"
        assert env.evidence_schema == "attack-path-v1"
        assert env.input_dependencies == ["find-complete-v1"]
        assert env.auto_approve is True  # default
        assert env.dispatch_mode == "serial"  # default


class TestSuccessfulPath:
    def test_complete_marker_no_vulns(self):
        prov = _MockProvider(responses={"a" * 12: _marker_response("a" * 12)})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="a" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=2, ancestor_path=[
                {"from_node_id": "r" * 12, "to_node_id": "l" * 12,
                 "from_type": "root_domain", "to_type": "parameter",
                 "from_value": "x", "to_value": "q",
                 "edge_state": "discovered"},
            ],
        ))
        assert outcome.status == "completed"
        assert outcome.vuln_count == 0
        assert "marker" in (outcome.evidence or {})

    def test_complete_with_vulns(self):
        vulns = [
            {"cve": "CVE-2024-9999", "cwe": "CWE-89", "severity": "critical",
             "title": "SQLi in q", "description": "x", "evidence": None,
             "request": "GET /?q=x", "response": "200", "payload": "x' OR 1=1",
             "discovered_by_wave": "W4", "discovered_by_specialist": "pen"},
        ]
        extractor = _RecordingExtractor(vulns=vulns)
        writer = _RecordingVulnWriter()
        prov = _MockProvider(responses={"b" * 12: _marker_response("b" * 12)})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
            vuln_extractor=extractor, vuln_writer=writer,
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="b" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[
                {"from_node_id": "r" * 12, "to_node_id": "l" * 12,
                 "from_type": "root_domain", "to_type": "parameter",
                 "from_value": "x", "to_value": "q",
                 "edge_state": "discovered"},
            ],
        ))
        assert outcome.status == "completed"
        assert outcome.vuln_count == 1
        # extractor 收到正确参数
        assert extractor.calls[0]["path_id"] == "b" * 12
        # writer 收到 leaf + ancestor
        assert writer.calls[0]["leaf_node_id"] == "l" * 12
        assert writer.calls[0]["ancestor_node_ids"] == ["l" * 12]
        assert writer.calls[0]["vuln_payloads"] == vulns


class TestFailureIsolation:
    def test_llm_raises(self):
        prov = _MockProvider(raise_error=RuntimeError("provider down"))
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="f" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[],
        ))
        assert outcome.status == "failed"
        assert "llm_chat" in (outcome.error or "")
        assert "provider down" in (outcome.error or "")

    def test_missing_result_marker(self):
        prov = _MockProvider(responses={"d" * 12: "no marker here"})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="d" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[],
        ))
        assert outcome.status == "failed"
        assert "result_marker_missing" in (outcome.error or "")
        assert "raw_response" in (outcome.evidence or {})

    def test_marker_phase_exploitation(self):
        prov = _MockProvider(responses={
            "a" * 12: _marker_response("a" * 12, phase="exploitation"),
        })
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="a" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[],
        ))
        # phase=exploitation 视为未完成, 标 failed
        assert outcome.status == "failed"
        assert "exploitation" in (outcome.error or "")

    def test_extractor_raises_continues(self):
        extractor = _RecordingExtractor(raise_error=RuntimeError("bad parse"))
        writer = _RecordingVulnWriter()
        prov = _MockProvider(responses={"e" * 12: _marker_response("e" * 12)})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
            vuln_extractor=extractor, vuln_writer=writer,
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="e" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[],
        ))
        # extractor 抛了 → 0 vuln, path 仍标 completed (marker 正常)
        assert outcome.status == "completed"
        assert outcome.vuln_count == 0
        # writer 没被调
        assert writer.calls == []

    def test_writer_raises_continues(self):
        extractor = _RecordingExtractor(vulns=[{"severity": "high", "title": "x"}])
        writer = _RecordingVulnWriter(raise_error=RuntimeError("db dead"))
        prov = _MockProvider(responses={"c" * 12: _marker_response("c" * 12)})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
            vuln_extractor=extractor, vuln_writer=writer,
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="c" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[],
        ))
        # writer 抛了 → vuln_count=0, path 仍 completed (marker OK)
        assert outcome.status == "completed"
        assert outcome.vuln_count == 0


class TestStreamingCollection:
    def test_text_delta_collected_in_order(self):
        """Mock provider 已经用 text_delta 切片, 这里只验证 _chat_collect
        把 chunk 拼起来 — 通过最终 result marker 能 parse 出正确 phase。"""
        prov = _MockProvider(responses={"1" * 12: _marker_response("1" * 12)})
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
        )
        disp = SessionsSpawnDispatcher(opts)
        outcome = asyncio.run(disp.dispatch(
            path_id="1" * 12, tree_id="t1", scope_string="x",
            leaf_node_id="l" * 12, leaf_type="parameter", leaf_value="q",
            edge_count=1, ancestor_path=[],
        ))
        # 如果流式拼错, marker parse 会失败 → status=failed
        # 这里成功了, 说明 chunks 顺序正确
        assert outcome.status == "completed"


class TestOrchestratorIntegration:
    """dispatcher 接到 orchestrator.run_attack_paths 时端到端可用。"""

    def test_end_to_end_via_orchestrator(self):
        from opensquilla.asset_tree.models import AssetType
        from opensquilla.asset_tree.tree import AssetTree
        from opensquilla.asset_tree.attack_paths import create_attack_paths_for_tree
        from opensquilla.orchestrator import run_attack_paths, RunAttackPathsOptions
        from tests._stubs.in_memory_backend import InMemoryStubBackend

        # 1) 树 (完整 L0..L7: root -> sub -> ip -> port -> service -> url -> endpoint -> param)
        tree = AssetTree("example.com")
        sub = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com",
                            parent_id=tree.root_id, allow_unverified=True)
        ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub, allow_unverified=True)
        port = tree.add_node(AssetType.PORT, "443", parent_id=ip, allow_unverified=True)
        svc = tree.add_node(AssetType.SERVICE, "HTTPS", parent_id=port, allow_unverified=True)
        url = tree.add_node(AssetType.URL, "https://a.example.com", parent_id=svc, allow_unverified=True)
        ep = tree.add_node(AssetType.ENDPOINT, "/api", parent_id=url, allow_unverified=True)
        leaf = tree.add_node(AssetType.PARAMETER, "q", parent_id=ep, allow_unverified=True)
        # 2) backend + 生成 paths
        backend = InMemoryStubBackend()
        asyncio.run(create_attack_paths_for_tree(
            tree=tree, backend=backend, tree_id="t1",
        ))
        # 3) dispatcher 返回 2 个 vuln
        vulns = [
            {"cve": "CVE-1", "severity": "high", "title": "x",
             "discovered_by_wave": "W4", "discovered_by_specialist": "pen"},
            {"cve": "CVE-2", "severity": "medium", "title": "y",
             "discovered_by_wave": "W4", "discovered_by_specialist": "pen"},
        ]
        extractor = _RecordingExtractor(vulns=vulns)
        writer = _RecordingVulnWriter()
        # 4) provider: 返回 path_id -> completed marker
        async def get_responses():
            stored = await backend.list_attack_paths("t1")
            return {
                r["path_id"]: _marker_response(r["path_id"])
                for r in stored
            }
        responses = asyncio.run(get_responses())
        prov = _MockProvider(responses=responses)
        opts = SessionsSpawnDispatcherOptions(
            provider=prov, model="m", system_prompt="sys",
            vuln_extractor=extractor, vuln_writer=writer,
        )
        disp = SessionsSpawnDispatcher(opts)
        # 5) 跑 orchestrator
        result = asyncio.run(run_attack_paths(RunAttackPathsOptions(
            tree_id="t1", tree=tree, backend=backend, dispatcher=disp,
        )))
        assert result.path_count == 1
        assert result.completed == 1
        assert result.failed == 0
        assert result.vuln_total == 2
        # writer 收到 2 个 vuln
        assert len(writer.calls) == 1
        assert len(writer.calls[0]["vuln_payloads"]) == 2
        # path 状态标 completed
        async def check():
            return await backend.list_attack_paths("t1")
        stored = asyncio.run(check())
        assert all(r["status"] == "completed" for r in stored)
        assert all(r["vuln_count"] == 2 for r in stored)
