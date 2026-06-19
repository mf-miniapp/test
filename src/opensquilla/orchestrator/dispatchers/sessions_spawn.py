"""SessionsSpawnDispatcher — 真实 LLM 调用的 AttackPathDispatcher。

工作流
======

```
caller ──(path_id, scope, ancestor_path, leaf_*)──> dispatch()
  │
  ▼
[1] 拼 attack-path-v1 HandoffEnvelope
    (HANDOFF hack-deep.attack-path.<path_id> | deps=find-complete-v1
     | schema=attack-path-v1 | eta=600)
  │
  ▼
[2] 拼 hack-deep system prompt (从 SOUL_BODY 读)
    + 上面 envelope 作为 user message
  │
  ▼
[3] LLMProvider.chat(messages=[{system, user}], config=ChatConfig(model=...))
    流式收 event, 累成完整 assistant response
  │
  ▼
[4] parse_result_marker(response) 拿 vuln evidence / vuln 列表
    │
    ▼
[5] evidence -> vulnerability:
       对每条 triage-v1 / pentest-v1 finding 含 cve_*/cwe_*/severity 的,
       backend.add_vulnerability(...)
       + add_path_vuln + add_node_vuln (反哺)
    │
    ▼
[6] 返回 AttackPathOutcome(status, vuln_count)
```

设计要点
========

- **不依赖 sessions_spawn 工具**: sessions_spawn 走 ToolContext, 是 LLM
  在 turn 内调用; 本 dispatcher 是程序化发起, 所以直接调 LLMProvider,
  等价于"hack-deep 接单后跑一次完整 run_turn"。
- **失败隔离**: 任何异常 (LLM error / parse error / DB error) 都被
  包成 ``AttackPathOutcome(status="failed", error=...)`` 返回, 不抛。
  orchestrator 拿到后标 path 失败, 跑下一条。
- **evidence 解析**: 在 ``evidence_parser`` 模块里 (还没写, 见 v6 TODO),
  dispatcher 调 ``extract_vulnerabilities(evidence)`` 拿 List[Dict]。
  本 dispatcher 容忍 parser 抛异常 (标 0 vuln, 不影响主流程)。

Public surface
==============

- ``SessionsSpawnDispatcherOptions`` — 配置 (provider / model / system prompt / et al)
- ``SessionsSpawnDispatcher``         — AttackPathDispatcher Protocol 实现
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from opensquilla.attack_dispatch.envelope import (
    EnvelopeFormatError,
    HandoffEnvelope,
    ResultFormatError,
    envelope_to_text,
    parse_envelope,
    parse_result_marker,
    synthesize_marker,
)
from opensquilla.attack_dispatch.evidence import AttackPathEvidence
from opensquilla.orchestrator.run_attack_paths import AttackPathOutcome
from opensquilla.provider.protocol import LLMProvider
from opensquilla.provider.types import ChatConfig, Message


logger = logging.getLogger(__name__)


# ── 漏洞提取协议 (extracted so tests can stub) ───────────


class VulnerabilityExtractor(Protocol):
    """从 assistant 完整响应中抽出漏洞列表 — 由 evidence_parser 模块实现。"""

    def extract(
        self,
        *,
        response_text: str,
        tree_id: str,
        path_id: str,
        leaf_node_id: str,
    ) -> list[dict[str, Any]]:
        ...


@dataclass
class _NullExtractor:
    """默认 extractor — 永远返回空列表。生产由 evidence_parser 替换。"""

    def extract(
        self,
        *,
        response_text: str,
        tree_id: str,
        path_id: str,
        leaf_node_id: str,
    ) -> list[dict[str, Any]]:
        return []


# ── 配置 ────────────────────────────────────────────────


@dataclass
class SessionsSpawnDispatcherOptions:
    provider: LLMProvider
    model: str
    system_prompt: str
    hack_deep_agent_id: str = "hack-deep"   # 写到 envelope 标识
    auto_approve: bool = True               # v3.3 (2026-06-08 Issue 1)
    dispatch_mode: Optional[str] = "serial" # v3.3 (2026-06-08 Issue 4)
    extra_context: dict[str, Any] = field(default_factory=dict)
    vuln_extractor: VulnerabilityExtractor = field(default_factory=_NullExtractor)
    vuln_writer: Optional["VulnerabilityWriter"] = None  # 见下


class VulnerabilityWriter(Protocol):
    """漏洞持久化抽象 — 默认实现写到 backend。"""

    async def write(
        self,
        *,
        vuln_payloads: list[dict[str, Any]],
        tree_id: str,
        path_id: str,
        leaf_node_id: str,
        ancestor_node_ids: list[str],
    ) -> int:
        """Returns count of vulnerabilities written (post-DB dedup)."""
        ...


@dataclass
class _DefaultVulnWriter:
    """用 AssetTreeBackend 直接写的 vulnerability writer。"""

    backend: Any  # AssetTreeBackend — 用 Any 避免循环 import

    async def write(
        self,
        *,
        vuln_payloads: list[dict[str, Any]],
        tree_id: str,
        path_id: str,
        leaf_node_id: str,
        ancestor_node_ids: list[str],
    ) -> int:
        import secrets
        written = 0
        for p in vuln_payloads:
            vuln_id = secrets.token_hex(6)  # 12-hex
            try:
                await self.backend.add_vulnerability(
                    vuln_id=vuln_id,
                    tree_id=tree_id,
                    attack_path_id=path_id,
                    leaf_node_id=leaf_node_id,
                    cwe=p.get("cwe"),
                    cve=p.get("cve"),
                    severity=p.get("severity", "info"),
                    title=p.get("title", "(untitled)"),
                    description=p.get("description"),
                    evidence=p.get("evidence"),
                    request=p.get("request"),
                    response=p.get("response"),
                    payload=p.get("payload"),
                    discovered_by_wave=p.get("discovered_by_wave"),
                    discovered_by_specialist=p.get("discovered_by_specialist"),
                )
                await self.backend.add_path_vuln(
                    attack_path_id=path_id, vulnerability_id=vuln_id,
                )
                # 反哺: leaf + ancestor 全部 node 都挂 vuln_node_vulns
                all_node_ids = [leaf_node_id] + [
                    n for n in ancestor_node_ids if n and n != leaf_node_id
                ]
                for nid in all_node_ids:
                    await self.backend.add_node_vuln(
                        tree_id=tree_id, node_id=nid, vulnerability_id=vuln_id,
                    )
                written += 1
            except Exception:
                logger.exception(
                    "write vuln failed path_id=%s vuln_id=%s", path_id, vuln_id,
                )
        return written


# ── 主类 ────────────────────────────────────────────────


class SessionsSpawnDispatcher:
    """v6 真实生产 AttackPathDispatcher — 走 LLMProvider.chat。"""

    def __init__(self, opts: SessionsSpawnDispatcherOptions) -> None:
        self._opts = opts

    async def dispatch(
        self,
        *,
        path_id: str,
        tree_id: str,
        scope_string: str,
        leaf_node_id: str,
        leaf_type: str,
        leaf_value: str,
        edge_count: int,
        ancestor_path: list[dict[str, Any]],
    ) -> AttackPathOutcome:
        # 1. 拼 envelope
        try:
            envelope = self._build_envelope(path_id)
        except Exception as exc:
            return AttackPathOutcome(
                status="failed", error=f"envelope_build: {exc!r}",
            )

        # 2. 拼 evidence body (AttackPathEvidence)
        ap_ev = AttackPathEvidence(
            tree_id=tree_id,
            path_id=path_id,
            scope_string=scope_string,
            leaf_node_id=leaf_node_id,
            leaf_type=leaf_type,
            leaf_value=leaf_value,
            ancestor_path=ancestor_path,
            edge_count=edge_count,
        )

        task = f"{envelope_to_text(envelope)}\n\n{ap_ev.model_dump_json()}"

        messages = [
            Message(role="user", content=task),
        ]

        # 3. 调 LLM 流式收 (system prompt 走 ChatConfig.system)
        try:
            response_text = await self._chat_collect(
                messages=messages,
                config=ChatConfig(
                    model=self._opts.model,
                    system=self._opts.system_prompt,
                ),
            )
        except Exception as exc:
            logger.exception("LLM chat failed path_id=%s", path_id)
            return AttackPathOutcome(
                status="failed", error=f"llm_chat: {exc!r}",
            )

        # 4. parse result marker
        try:
            marker = parse_result_marker(response_text)
        except ResultFormatError as exc:
            return AttackPathOutcome(
                status="failed",
                error=f"result_marker_missing: {exc!r}",
                evidence={"raw_response": response_text[:4096]},
            )

        # 5. extract vulnerabilities
        try:
            vuln_payloads = self._opts.vuln_extractor.extract(
                response_text=response_text,
                tree_id=tree_id, path_id=path_id, leaf_node_id=leaf_node_id,
            )
        except Exception as exc:
            logger.exception("vuln_extractor failed path_id=%s", path_id)
            vuln_payloads = []

        # 6. write vulns (if writer provided)
        written = 0
        if self._opts.vuln_writer and vuln_payloads:
            ancestor_node_ids = [
                ap.get("to_node_id") for ap in ancestor_path if ap.get("to_node_id")
            ]
            try:
                written = await self._opts.vuln_writer.write(
                    vuln_payloads=vuln_payloads,
                    tree_id=tree_id, path_id=path_id,
                    leaf_node_id=leaf_node_id,
                    ancestor_node_ids=ancestor_node_ids,
                )
            except Exception:
                logger.exception("vuln_writer failed path_id=%s", path_id)

        # 7. 决定 outcome
        if marker.phase == "complete":
            return AttackPathOutcome(
                status="completed",
                vuln_count=written,
                evidence={
                    "marker": marker.model_dump(mode="json"),
                    "raw_extracted": vuln_payloads,
                },
            )
        return AttackPathOutcome(
            status="failed",
            error=f"marker_phase={marker.phase!r}",
            evidence={"marker": marker.model_dump(mode="json")},
        )

    # ── helpers ────────────────────────────────────────────

    def _build_envelope(self, path_id: str) -> HandoffEnvelope:
        return HandoffEnvelope(
            handoff_id=f"hack-deep.attack-path.{path_id}",
            input_dependencies=["find-complete-v1"],
            evidence_schema="attack-path-v1",
            expected_runtime_s=600,
            dispatch_mode=self._opts.dispatch_mode,  # type: ignore[arg-type]
            auto_approve=self._opts.auto_approve,
        )

    async def _chat_collect(
        self,
        *,
        messages: list[Message],
        config: ChatConfig,
    ) -> str:
        """流式 chat, 拼成完整 assistant response 字符串。"""
        chunks: list[str] = []
        async for ev in self._opts.provider.chat(
            messages=messages, tools=None, config=config,
        ):
            # Event shapes are union; only text_delta carries content.
            # Avoid attribute errors for non-text events.
            kind = getattr(ev, "kind", None)
            if kind == "text_delta":
                chunks.append(getattr(ev, "text", "") or "")
            elif kind == "done":
                break
            elif kind == "error":
                msg = getattr(ev, "error", None) or "provider_error"
                raise RuntimeError(f"provider error: {msg}")
        return "".join(chunks)

    @staticmethod
    def build_default_system_prompt() -> str:
        """从 hack-deep SOUL_BODY.md 读 system prompt — 给一个常用默认值。"""
        try:
            from opensquilla.agents.hack_deep import SOUL_BODY
            return SOUL_BODY
        except Exception:
            return (
                "You are hack-deep, the v6 attack-path orchestrator. "
                "Read the HANDOFF envelope and AttackPathEvidence body; "
                "produce a complete result marker and any discovered "
                "vulnerability evidence."
            )
