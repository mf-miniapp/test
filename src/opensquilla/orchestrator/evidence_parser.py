"""v6 (2026-06-19) Evidence -> Vulnerability 解析。

从 hack-deep 的 assistant response 文本中抽取漏洞, 转换为
vulnerabilities 表的写入格式 (``vuln_payloads`` dict 列表)。

策略 (按顺序尝试, 首个有结果的就用):
  1. **structured (pentest-v1)**: regex 抓 ``schema: pentest-v1`` 块,
     parse 成 PenetrationEvidence, 走 findings[]。
  2. **structured (triage-v1)**: 同上, 走 candidates[] + prioritized_top_n[]。
  3. **structured (any w-###)**: 任何 w4/w2/w6 等 evidence 块, 找
     含 cve_*/cwe_*/severity 的 finding 子对象。
  4. **regex fallback**: response 文本里直接搜
     ``cve-YYYY-NNNN`` / ``cwe-NNN`` / ``severity: <level>`` 模式。

severity 等级映射:
  CVSS >= 9.0  → critical
  CVSS >= 7.0  → high
  CVSS >= 4.0  → medium
  CVSS >= 0.1  → low
  缺省         → info
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Optional

from opensquilla.attack_dispatch.evidence import EVIDENCE_SCHEMAS, make_evidence
from opensquilla.orchestrator.dispatchers.sessions_spawn import (
    VulnerabilityExtractor,
)


# ── Severity 等级映射 ─────────────────────────────────────

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def severity_from_text(text: str | None) -> str:
    if not text:
        return "info"
    t = text.strip().lower()
    # 接受 critical / high / medium / low / info / informative
    aliases = {
        "critical": "critical", "crit": "critical",
        "high": "high", "h": "high",
        "medium": "medium", "med": "medium", "moderate": "medium",
        "low": "low", "l": "low",
        "info": "info", "informational": "info", "informative": "info",
    }
    return aliases.get(t, "info")


# ── Vulnerability payload 归一化 ─────────────────────────


def _normalize_vuln_payload(
    *,
    title: str,
    cve: str | None = None,
    cwe: str | None = None,
    severity: str | None = None,
    description: str | None = None,
    evidence: dict | None = None,
    request: str | None = None,
    response: str | None = None,
    payload: str | None = None,
    discovered_by_wave: str | None = None,
    discovered_by_specialist: str | None = None,
) -> dict[str, Any]:
    """统一为 vulnerability 表写入格式, 缺省字段填 None。"""
    return {
        "title": title or "(untitled)",
        "cve": cve or None,
        "cwe": cwe or None,
        "severity": severity_from_text(severity or "info"),
        "description": description,
        "evidence": evidence,
        "request": request,
        "response": response,
        "payload": payload,
        "discovered_by_wave": discovered_by_wave,
        "discovered_by_specialist": discovered_by_specialist,
    }


# ── CVE / CWE regex ──────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_CWE_RE = re.compile(r"CWE-\d{1,5}")
_CVSS_RE = re.compile(
    r"(?:CVSS(?:\s*v?[23](?:\.1)?)?[:\s]+|cvss_score[:\s]+|cvss[:\s]+)"
    r"(?P<score>\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
# severity: critical / high / medium / low / info (短句)
_SEVERITY_RE = re.compile(
    r"\b(?:severity|priority|risk)[:\s]+(?P<sev>critical|high|medium|low|info)\b",
    re.IGNORECASE,
)


def _extract_cve(text: str) -> str | None:
    m = _CVE_RE.search(text)
    return m.group(0) if m else None


def _extract_cwe(text: str) -> str | None:
    m = _CWE_RE.search(text)
    return m.group(0) if m else None


def _extract_cvss(text: str) -> float | None:
    m = _CVSS_RE.search(text)
    return float(m.group("score")) if m else None


def _extract_severity_text(text: str) -> str | None:
    m = _SEVERITY_RE.search(text)
    return m.group("sev").lower() if m else None


# ── JSON 块抽取 (markdown ```json ... ``` 或 inline {...}) ───


_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n(?P<body>\{[\s\S]+?\})\s*\n```")
_JSON_INLINE_RE = re.compile(r"\{[\s\S]+?\}")


def _extract_json_blocks(text: str) -> Iterable[dict[str, Any]]:
    """从 response 文本抽所有 JSON 块, 尝试 parse。"""
    # markdown 优先
    for m in _JSON_BLOCK_RE.finditer(text):
        try:
            obj = json.loads(m.group("body"))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj
    # fallback: 找第一段看起来像 evidence 的 {...}
    for m in _JSON_INLINE_RE.finditer(text):
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("findings" in obj or "candidates" in obj or
                                       "evidence_schema" in obj):
            yield obj


# ── Extractor 主类 ───────────────────────────────────────


class DefaultVulnerabilityExtractor:
    """默认 vulnerability extractor — structured + regex 双轨。

    行为:
      1. 抽 response 里的 JSON 块 (markdown ```json``` 优先)。
      2. 凡是含 ``findings[]`` (pentest) 或 ``candidates[]`` (triage) 的,
         走结构化路径, 把每条 finding 归一化成 vuln_payload。
      3. 结构化路径没出东西 → 跑 regex fallback (CVSS 段 + CVE/CWE/severity
         字符串), 归一化成 1 条 vuln_payload。
    """

    def extract(
        self,
        *,
        response_text: str,
        tree_id: str,
        path_id: str,
        leaf_node_id: str,
    ) -> list[dict[str, Any]]:
        payloads: list[dict[str, Any]] = []

        # 1) structured
        for obj in _extract_json_blocks(response_text):
            schema = obj.get("evidence_schema")
            if schema == "pentest-v1" or "findings" in obj:
                payloads.extend(self._from_pentest(obj, path_id))
            elif schema == "triage-v1" or "candidates" in obj:
                payloads.extend(self._from_triage(obj, path_id))
            elif schema and schema in EVIDENCE_SCHEMAS:
                # 其它 typed evidence, 试构造
                try:
                    ev = make_evidence(schema, **obj)
                    payloads.extend(self._from_any_evidence(ev, schema, path_id))
                except Exception:
                    pass

        if payloads:
            return payloads

        # 2) regex fallback
        fallback = self._from_regex(response_text, path_id)
        if fallback:
            payloads.append(fallback)
        return payloads

    # ── structured paths ────────────────────────────────

    @staticmethod
    def _from_pentest(obj: dict[str, Any], path_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for f in obj.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            # 关键字段
            title = f.get("title") or f"finding {f.get('entry_id', '?')}"
            cve = f.get("cve") or _extract_cve(json.dumps(f))
            cwe = f.get("cwe") or _extract_cwe(json.dumps(f))
            # classification.cwe 嵌套
            cls = f.get("classification") or {}
            if not cwe and isinstance(cls, dict):
                cwe = cls.get("cwe") or _extract_cwe(json.dumps(cls))
            # cvss
            cvss_obj = f.get("cvss") or {}
            cvss_score = None
            if isinstance(cvss_obj, dict):
                cvss_score = cvss_obj.get("base_score") or cvss_obj.get("score")
            if cvss_score is None:
                cvss_score = _extract_cvss(json.dumps(f))
            severity = (
                f.get("severity") or _extract_severity_text(json.dumps(f))
                or severity_from_cvss(float(cvss_score) if cvss_score else None)
            )
            # request/response
            req = f.get("request")
            if isinstance(req, dict):
                req = json.dumps(req, ensure_ascii=False)
            resp = f.get("response")
            if isinstance(resp, dict):
                resp = json.dumps(resp, ensure_ascii=False)
            # evidence
            evidence = {
                "wave": "W4",
                "vector_class": f.get("vector_class"),
                "entry_id": f.get("entry_id"),
                "status": f.get("status"),
                "confidence": f.get("confidence"),
                "auth_context": f.get("auth_context"),
            }
            # 去掉 None 让 dict 干净
            evidence = {k: v for k, v in evidence.items() if v is not None}
            out.append(_normalize_vuln_payload(
                title=title, cve=cve, cwe=cwe, severity=severity,
                description=f.get("impact_summary") or f.get("blocked_reason"),
                evidence=evidence or None,
                request=req, response=resp,
                payload=req,  # 没专门 payload 字段, 用 request
                discovered_by_wave="W4",
                discovered_by_specialist="penetration",
            ))
        return out

    @staticmethod
    def _from_triage(obj: dict[str, Any], path_id: str) -> list[dict[str, Any]]:
        """TriageEvidence 的 candidates[] / prioritized_top_n[]。"""
        out: list[dict[str, Any]] = []
        for c in (obj.get("candidates") or []) + (obj.get("prioritized_top_n") or []):
            if not isinstance(c, dict):
                continue
            title = c.get("title") or c.get("vuln_class") or "triage candidate"
            cve = c.get("cve") or _extract_cve(json.dumps(c))
            cwe = c.get("cwe") or _extract_cwe(json.dumps(c))
            cvss = c.get("cvss") or c.get("cvss_score")
            if cvss is None:
                cvss = _extract_cvss(json.dumps(c))
            severity = (
                c.get("severity") or _extract_severity_text(json.dumps(c))
                or severity_from_cvss(float(cvss) if cvss else None)
            )
            out.append(_normalize_vuln_payload(
                title=title, cve=cve, cwe=cwe, severity=severity,
                description=c.get("description") or c.get("rationale"),
                evidence={"wave": "W2", "triage_class": c.get("vuln_class")},
                discovered_by_wave="W2",
                discovered_by_specialist="vulnerability-triage",
            ))
        return out

    @staticmethod
    def _from_any_evidence(ev: Any, schema: str, path_id: str) -> list[dict[str, Any]]:
        """对其它 typed evidence 找含 cve/cwe/severity 的子对象。"""
        # PentestEvidence: has .findings
        if hasattr(ev, "findings") and ev.findings:
            return DefaultVulnerabilityExtractor._from_pentest(
                ev.model_dump(mode="json"), path_id,
            )
        # TriageEvidence: has .candidates
        if hasattr(ev, "candidates") and ev.candidates:
            return DefaultVulnerabilityExtractor._from_triage(
                ev.model_dump(mode="json"), path_id,
            )
        return []

    # ── regex fallback ─────────────────────────────────

    @staticmethod
    def _from_regex(text: str, path_id: str) -> dict[str, Any] | None:
        cve = _extract_cve(text)
        cwe = _extract_cwe(text)
        cvss = _extract_cvss(text)
        severity_text = _extract_severity_text(text)
        if not (cve or cwe or cvss or severity_text):
            return None
        # 从附近行找个标题 — 取首段非空行作 title
        title = ""
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("```") and not line.startswith("schema:"):
                title = line[:120]
                break
        return _normalize_vuln_payload(
            title=title or f"regex-extracted vuln (path {path_id[:8]})",
            cve=cve, cwe=cwe,
            severity=severity_text or severity_from_cvss(cvss),
            description=text[:500] if text else None,
            evidence={"extraction": "regex_fallback"},
        )


