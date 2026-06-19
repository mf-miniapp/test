"""v6 (2026-06-19) orchestrator.evidence_parser 单测。

覆盖:
  - severity 等级映射 (CVSS / text / fallback)
  - CVE / CWE / CVSS / severity regex 抽取
  - JSON 块抽取 (markdown + inline)
  - structured pentest-v1 → vuln_payload
  - structured triage-v1 → vuln_payload
  - regex fallback
  - 空 response / 无 vulnerability 时返回空 list
"""
from __future__ import annotations

import pytest

from opensquilla.orchestrator.evidence_parser import (
    DefaultVulnerabilityExtractor,
    _extract_cve,
    _extract_cwe,
    _extract_cvss,
    _extract_severity_text,
    severity_from_cvss,
    severity_from_text,
)


# ── severity ──────────────────────────────────────────


class TestSeverityFromCVSS:
    def test_critical(self):
        assert severity_from_cvss(9.5) == "critical"
        assert severity_from_cvss(10.0) == "critical"
        assert severity_from_cvss(9.0) == "critical"

    def test_high(self):
        assert severity_from_cvss(7.0) == "high"
        assert severity_from_cvss(8.9) == "high"

    def test_medium(self):
        assert severity_from_cvss(4.0) == "medium"
        assert severity_from_cvss(6.9) == "medium"

    def test_low(self):
        assert severity_from_cvss(0.1) == "low"
        assert severity_from_cvss(3.9) == "low"

    def test_none(self):
        assert severity_from_cvss(None) == "info"


class TestSeverityFromText:
    def test_known(self):
        assert severity_from_text("critical") == "critical"
        assert severity_from_text("HIGH") == "high"
        assert severity_from_text("Med") == "medium"
        assert severity_from_text("informative") == "info"
        assert severity_from_text("moderate") == "medium"

    def test_unknown_falls_back_to_info(self):
        assert severity_from_text("zomg") == "info"
        assert severity_from_text(None) == "info"
        assert severity_from_text("") == "info"


# ── regex 抽取 ────────────────────────────────────────


class TestRegexExtract:
    def test_cve(self):
        assert _extract_cve("Confirmed CVE-2024-1234 in payload") == "CVE-2024-1234"
        assert _extract_cve("CVE-2023-99999 abc") == "CVE-2023-99999"
        assert _extract_cve("no cve here") is None

    def test_cwe(self):
        assert _extract_cwe("we hit CWE-89 sql injection") == "CWE-89"
        assert _extract_cwe("CWE-12345 mentioned") == "CWE-12345"
        assert _extract_cwe("none") is None

    def test_cvss(self):
        assert _extract_cvss("CVSS: 9.8 (critical)") == 9.8
        assert _extract_cvss("CVSS v3.1: 7.5") == 7.5
        assert _extract_cvss("cvss_score: 4.3") == 4.3
        assert _extract_cvss("score 2.0") is None  # 必须有 "CVSS" 关键词

    def test_severity(self):
        assert _extract_severity_text("severity: critical") == "critical"
        assert _extract_severity_text("Priority: high") == "high"
        assert _extract_severity_text("risk: medium") == "medium"
        assert _extract_severity_text("low stuff") is None  # 必须前缀


# ── extractor 主路径 ────────────────────────────────


class TestExtractorEmpty:
    def test_empty(self):
        e = DefaultVulnerabilityExtractor()
        assert e.extract(response_text="", tree_id="t", path_id="a"*12,
                        leaf_node_id="l"*12) == []

    def test_no_vuln_signals(self):
        e = DefaultVulnerabilityExtractor()
        out = e.extract(
            response_text="Just some prose, nothing fancy.",
            tree_id="t", path_id="a"*12, leaf_node_id="l"*12,
        )
        assert out == []


class TestExtractorStructuredPentest:
    def test_pentest_findings(self):
        e = DefaultVulnerabilityExtractor()
        body = """
```json
{
  "evidence_schema": "pentest-v1",
  "findings": [
    {
      "entry_id": "V001",
      "title": "SQL Injection in q",
      "vector_class": "http_sqli",
      "status": "owned",
      "confidence": "high",
      "auth_context": "anonymous",
      "classification": {"cwe": "CWE-89", "owasp": "A03"},
      "cvss": {"base_score": 9.8, "vector": "CVSS:3.1/..."},
      "request": "GET /?q=x' OR 1=1",
      "response": "HTTP 200; rows leaked: 1234",
      "impact_summary": "DB rows dumped"
    }
  ]
}
```
"""
        out = e.extract(response_text=body, tree_id="t1",
                        path_id="a"*12, leaf_node_id="l"*12)
        assert len(out) == 1
        v = out[0]
        assert v["title"] == "SQL Injection in q"
        assert v["cwe"] == "CWE-89"
        assert v["severity"] == "critical"  # CVSS 9.8 → critical
        assert v["discovered_by_wave"] == "W4"
        assert v["discovered_by_specialist"] == "penetration"
        assert v["request"] is not None
        assert "wave" in v["evidence"]

    def test_pentest_no_cve_uses_text_fallback(self):
        e = DefaultVulnerabilityExtractor()
        body = """
```json
{
  "evidence_schema": "pentest-v1",
  "findings": [
    {
      "entry_id": "V002",
      "title": "Reflected XSS",
      "classification": {},
      "cvss": null,
      "impact_summary": "xss in q"
    }
  ]
}
```
"""
        out = e.extract(response_text=body, tree_id="t1",
                        path_id="a"*12, leaf_node_id="l"*12)
        assert len(out) == 1
        v = out[0]
        # 没 CVSS → info
        assert v["severity"] == "info"

    def test_pentest_with_inline_cve_string(self):
        """cve 字段缺失但 finding description 含 CVE 字符串 → regex 抽。"""
        e = DefaultVulnerabilityExtractor()
        body = """
{
  "findings": [
    {
      "entry_id": "V003",
      "title": "RCE",
      "impact_summary": "triggered CVE-2024-9999 in dependency"
    }
  ]
}
"""
        out = e.extract(response_text=body, tree_id="t1",
                        path_id="a"*12, leaf_node_id="l"*12)
        assert len(out) == 1
        assert out[0]["cve"] == "CVE-2024-9999"


class TestExtractorStructuredTriage:
    def test_triage_candidates(self):
        e = DefaultVulnerabilityExtractor()
        body = """
```json
{
  "evidence_schema": "triage-v1",
  "candidates": [
    {
      "vuln_class": "sqli",
      "title": "Potential SQLi",
      "cve": "CVE-2023-1234",
      "cvss": 8.5,
      "description": "q parameter untested"
    }
  ],
  "prioritized_top_n": [
    {
      "vuln_class": "xss",
      "title": "Reflected XSS in q",
      "cwe": "CWE-79"
    }
  ]
}
```
"""
        out = e.extract(response_text=body, tree_id="t1",
                        path_id="a"*12, leaf_node_id="l"*12)
        assert len(out) == 2
        # candidate 1: CVE + CVSS 8.5 → high
        v1 = next(v for v in out if v["title"] == "Potential SQLi")
        assert v1["cve"] == "CVE-2023-1234"
        assert v1["severity"] == "high"
        assert v1["discovered_by_wave"] == "W2"
        # candidate 2: CWE 79 → no CVSS → info
        v2 = next(v for v in out if v["title"] == "Reflected XSS in q")
        assert v2["cwe"] == "CWE-79"
        assert v2["severity"] == "info"


class TestExtractorRegexFallback:
    def test_regex_with_cve_and_severity(self):
        e = DefaultVulnerabilityExtractor()
        text = """
Found SQL injection in parameter q.

The vulnerability is CVE-2024-5555 with severity: critical.
CVSS: 9.1 (critical).

Payload: x' OR 1=1--
"""
        out = e.extract(response_text=text, tree_id="t1",
                        path_id="a"*12, leaf_node_id="l"*12)
        assert len(out) == 1
        v = out[0]
        assert v["cve"] == "CVE-2024-5555"
        assert v["severity"] == "critical"
        assert v["evidence"]["extraction"] == "regex_fallback"

    def test_regex_cwe_only(self):
        e = DefaultVulnerabilityExtractor()
        out = e.extract(
            response_text="vuln: CWE-89 sqli confirmed",
            tree_id="t1", path_id="a"*12, leaf_node_id="l"*12,
        )
        assert len(out) == 1
        assert out[0]["cwe"] == "CWE-89"
        assert out[0]["severity"] == "info"  # 没 CVSS / severity_text


class TestExtractorStructuredPreferred:
    def test_structured_beats_regex(self):
        """同一 response 既含结构化 JSON 又含 regex 命中, 优先用结构化。"""
        e = DefaultVulnerabilityExtractor()
        body = """
Structured finding: CVE-2024-1111.

```json
{"findings": [{"entry_id": "V1", "title": "structured one"}]}
```

Loose regex match: CVE-2024-9999.
"""
        out = e.extract(response_text=body, tree_id="t1",
                        path_id="a"*12, leaf_node_id="l"*12)
        # 走结构化, 1 条
        assert len(out) == 1
        assert out[0]["title"] == "structured one"
        # 不应该有 9999 (regex fallback 跳过)
        assert not any(v.get("cve") == "CVE-2024-9999" for v in out)
