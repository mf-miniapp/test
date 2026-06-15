"""Tests for the Claude-BugHunter adoption batch (2026-06-14).

Covers:
- scope_matcher pattern DSL (apex / wildcard / exact / CIDR / re:regex)
- deny-wins + default-deny semantics
- suffix-confusion guard
- extract_hosts_from_blob for URL + proto://user@host forms
- ROEEvidence.engagement_type / scope_patterns / severity_gate / cadence
- TriageEvidence.disclosed_report_patterns / hunt_skills_consulted
- PenetrationFinding.seven_question_gate (any_fail / fail_questions)
- ReportEvidence.gate_* aggregate fields
- DispatchExecutor.scope_audit_findings + _apply_seven_question_gate
- Self-test parity with the upstream reference suite
"""
from __future__ import annotations

import pytest
from pathlib import Path

from opensquilla.attack_dispatch import (
    DispatchExecutor,
    LateralEvidence,
    PenetrationEvidence,
    ReportEvidence,
    ROEEvidence,
    SevenQuestionGate,
    QAResult,
    TriageEvidence,
    extract_hosts_from_blob,
    in_scope,
    reject_reason,
    scope_audit_hosts,
    REJECT_DENY_WINS,
    REJECT_DEFAULT_DENY,
    REJECT_CANNOT_PARSE,
)


# ---------------------------------------------------------------------------
# scope_matcher
# ---------------------------------------------------------------------------


class TestScopeMatcher:
    def test_apex_matches_self_and_subdomain(self):
        assert in_scope("https://example.com", in_scope_patterns=["example.com"])
        assert in_scope(
            "https://api.example.com/x", in_scope_patterns=["example.com"]
        )

    def test_wildcard_matches_subdomain_only(self):
        assert in_scope(
            "https://a.test.example.com",
            in_scope_patterns=["*.test.example.com"],
        )
        assert not in_scope(
            "https://test.example.com",
            in_scope_patterns=["*.test.example.com"],
        )

    def test_cidr_matches_inside(self):
        assert in_scope(
            "https://10.1.2.3:8080/", in_scope_patterns=["10.0.0.0/8"]
        )
        assert not in_scope(
            "https://11.0.0.1/", in_scope_patterns=["10.0.0.0/8"]
        )

    def test_regex_prefix(self):
        assert in_scope(
            "https://lab42.acme.io", in_scope_patterns=["re:^lab[0-9]+\\.acme\\.io$"]
        )
        assert not in_scope(
            "https://api.acme.io", in_scope_patterns=["re:^lab[0-9]+\\.acme\\.io$"]
        )

    def test_deny_wins(self):
        # out_of_scope pattern matches -> reject, even if in_scope also matches
        assert not in_scope(
            "https://admin.example.com",
            in_scope_patterns=["example.com"],
            out_of_scope_patterns=["admin.example.com"],
        )

    def test_default_deny(self):
        # no in_scope pattern matches -> reject
        assert not in_scope("https://evil.com", in_scope_patterns=["example.com"])

    def test_suffix_confusion_guard(self):
        assert not in_scope(
            "https://example.com.evil.com", in_scope_patterns=["example.com"]
        )
        assert not in_scope(
            "https://notexample.com", in_scope_patterns=["example.com"]
        )

    def test_reject_reasons_stable_strings(self):
        assert reject_reason("https://evil.com", in_scope_patterns=["example.com"]) == REJECT_DEFAULT_DENY
        assert (
            reject_reason(
                "https://admin.example.com",
                in_scope_patterns=["example.com"],
                out_of_scope_patterns=["admin.example.com"],
            )
            == REJECT_DENY_WINS
        )
        assert reject_reason("", in_scope_patterns=["example.com"]) == REJECT_CANNOT_PARSE

    def test_extract_hosts_from_blob(self):
        blob = (
            "GET https://api.example.com/v1/x HTTP/1.1\n"
            "POST https://admin.example.com/y\n"
            "Direct: postgres://u:p@db.internal:5432/x"
        )
        hosts = extract_hosts_from_blob(blob)
        assert "api.example.com" in hosts
        assert "admin.example.com" in hosts
        assert "db.internal" in hosts
        # dedup + sorted
        assert hosts == sorted(set(hosts))

    def test_scope_audit_hosts_filters_in_scope(self):
        in_pats = ["example.com", "*.test.example.com", "10.0.0.0/8"]
        out_pats = ["admin.example.com"]
        audit = scope_audit_hosts(
            ["admin.example.com", "api.example.com", "evil.com", "10.0.0.5"],
            in_scope_patterns=in_pats,
            out_of_scope_patterns=out_pats,
        )
        # admin -> deny-wins, evil -> default-deny, 10.0.0.5 -> in-scope
        assert "admin.example.com" in audit
        assert "evil.com" in audit
        assert "api.example.com" not in audit
        assert "10.0.0.5" not in audit

    def test_self_test_passes(self):
        """Run the module's own self-test to catch regressions."""
        import subprocess
        import sys
        proc = subprocess.run(
            [sys.executable, "-m", "opensquilla.attack_dispatch.scope_matcher"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "PASS" in proc.stdout


# ---------------------------------------------------------------------------
# ROEEvidence new fields (engagement_type / scope_patterns / severity_gate / cadence)
# ---------------------------------------------------------------------------


class TestROEEvidenceAdoption:
    def test_engagement_type_default_red_team(self):
        e = ROEEvidence(target="t", scope_summary="s", success_unit="per-host")
        assert e.engagement_type == "red_team"

    def test_engagement_type_allows_4_values(self):
        for et in ("bug_bounty", "red_team", "pentest", "internal_audit"):
            e = ROEEvidence(
                target="t", scope_summary="s", success_unit="per-host",
                engagement_type=et,
            )
            assert e.engagement_type == et

    def test_scope_patterns_carries_dsl(self):
        e = ROEEvidence(
            target="t", scope_summary="s", success_unit="per-host",
            scope_patterns=["*.example.com", "10.0.0.0/8", "re:^.*\\.internal\\.local$"],
        )
        assert "*.example.com" in e.scope_patterns
        assert "10.0.0.0/8" in e.scope_patterns

    def test_severity_gate_filter(self):
        e = ROEEvidence(
            target="t", scope_summary="s", success_unit="per-host",
            severity_gate=["critical", "high"],
        )
        assert "critical" in e.severity_gate
        assert "info" not in e.severity_gate

    def test_cadence_default_all_true(self):
        e = ROEEvidence(target="t", scope_summary="s", success_unit="per-host")
        assert e.cadence["top_100_path_probe"] is True
        assert e.cadence["js_bundle_grep"] is True

    def test_cadence_can_be_disabled(self):
        # Cadence is a dict[str, bool] with default_factory that
        # returns all 8 keys True. The constructor accepts an
        # explicit dict; Pydantic v2 uses the provided dict
        # verbatim (it does NOT merge with the default).
        e = ROEEvidence(
            target="t", scope_summary="s", success_unit="per-host",
            cadence={"top_100_path_probe": False},
        )
        # Explicit value used
        assert e.cadence["top_100_path_probe"] is False
        # Default keys NOT in the explicit dict are absent
        assert "robots_txt_read" not in e.cadence
        # Document this so the integration test in W8 reporting
        # knows to read the cadence from a default-constructed
        # ROE first if a custom one is missing keys.


# ---------------------------------------------------------------------------
# TriageEvidence new fields (disclosed_report_patterns / hunt_skills_consulted)
# ---------------------------------------------------------------------------


class TestTriageEvidenceAdoption:
    def test_disclosed_report_patterns_default_empty(self):
        t = TriageEvidence(target="t")
        assert t.disclosed_report_patterns == []
        assert t.hunt_skills_consulted == []

    def test_disclosed_report_patterns_round_trip(self):
        rows = [
            {
                "vuln_class": "injection_sql",
                "source": "hackerone_public",
                "report_id": "H1-12345",
                "cve": None,
                "tech_stack": ["PHP", "MySQL"],
                "pattern_summary": "classic search concat",
                "payload_template": "curl -s 'https://t/search?q=z1z%27%20OR%20%271%27%3D%271'",
                "bypass_table": ["url-encode-quote"],
            }
        ]
        t = TriageEvidence(
            target="t",
            disclosed_report_patterns=rows,
            hunt_skills_consulted=["hunt-sqli", "hunt-skill-map"],
        )
        assert t.hunt_skills_consulted == ["hunt-sqli", "hunt-skill-map"]
        assert t.disclosed_report_patterns[0]["vuln_class"] == "injection_sql"


# ---------------------------------------------------------------------------
# PenetrationFinding.seven_question_gate
# ---------------------------------------------------------------------------


class _PassGate(SevenQuestionGate):
    """All 7 questions pass; convenience for tests."""


def _all_pass_gate() -> SevenQuestionGate:
    return SevenQuestionGate(
        q1_attacker_usable=QAResult(verdict="pass"),
        q2_impact_accepted=QAResult(verdict="pass"),
        q3_in_scope=QAResult(verdict="pass"),
        q4_privilege_realistic=QAResult(verdict="pass"),
        q5_not_known=QAResult(verdict="pass"),
        q6_chainable=QAResult(verdict="pass"),
        q7_business_impact=QAResult(verdict="pass"),
    )


class TestSevenQuestionGate:
    def test_all_pass_does_not_fail(self):
        g = _all_pass_gate()
        assert g.any_fail() is False
        assert g.fail_questions() == []

    def test_single_q_fail_marks_gate_failed(self):
        g = _all_pass_gate()
        g.q1_attacker_usable = QAResult(verdict="fail", reason="theoretical only")
        assert g.any_fail() is True
        assert g.fail_questions() == ["q1_attacker_usable"]

    def test_multiple_q_fails(self):
        g = _all_pass_gate()
        g.q3_in_scope = QAResult(verdict="fail", reason="dev env, not prod")
        g.q7_business_impact = QAResult(verdict="fail", reason="no $ impact")
        assert g.fail_questions() == ["q3_in_scope", "q7_business_impact"]

    def test_legacy_finding_without_gate_is_optional(self):
        """Findings WITHOUT seven_question_gate set must not error."""
        from opensquilla.attack_dispatch.evidence import PenetrationFinding
        f = PenetrationFinding(entry_id="V001")
        assert f.seven_question_gate is None

    def test_pentest_finding_accepts_gate(self):
        from opensquilla.attack_dispatch.evidence import PenetrationFinding
        f = PenetrationFinding(entry_id="V001", seven_question_gate=_all_pass_gate())
        assert f.seven_question_gate is not None
        assert f.seven_question_gate.any_fail() is False


# ---------------------------------------------------------------------------
# ReportEvidence gate_* aggregate fields
# ---------------------------------------------------------------------------


class TestReportEvidenceGate:
    def test_gate_defaults(self):
        r = ReportEvidence(target="t", executive_summary="x")
        assert r.gate_engagement_type is None
        assert r.gate_total_findings == 0
        assert r.gate_passed_findings == 0
        assert r.gate_pass_rate == 1.0

    def test_gate_engagement_type_mirror(self):
        r = ReportEvidence(
            target="t",
            executive_summary="x",
            gate_engagement_type="bug_bounty",
            gate_total_findings=10,
            gate_passed_findings=8,
            gate_failed_findings=2,
            gate_skipped_findings=0,
            gate_pass_rate=0.8,
            gate_failed_entry_ids=["V001", "V005"],
        )
        assert r.gate_engagement_type == "bug_bounty"
        assert r.gate_pass_rate == 0.8
        assert r.gate_failed_entry_ids == ["V001", "V005"]


# ---------------------------------------------------------------------------
# DispatchExecutor hooks
# ---------------------------------------------------------------------------


class TestExecutorHooks:
    def test_apply_seven_question_gate_downgrades_on_fail(self):
        from opensquilla.attack_dispatch.evidence import (
            ExploitRequest,
            PenetrationFinding,
        )
        from opensquilla.attack_dispatch import DispatchState

        # Finding with 7Q fail
        f = PenetrationFinding(
            entry_id="V001",
            status="owned",
            seven_question_gate=SevenQuestionGate(
                q1_attacker_usable=QAResult(verdict="pass"),
                q2_impact_accepted=QAResult(verdict="pass"),
                q3_in_scope=QAResult(verdict="fail", reason="dev only"),
                q4_privilege_realistic=QAResult(verdict="pass"),
                q5_not_known=QAResult(verdict="pass"),
                q6_chainable=QAResult(verdict="pass"),
                q7_business_impact=QAResult(verdict="pass"),
            ),
        )
        ev = PenetrationEvidence(target="t", findings=[f])
        state = DispatchState()

        applied, downgraded, skipped = DispatchExecutor._apply_seven_question_gate(
            evidence=ev, wave="W4", state=state
        )
        assert applied == 1
        assert downgraded == 1
        assert skipped == 0
        assert f.status == "partial"  # downgraded
        assert "V001" in ev.unverified_findings
        # state.errors should mention the failing question
        assert any("q3_in_scope" in e for e in state.errors)

    def test_apply_seven_question_gate_passes(self):
        from opensquilla.attack_dispatch.evidence import PenetrationFinding
        from opensquilla.attack_dispatch import DispatchState

        f = PenetrationFinding(
            entry_id="V002",
            status="owned",
            seven_question_gate=_all_pass_gate(),
        )
        ev = PenetrationEvidence(target="t", findings=[f])
        state = DispatchState()

        applied, downgraded, skipped = DispatchExecutor._apply_seven_question_gate(
            evidence=ev, wave="W4", state=state
        )
        assert applied == 1
        assert downgraded == 0
        assert f.status == "owned"  # unchanged

    def test_apply_seven_question_gate_legacy_no_field(self):
        from opensquilla.attack_dispatch.evidence import PenetrationFinding
        from opensquilla.attack_dispatch import DispatchState

        f = PenetrationFinding(entry_id="V003", status="owned")
        ev = PenetrationEvidence(target="t", findings=[f])
        state = DispatchState()

        applied, downgraded, skipped = DispatchExecutor._apply_seven_question_gate(
            evidence=ev, wave="W4", state=state
        )
        assert applied == 0
        assert downgraded == 0
        assert skipped == 1
        assert f.status == "owned"  # legacy findings pass through

    def test_apply_seven_question_gate_severity_drop(self):
        from opensquilla.attack_dispatch.evidence import (
            CVSSScore,
            PenetrationFinding,
        )
        from opensquilla.attack_dispatch import DispatchState

        # CVSS severity rating "low" — should be flagged when gate is
        # bug_bounty (severity_gate defaults to all tiers in our test
        # helper, but we'll set explicit ['critical', 'high']).
        f = PenetrationFinding(
            entry_id="V004",
            status="owned",
            cvss=CVSSScore(base_score=3.5, vector="CVSS:3.1/..."),
            seven_question_gate=_all_pass_gate(),
        )
        # Patch the CVSS severity_rating via the model's own field
        # (CVSSScore has severity_rating as a Literal)
        f.cvss.severity = "low"  # CVSSScore.severity is the CVSSSeverity Literal
        ev = PenetrationEvidence(target="t", findings=[f])
        state = DispatchState()
        roe = ROEEvidence(
            target="t",
            scope_summary="s",
            success_unit="per-host",
            severity_gate=["critical", "high"],
            engagement_type="bug_bounty",
        )

        DispatchExecutor._apply_seven_question_gate(
            evidence=ev, wave="W4", state=state, roe=roe
        )
        # The severity-drop message should mention the entry id
        assert any("V004" in e and "severity" in e for e in state.errors)

    def test_scope_audit_findings_flags_oos_hosts(self):
        from opensquilla.attack_dispatch.evidence import (
            ExploitRequest,
            ExploitResponse,
            PenetrationFinding,
        )

        # Finding whose request body references out-of-scope host
        f = PenetrationFinding(
            entry_id="V005",
            status="owned",
            request=ExploitRequest(
                method="POST",
                url="https://api.example.com/v1/x",
                body='{"proxy":"https://admin.example.com/leak"}',
            ),
            response=ExploitResponse(
                status_code=200,
                body_snippet='{"forwarded":"https://admin.example.com/leak"}',
            ),
        )
        ev = PenetrationEvidence(target="t", findings=[f])
        roe = ROEEvidence(
            target="t",
            scope_summary="s",
            success_unit="per-host",
            scope_patterns=["example.com"],
            forbidden_assets=["admin.example.com"],
        )
        violations = DispatchExecutor.scope_audit_findings(
            evidence=ev, roe=roe
        )
        assert "V005" in violations
        assert "admin.example.com" in violations["V005"]
        # The evidence-level scope_violations is updated
        assert any("V005" in v for v in ev.scope_violations)
        assert ev.out_of_scope_hits >= 1

    def test_scope_audit_findings_no_roe_noop(self):
        from opensquilla.attack_dispatch.evidence import PenetrationFinding
        f = PenetrationFinding(entry_id="V006")
        ev = PenetrationEvidence(target="t", findings=[f])
        violations = DispatchExecutor.scope_audit_findings(evidence=ev, roe=None)
        assert violations == {}
