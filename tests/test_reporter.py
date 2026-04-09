"""Tests for the SARIF reporter."""

import json

import pytest

from sspm.core.models import (
    AssessmentStatus,
    CISProfile,
    Evidence,
    Finding,
    FindingStatus,
    RuleMetadata,
    ScanResult,
    Severity,
)
from sspm.core.reporter import to_sarif


def _make_rule(rid="ms365-test-1", assessment=AssessmentStatus.AUTOMATED):
    return RuleMetadata(
        id=rid,
        title="Test rule",
        section="1.0 Test",
        benchmark="CIS MS365 v6.0.1",
        assessment_status=assessment,
        profiles=[CISProfile.E3_L1],
        severity=Severity.HIGH,
        description="A test rule.",
        rationale="Testing.",
        impact="None.",
        audit_procedure="Check X.",
        remediation="Fix X.",
        default_value="Default",
    )


def _make_result(findings):
    r = ScanResult(
        target="test.onmicrosoft.com",
        provider="ms365",
        benchmark="CIS MS365 v6.0.1",
        started_at="2026-04-09T00:00:00+00:00",
        completed_at="2026-04-09T00:01:00+00:00",
    )
    r.findings = findings
    return r


class TestSarifOutput:
    def test_schema_and_version(self):
        result = _make_result([])
        doc = to_sarif(result)
        assert doc["version"] == "2.1.0"
        assert "sarif-schema" in doc["$schema"]

    def test_tool_info(self):
        result = _make_result([])
        doc = to_sarif(result)
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "AccuKnox SSPM"
        assert driver["organization"] == "AccuKnox"

    def test_pass_finding_kind(self):
        rule = _make_rule()
        finding = Finding(rule=rule, status=FindingStatus.PASS, message="Passed.")
        doc = to_sarif(_make_result([finding]))
        res = doc["runs"][0]["results"][0]
        assert res["kind"] == "pass"
        assert res["level"] == "none"

    def test_fail_finding_kind_and_level(self):
        rule = _make_rule()
        finding = Finding(rule=rule, status=FindingStatus.FAIL, message="Failed!")
        doc = to_sarif(_make_result([finding]))
        res = doc["runs"][0]["results"][0]
        assert res["kind"] == "fail"
        assert res["level"] == "error"  # HIGH severity → error

    def test_manual_finding_kind(self):
        rule = _make_rule(assessment=AssessmentStatus.MANUAL)
        finding = Finding(rule=rule, status=FindingStatus.MANUAL, message="Manual check.")
        doc = to_sarif(_make_result([finding]))
        res = doc["runs"][0]["results"][0]
        assert res["kind"] == "open"
        assert res["level"] == "none"

    def test_rule_deduplication(self):
        rule = _make_rule()
        findings = [
            Finding(rule=rule, status=FindingStatus.PASS, resource_id="u1"),
            Finding(rule=rule, status=FindingStatus.FAIL, resource_id="u2"),
        ]
        doc = to_sarif(_make_result(findings))
        driver = doc["runs"][0]["tool"]["driver"]
        assert len(driver["rules"]) == 1  # de-duplicated
        assert len(doc["runs"][0]["results"]) == 2

    def test_rule_descriptor_has_metadata(self):
        rule = _make_rule()
        finding = Finding(rule=rule, status=FindingStatus.PASS)
        doc = to_sarif(_make_result([finding]))
        descriptor = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert descriptor["id"] == "ms365-test-1"
        assert descriptor["properties"]["assessmentStatus"] == "automated"
        assert "E3 Level 1" in descriptor["properties"]["profiles"]

    def test_evidence_in_related_locations(self):
        rule = _make_rule()
        finding = Finding(
            rule=rule,
            status=FindingStatus.FAIL,
            evidence=[Evidence(source="graph/users", data={"count": 5}, description="Five users.")],
        )
        doc = to_sarif(_make_result([finding]))
        res = doc["runs"][0]["results"][0]
        assert "relatedLocations" in res
        assert res["relatedLocations"][0]["message"]["text"] == "graph/users: Five users."

    def test_serialisable_to_json(self):
        rule = _make_rule()
        findings = [
            Finding(rule=rule, status=FindingStatus.PASS),
            Finding(rule=rule, status=FindingStatus.FAIL, resource_id="r1"),
        ]
        doc = to_sarif(_make_result(findings))
        # Should not raise
        serialised = json.dumps(doc, default=str)
        parsed = json.loads(serialised)
        assert parsed["version"] == "2.1.0"
