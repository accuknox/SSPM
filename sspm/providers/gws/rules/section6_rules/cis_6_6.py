"""
CIS GWS 6.6 (L1) – Ensure Suspicious login alert rule is configured (Manual)

Profile Applicability: Enterprise Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_6_6(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.6",
        title="Ensure Suspicious login alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures an alert rule in Google Workspace that notifies "
            "administrators when Google's risk analysis detects a "
            "suspicious interactive login attempt.  Suspicious login "
            "indicators include unusual geographic locations, impossible "
            "travel, and access from known malicious IP addresses."
        ),
        rationale=(
            "Suspicious login alerts provide early warning of potential "
            "account compromise from credential theft or phishing attacks.  "
            "Early detection enables administrators to force password resets, "
            "revoke active sessions, and investigate before significant "
            "damage occurs."
        ),
        impact=(
            "Legitimate users who frequently travel or use VPNs may "
            "occasionally trigger suspicious login alerts.  Administrators "
            "should establish a triage process to quickly distinguish "
            "false positives from genuine threats."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'Suspicious login' alert rule is enabled "
            "and routes notifications to the security team"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'Suspicious login' alert rule\n"
            "  4. Configure notification recipients\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'Suspicious login' alert rule may not be enabled by "
            "default (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="8.11",
                title="Conduct Audit Log Reviews",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "suspicious-login"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
