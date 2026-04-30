"""
CIS GWS 4.2.3.1 (L1) – Ensure DLP policies for Google Drive are configured
(Manual)

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
class CIS_4_2_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.3.1",
        title="Ensure DLP policies for Google Drive are configured",
        section="4.2.3 Data Protection",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures Data Loss Prevention (DLP) policies in Google "
            "Workspace to detect and prevent the sharing of sensitive "
            "information stored in Google Drive.  DLP policies can scan "
            "for patterns such as credit card numbers, social security "
            "numbers, and other regulated data, and block or alert on "
            "sharing attempts."
        ),
        rationale=(
            "Without DLP policies, sensitive data stored in Drive can be "
            "freely shared externally by users who may not be aware of "
            "regulatory requirements.  DLP provides an automated safety "
            "net that enforces data handling policies regardless of "
            "individual user awareness or intent."
        ),
        impact=(
            "DLP policies may block or flag legitimate sharing of documents "
            "that match DLP rules.  False positives should be monitored and "
            "policies tuned accordingly.  Users whose sharing attempts are "
            "blocked should have a defined escalation path."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Data protection\n"
            "  3. Verify that at least one DLP rule is configured for "
            "Google Drive that covers sensitive data types relevant to "
            "the organisation (e.g., credit card numbers, PII)"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Data protection\n"
            "  3. Create DLP rules for sensitive data categories appropriate "
            "to the organisation\n"
            "  4. Configure rules to block external sharing or alert "
            "administrators when sensitive data is detected\n"
            "  5. Click Save"
        ),
        default_value=(
            "No DLP policies are configured by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/9004364",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.13",
                title="Deploy a Data Loss Prevention Solution",
                ig1=False,
                ig2=False,
                ig3=True,
            ),
        ],
        tags=["dlp", "data-protection", "drive"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
