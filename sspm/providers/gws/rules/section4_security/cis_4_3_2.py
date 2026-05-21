"""
CIS GWS 4.3.2 (L2) – Ensure the Security health is reviewed regularly for
anomalies (Manual)

Profile Applicability: Enterprise Level 2
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
class CIS_4_3_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.3.2",
        title="Ensure the Security health is reviewed regularly for anomalies",
        section="4.3 Security Center",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Establishes a regular review process for the Google Workspace "
            "Security Health page, which provides a consolidated view of "
            "security configuration recommendations and identifies settings "
            "that deviate from Google's security best practices."
        ),
        rationale=(
            "The Security Health page continuously monitors Google Workspace "
            "configuration settings against security recommendations.  "
            "Regular review ensures that configuration drift is detected "
            "and corrected promptly, maintaining the organisation's "
            "security posture over time."
        ),
        impact=(
            "Regular review of the Security Health page requires dedicated "
            "administrator time.  Organisations should assign ownership of "
            "security health monitoring and establish remediation SLAs for "
            "identified issues."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Security center → Security health\n"
            "  3. Verify that no critical or high-severity findings are "
            "unaddressed\n"
            "  4. Confirm that the health page has been reviewed within "
            "the last 30 days and that findings are documented"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Security center → Security health\n"
            "  3. Review all findings and their severity levels\n"
            "  4. Remediate critical and high findings promptly\n"
            "  5. Document medium and low findings with remediation plans\n"
            "  6. Establish a recurring monthly review schedule"
        ),
        default_value=(
            "No automatic review process exists; review must be performed "
            "manually on a regular schedule."
        ),
        references=[
            "https://support.google.com/a/answer/7492330",
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
        tags=["security-center", "health", "monitoring"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
