"""
CIS GWS 5.1.1.2 (L1) – Ensure the Security Report is reviewed regularly for
anomalies (Manual)

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
class CIS_5_1_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-5.1.1.2",
        title="Ensure the Security Report is reviewed regularly for anomalies",
        section="5.1.1 User Reports",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Establishes a regular review process for the Google Workspace "
            "Security Report, which provides metrics on security events "
            "including spam, malware, authentication failures, and "
            "suspicious login activity for users in the organisation."
        ),
        rationale=(
            "The Security Report aggregates security-relevant events and "
            "presents them in a format suitable for identifying trends and "
            "anomalies.  Regular review allows administrators to detect "
            "ongoing attacks, identify users at risk, and assess the "
            "effectiveness of existing security controls."
        ),
        impact=(
            "Regular review of Security Reports requires dedicated "
            "administrator time but is essential for maintaining situational "
            "awareness of the organisation's security posture.  A defined "
            "review owner and documented process should be established."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Reports → User Reports → Security\n"
            "  3. Verify that the security report has been reviewed within "
            "the last 30 days\n"
            "  4. Confirm that any security anomalies have been investigated "
            "and documented"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Reports → User Reports → Security\n"
            "  3. Review all security metrics for anomalies\n"
            "  4. Investigate users with high counts of suspicious "
            "authentication events or security alerts\n"
            "  5. Document findings and establish a recurring monthly "
            "review schedule"
        ),
        default_value=(
            "No automatic review process exists; review must be performed "
            "manually on a regular schedule."
        ),
        references=[
            "https://support.google.com/a/answer/4547199",
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
        tags=["reporting", "security", "monitoring"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
