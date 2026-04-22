"""
CIS GWS 4.3.1 (L1) – Ensure the Security Dashboard is reviewed regularly for
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
class CIS_4_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.3.1",
        title="Ensure the Security Dashboard is reviewed regularly for anomalies",
        section="4.3 Security Center",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Establishes a regular review process for the Google Workspace "
            "Security Dashboard to identify security anomalies, unusual "
            "activity patterns, and potential indicators of compromise "
            "across the organisation's Google Workspace environment."
        ),
        rationale=(
            "The Security Dashboard provides a consolidated view of security "
            "metrics including spam, malware, authentication events, and "
            "data access patterns.  Regular review enables early detection "
            "of security incidents and helps identify areas where security "
            "controls need to be strengthened."
        ),
        impact=(
            "Regular review of the Security Dashboard requires dedicated "
            "administrator time but provides essential visibility into the "
            "security posture of the Google Workspace environment.  "
            "Organisations should assign responsibility for this review "
            "to a specific role."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Security center → Dashboard\n"
            "  3. Verify that the dashboard has been reviewed within the "
            "last 7 days\n"
            "  4. Confirm that any anomalies identified have been "
            "investigated and documented"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Security center → Dashboard\n"
            "  3. Review all security metrics and widgets for anomalies\n"
            "  4. Investigate any identified anomalies and document findings\n"
            "  5. Establish a recurring review schedule (at minimum weekly)"
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
        tags=["security-center", "dashboard", "monitoring"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
