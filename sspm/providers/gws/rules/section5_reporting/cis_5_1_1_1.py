"""
CIS GWS 5.1.1.1 (L1) – Ensure the App Usage Report is reviewed regularly for
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
class CIS_5_1_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-5.1.1.1",
        title="Ensure the App Usage Report is reviewed regularly for anomalies",
        section="5.1.1 User Reports",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Establishes a regular review process for the Google Workspace "
            "App Usage Report, which shows how users interact with Google "
            "Workspace applications.  Monitoring app usage helps identify "
            "unusual access patterns, inactive accounts, or shadow IT "
            "adoption."
        ),
        rationale=(
            "App usage reports provide visibility into user behaviour and "
            "application adoption.  Anomalies such as sudden spikes in "
            "data access, usage from unexpected locations, or access by "
            "inactive accounts can indicate a security incident.  Regular "
            "review enables proactive threat detection."
        ),
        impact=(
            "Regular review of App Usage Reports requires dedicated "
            "administrator time but provides essential visibility into "
            "user activity.  Organisations should define what constitutes "
            "an anomaly and document the review process."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Reports → User Reports → App Usage\n"
            "  3. Verify that the report has been reviewed within the last "
            "30 days\n"
            "  4. Confirm that any anomalies identified have been "
            "investigated and documented"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Reports → User Reports → App Usage\n"
            "  3. Review usage patterns across all applications\n"
            "  4. Investigate any unusual spikes or access patterns\n"
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
        tags=["reporting", "app-usage", "monitoring"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
