"""
CIS MS365 7.2.8 (L2) – Ensure external sharing is restricted by security group
(Manual)

Profile Applicability: E3 Level 2, E5 Level 2
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_7_2_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.8",
        title="Ensure external sharing is restricted by security group",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "External sharing in SharePoint should be limited to users in a specific "
            "security group, preventing all users from sharing externally by default."
        ),
        rationale=(
            "Restricting external sharing to a security group ensures only authorized "
            "users can share content with external parties, reducing the risk of "
            "accidental data exposure."
        ),
        impact="Most users will be unable to share content with external parties.",
        audit_procedure=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Check if external sharing is limited to members of a security group.\n\n"
            "There is no Graph API for this specific SharePoint setting."
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Under 'Limit external sharing by domain', add the security group that "
            "is permitted to share externally."
        ),
        default_value="All users can share externally by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/manage-external-sharing",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "external-sharing", "security-group", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify external sharing is restricted by security group:\n"
            "  1. Go to SharePoint admin center (admin.microsoft.com → SharePoint)\n"
            "  2. Navigate to Policies > Sharing\n"
            "  3. Verify external sharing is limited to members of a specific security group\n\n"
            "This setting cannot be verified via Microsoft Graph API."
        )
