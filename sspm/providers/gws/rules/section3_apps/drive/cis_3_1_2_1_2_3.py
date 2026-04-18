"""
CIS GWS 3.1.2.1.2.3 (L1) – Ensure shared drive file access is restricted
to members only (Manual)

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
class CIS_3_1_2_1_2_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.2.3",
        title="Ensure shared drive file access is restricted to members only",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Shared drive file access should be restricted to that shared drive's "
            "members.  Non-members should not be able to be added to individual "
            "files within a shared drive."
        ),
        rationale=(
            "Preventing unauthorised users from accessing sensitive data is paramount "
            "in preventing unauthorised or unintentional information disclosures."
        ),
        impact=(
            "Disabling this feature will prevent shared drive non-members from "
            "accessing content in shared drives where they are not a member."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Sharing settings\n"
            "  4. Under Shared drive creation, ensure 'Allow people who aren't "
            "shared drive members to be added to files' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Sharing settings\n"
            "  4. Under Shared drive creation, set 'Allow people who aren't shared "
            "drive members to be added to files' to unchecked\n"
            "  5. Click Save"
        ),
        default_value=(
            "Allow people who aren't shared drive members to be added to files is checked."
        ),
        references=[
            "https://support.google.com/a/answer/7662202",
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
        tags=["drive", "shared-drive", "access-control"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
