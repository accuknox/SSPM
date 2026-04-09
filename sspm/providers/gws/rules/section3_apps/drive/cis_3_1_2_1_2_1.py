"""
CIS GWS 3.1.2.1.2.1 (L1) – Ensure users can create new shared drives
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
class CIS_3_1_2_1_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.2.1",
        title="Ensure users can create new shared drives",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.LOW,
        description=(
            "All users should have the ability to create new shared drives. "
            "By default when a user account is deleted, all data in their personal "
            "drive is deleted as well.  Allowing users to create shared drives "
            "prevents data loss when user accounts are deleted."
        ),
        rationale=(
            "When a user account is deleted, all data in their personal drive is "
            "deleted as well.  By allowing any user to create new shared drives, "
            "this aids in preventing data loss when user accounts are deleted."
        ),
        impact="Disabling this feature will prevent users from creating new shared drives.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings, select 'Shared drive creation'\n"
            "  4. Ensure 'Prevent users in <Company> from creating new shared drives' "
            "is un-checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Shared drive creation\n"
            "  4. Set 'Prevent users in <Company> from creating new shared drives' "
            "to unchecked\n"
            "  5. Click Save"
        ),
        default_value=(
            "Prevent users in <Company> from creating new shared drives is unchecked."
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
        tags=["drive", "shared-drive", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify users can create new shared drives:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Shared drive creation\n"
            "  4. Ensure 'Prevent users from creating new shared drives' is unchecked"
        )
