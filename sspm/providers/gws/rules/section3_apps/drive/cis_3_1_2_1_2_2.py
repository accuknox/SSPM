"""
CIS GWS 3.1.2.1.2.2 (L1) – Ensure manager access members cannot modify
shared drive settings (Manual)

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
class CIS_3_1_2_1_2_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.2.2",
        title="Ensure manager access members cannot modify shared drive settings",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Only administrators should be able to modify shared drive settings. "
            "Manager-level members of shared drives should not be able to override "
            "organisational settings."
        ),
        rationale=(
            "Allowing manager access members to override or modify shared drive "
            "settings can allow intentional and unintentional data access by "
            "unauthorised users."
        ),
        impact=(
            "Disabling this feature will prevent manager access members from "
            "modifying shared drive settings, requiring administrators to perform "
            "settings modifications as required."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Sharing settings\n"
            "  4. Under Shared drive creation, ensure 'Allow members with manager "
            "access to override the settings below' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Sharing settings\n"
            "  4. Under Shared drive creation, set 'Allow members with manager "
            "access to override the settings below' to unchecked\n"
            "  5. Click Save"
        ),
        default_value=(
            "Allow members with manager access to override the settings below is checked."
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
        tags=["drive", "shared-drive", "least-privilege"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
