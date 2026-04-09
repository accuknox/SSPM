"""
CIS GWS 3.1.2.1.2.4 (L2) – Ensure viewers and commenters ability to
download, print, and copy files is disabled (Manual)

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
class CIS_3_1_2_1_2_4(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.2.4",
        title="Ensure viewers and commenters ability to download, print, and copy files is disabled",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Limit what viewers and commenters on a shared document can do with it. "
            "The ability to download, print, and copy files should be disabled for "
            "viewer and commenter roles on shared drives."
        ),
        rationale=(
            "In restricted environments, the ability to download, print, and copy "
            "files should be prevented to protect Intellectual Property, PII, and "
            "other sensitive information from being extracted from the organisation."
        ),
        impact=(
            "Users of this shared drive will be restricted to only reading and "
            "commenting on the existing files — they cannot download, print, or copy."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Sharing settings\n"
            "  4. Under Shared drive creation, ensure 'Allow viewers and commenters "
            "to download, print, and copy files' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Sharing settings\n"
            "  4. Under Shared drive creation, set 'Allow viewers and commenters to "
            "download, print, and copy files' to unchecked\n"
            "  5. Click Save"
        ),
        default_value=(
            "Allow viewers and commenters to download, print, and copy files is unchecked."
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
        tags=["drive", "shared-drive", "download", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify viewers/commenters cannot download, print, or copy files:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Shared drive creation\n"
            "  4. Ensure 'Allow viewers and commenters to download, print, and copy "
            "files' is unchecked"
        )
