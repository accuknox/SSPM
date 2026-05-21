"""
CIS GWS 3.1.2.2.2 (L1) – Ensure desktop access to Drive is disabled
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
class CIS_3_1_2_2_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.2.2",
        title="Ensure desktop access to Drive is disabled",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "The Google Drive for desktop application should be disabled to prevent "
            "files from being stored locally on devices, particularly unmanaged "
            "devices."
        ),
        rationale=(
            "The Google Drive desktop application does not obey the Drive and Docs "
            "offline access using device policies setting and has its own way of "
            "handling offline files.  Disabling it prevents this separate data "
            "exfiltration channel."
        ),
        impact=(
            "The end user will not be able to use Google Drive for desktop and its "
            "convenient integration into the Windows/Mac file explorer."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Google Drive for desktop\n"
            "  4. Ensure 'Allow Google Drive for desktop in your organization' "
            "is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Google Drive for desktop\n"
            "  4. Set 'Allow Google Drive for desktop in your organization' to unchecked\n"
            "  5. Click Save"
        ),
        default_value="Allow Google Drive for desktop in your organization is checked.",
        references=[
            "https://support.google.com/a/answer/7491237",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.8",
                title="Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["drive", "desktop", "data-protection", "endpoint"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
