"""
CIS MS365 8.1.1 (L1) – Ensure external file sharing in Teams uses only
approved cloud storage services (Manual)

Profile Applicability: E3 Level 1, E5 Level 1
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
class CIS_8_1_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.1.1",
        title="Ensure external file sharing in Teams uses only approved cloud storage services",
        section="8.1 Teams Client Configuration",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Teams should be configured to only allow file sharing through "
            "approved cloud storage services (SharePoint/OneDrive). Third-party "
            "storage services like Dropbox and Box should be disabled."
        ),
        rationale=(
            "Third-party cloud storage services are outside organizational governance. "
            "Restricting Teams to use only SharePoint/OneDrive ensures files are stored "
            "in governed storage with appropriate compliance controls."
        ),
        impact="Users will only be able to share files stored in SharePoint and OneDrive.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsClientConfiguration | Select-Object AllowDropbox, "
            "AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte\n\n"
            "Compliant: All third-party storage options = False"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsClientConfiguration -AllowDropbox $false "
            "-AllowBox $false -AllowGoogleDrive $false "
            "-AllowShareFile $false -AllowEgnyte $false"
        ),
        default_value="Third-party storage is allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/teams-client-configuration",
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
        tags=["teams", "file-sharing", "cloud-storage", "third-party"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Teams external file sharing storage via Microsoft Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsClientConfiguration | Select-Object AllowDropbox, "
            "AllowBox, AllowGoogleDrive, AllowShareFile\n\n"
            "Compliant: All third-party storage options are False."
        )
