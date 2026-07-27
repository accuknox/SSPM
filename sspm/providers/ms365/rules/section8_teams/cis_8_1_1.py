"""
CIS MS365 8.1.1 (L1) – Ensure external file sharing in Teams is enabled for
only approved cloud storage services (Automated)

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
        title="Ensure external file sharing in Teams is enabled for only approved cloud storage services",
        section="8.1 Teams Client Configuration",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Connect-MicrosoftTeams.\n"
            "  Get-CsTeamsClientConfiguration -Identity Global | fl AllowDropbox, "
            "AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte\n\n"
            "Verify that only organizationally-approved third-party storage providers "
            "are set to True; all others should be False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsClientConfiguration -Identity Global -AllowDropbox $false "
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
        # Get-CsTeamsClientConfiguration is a MicrosoftTeams Remote PowerShell
        # cmdlet with no Microsoft Graph equivalent, so this collector (which
        # only performs Graph client-credentials auth) cannot read it.
        if "teams_client_configuration" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Teams client configuration: "
                f"{data.errors.get('teams_client_configuration')}"
            )

        return self._manual(
            message=(
                "Approved cloud storage providers for Teams file sharing cannot be "
                "read via Microsoft Graph. Verify manually via Microsoft Teams "
                "PowerShell: Connect-MicrosoftTeams; "
                "Get-CsTeamsClientConfiguration -Identity Global | fl AllowDropbox, "
                "AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte — ensure only "
                "organizationally-approved providers are True."
            )
        )
