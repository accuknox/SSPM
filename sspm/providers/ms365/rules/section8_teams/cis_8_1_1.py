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
    Evidence,
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

        config = data.get("teams_client_configuration")
        if config is None:
            return self._manual(
                message=(
                    "Approved cloud storage providers for Teams file sharing "
                    "requires the Microsoft Teams PowerShell bridge "
                    "(Connect-MicrosoftTeams with certificate app-only auth), "
                    "which is not configured for this scan. Verify manually: "
                    "Get-CsTeamsClientConfiguration -Identity Global | fl "
                    "AllowDropbox, AllowBox, AllowGoogleDrive, AllowShareFile, "
                    "AllowEgnyte — ensure only organizationally-approved providers "
                    "are True."
                )
            )

        providers = {
            "AllowDropbox": config.get("AllowDropbox"),
            "AllowBox": config.get("AllowBox"),
            "AllowGoogleDrive": config.get("AllowGoogleDrive"),
            "AllowShareFile": config.get("AllowShareFile"),
            "AllowEgnyte": config.get("AllowEgnyte"),
        }
        enabled = [name for name, value in providers.items() if value is True]

        evidence = [
            Evidence(
                source="teams/Get-CsTeamsClientConfiguration",
                data=providers,
                description=(
                    "Third-party cloud storage providers allowed for Teams file "
                    "sharing."
                ),
            )
        ]

        if not enabled:
            return self._pass(
                "No third-party cloud storage providers (Dropbox, Box, Google "
                "Drive, ShareFile, Egnyte) are enabled for Teams file sharing.",
                evidence=evidence,
            )

        # CIS's own audit procedure only requires that "organizationally
        # approved" providers be True — which providers are approved is a
        # business decision this data cannot answer, so a non-empty enabled
        # set is left for manual review rather than an automatic FAIL that
        # could wrongly flag a legitimately-approved provider.
        return self._manual(
            message=(
                "The following third-party storage providers are enabled for "
                f"Teams file sharing: {', '.join(enabled)}. Verify each is "
                "organizationally-approved; disable any that are not via "
                "Set-CsTeamsClientConfiguration -Identity Global."
            )
        )
