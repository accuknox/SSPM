"""
CIS MS365 8.4.1 (L1) – Ensure Teams app permission policies are configured
(Manual)

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
class CIS_8_4_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.4.1",
        title="Ensure Teams app permission policies are configured",
        section="8.4 Teams Apps",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Teams app permission policies should be configured to restrict "
            "which apps users can install in Teams. Third-party apps should "
            "require admin approval before users can install them."
        ),
        rationale=(
            "Third-party Teams apps can access organizational data and conversations. "
            "Requiring admin approval ensures apps are reviewed before deployment "
            "and prevents users from installing unapproved data-accessing apps."
        ),
        impact="Users must request admin approval to install third-party Teams apps.",
        audit_procedure=(
            "Microsoft Teams admin center → Teams apps > Permission policies.\n"
            "Teams PowerShell:\n"
            "  Get-CsTeamsAppPermissionPolicy | Select-Object Identity, "
            "DefaultCatalogApps, PrivateCatalogApps, GlobalCatalogApps\n\n"
            "Compliant: Third-party apps are blocked or require approval."
        ),
        remediation=(
            "Microsoft Teams admin center → Teams apps > Permission policies.\n"
            "Create or modify the global policy:\n"
            "  • Microsoft apps: Allow all\n"
            "  • Third-party apps: Block all or Allow specific\n"
            "  • Custom apps: Block or Allow specific"
        ),
        default_value="All apps may be allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "apps", "permission-policies", "app-governance"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Teams app permission policies via Microsoft Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsAppPermissionPolicy | Select-Object Identity, "
            "DefaultCatalogApps, PrivateCatalogApps\n\n"
            "Compliant: Third-party apps are blocked or limited in the global policy."
        )
