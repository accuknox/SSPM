"""
CIS MS365 8.2.4 (L1) – Ensure communication with Teams trial tenants is not
allowed (Manual)

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
class CIS_8_2_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.4",
        title="Ensure communication with Teams trial tenants is not allowed",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Communication with Teams trial tenants (free or trial accounts) "
            "should be disabled. Trial tenants may be created by attackers for "
            "phishing or social engineering attacks."
        ),
        rationale=(
            "Trial Teams tenants have lower accountability and may be used by "
            "attackers to impersonate legitimate organizations. Blocking communication "
            "with trial tenants reduces this risk."
        ),
        impact="Communication with free/trial Teams tenants will be blocked.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTenantFederationConfiguration | Select-Object "
            "AllowFederatedUsers, AllowedDomains"
        ),
        remediation=(
            "Microsoft Teams admin center → External access:\n"
            "  Configure to block or restrict communication with unverified/trial tenants.\n\n"
            "Teams PowerShell - restrict to verified domains only."
        ),
        default_value="Trial tenant communication may be allowed if external access is open.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="12.2",
                title="Establish and Maintain a Secure Network Architecture",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "external-access", "trial-tenants"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Teams does not communicate with trial tenants:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTenantFederationConfiguration | Select-Object "
            "AllowFederatedUsers, AllowedDomains\n\n"
            "Compliant: External access is limited to specific approved domains "
            "OR federation is disabled."
        )
