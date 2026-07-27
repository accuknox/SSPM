"""
CIS MS365 8.2.4 (L1) – Ensure the organization cannot communicate with
accounts in trial Teams tenants (Automated)

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
class CIS_8_2_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.4",
        title="Ensure the organization cannot communicate with accounts in trial Teams tenants",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Connect-MicrosoftTeams.\n"
            "  Get-CsTenantFederationConfiguration — ensure "
            "ExternalAccessWithTrialTenants is set to Blocked."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked"
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
        # Get-CsTenantFederationConfiguration is a MicrosoftTeams Remote
        # PowerShell cmdlet with no Microsoft Graph equivalent, so this
        # collector (which only performs Graph client-credentials auth)
        # cannot read it.
        if "teams_tenant_federation_configuration" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Teams tenant federation configuration: "
                f"{data.errors.get('teams_tenant_federation_configuration')}"
            )

        fed_config = data.get("teams_tenant_federation_configuration")
        if fed_config is None:
            return self._manual(
                message=(
                    "Communication with trial Teams tenants requires the "
                    "Microsoft Teams PowerShell bridge (Connect-MicrosoftTeams "
                    "with certificate app-only auth), which is not configured "
                    "for this scan. Verify manually: "
                    "Get-CsTenantFederationConfiguration — ensure "
                    "ExternalAccessWithTrialTenants is set to Blocked."
                )
            )

        value = fed_config.get("ExternalAccessWithTrialTenants")
        evidence = [
            Evidence(
                source="teams/Get-CsTenantFederationConfiguration",
                data={"ExternalAccessWithTrialTenants": value},
                description="Whether communication with trial Teams tenants is blocked.",
            )
        ]

        if value == "Blocked":
            return self._pass(
                "ExternalAccessWithTrialTenants is Blocked.", evidence=evidence
            )
        return self._fail(
            f"ExternalAccessWithTrialTenants is {value!r}, not Blocked; "
            "communication with trial Teams tenants is not fully restricted.",
            evidence=evidence,
        )
