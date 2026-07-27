"""
CIS MS365 8.2.3 (L1) – Ensure external Teams users cannot initiate
conversations (Automated)

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
class CIS_8_2_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.3",
        title="Ensure external Teams users cannot initiate conversations",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "External Teams users should not be able to initiate conversations with "
            "internal users. Internal users should be the ones initiating external "
            "communications."
        ),
        rationale=(
            "Allowing external users to initiate conversations opens the door to "
            "social engineering and phishing via Teams chat. Restricting initiation "
            "to internal users reduces unsolicited external contact."
        ),
        impact="External Teams users will not be able to initiate chats with internal users.",
        audit_procedure=(
            "Connect-MicrosoftTeams.\n"
            "  Get-CsExternalAccessPolicy -Identity Global — ensure "
            "EnableTeamsConsumerInbound is False.\n\n"
            "OR (the organization-level setting takes precedence and is also a "
            "passing state):\n"
            "  Get-CsTenantFederationConfiguration | fl AllowTeamsConsumerInbound — "
            "ensure it is False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerInbound $false"
        ),
        default_value="External users may be able to initiate conversations.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.3",
                title="Maintain and Enforce Network-Based URL Filters",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "external-access", "inbound-communication"],
    )

    async def check(self, data: CollectedData):
        # Get-CsExternalAccessPolicy and Get-CsTenantFederationConfiguration are
        # MicrosoftTeams Remote PowerShell cmdlets with no Microsoft Graph
        # equivalent, so this collector (which only performs Graph
        # client-credentials auth) cannot read them.
        errors = data.errors or {}
        if "teams_external_access_policy" in errors or (
            "teams_tenant_federation_configuration" in errors
        ):
            return self._skip(
                "Could not retrieve Teams external access configuration: "
                f"{errors.get('teams_external_access_policy') or errors.get('teams_tenant_federation_configuration')}"
            )

        return self._manual(
            message=(
                "Whether external Teams users can initiate conversations cannot be "
                "read via Microsoft Graph. Verify manually via Microsoft Teams "
                "PowerShell: Connect-MicrosoftTeams; Get-CsExternalAccessPolicy "
                "-Identity Global — ensure EnableTeamsConsumerInbound is False, OR "
                "(org-level setting takes precedence, also passing) "
                "Get-CsTenantFederationConfiguration | fl AllowTeamsConsumerInbound "
                "— ensure it is False."
            )
        )
