"""
CIS MS365 8.2.2 (L1) – Ensure communication with unmanaged Teams users is
disabled (Automated)

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
class CIS_8_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.2",
        title="Ensure communication with unmanaged Teams users is disabled",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Communication with unmanaged Teams users (those who use Teams without "
            "a work or school account) should be disabled to prevent data leakage "
            "to consumer accounts."
        ),
        rationale=(
            "Unmanaged Teams accounts (personal/consumer) don't have the same "
            "governance as organizational accounts. Disabling communication with "
            "them prevents sensitive business data from being shared with consumer accounts."
        ),
        impact="Users will not be able to communicate with personal/consumer Teams accounts.",
        audit_procedure=(
            "Connect-MicrosoftTeams.\n"
            "  Get-CsExternalAccessPolicy -Identity Global — ensure "
            "EnableTeamsConsumerAccess is False.\n\n"
            "OR (the organization-level setting takes precedence and is also a "
            "passing state):\n"
            "  Get-CsTenantFederationConfiguration | fl AllowTeamsConsumer — ensure "
            "it is False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $false"
        ),
        default_value="Communication with unmanaged Teams users may be enabled.",
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
        tags=["teams", "external-access", "unmanaged-users", "consumer-accounts"],
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

        ext_policy = data.get("teams_external_access_policy")
        fed_config = data.get("teams_tenant_federation_configuration")

        if ext_policy is None and fed_config is None:
            return self._manual(
                message=(
                    "Unmanaged (consumer) Teams communication settings require "
                    "the Microsoft Teams PowerShell bridge (Connect-MicrosoftTeams "
                    "with certificate app-only auth), which is not configured for "
                    "this scan. Verify manually: Get-CsExternalAccessPolicy "
                    "-Identity Global — ensure EnableTeamsConsumerAccess is False, "
                    "OR (org-level setting takes precedence, also passing) "
                    "Get-CsTenantFederationConfiguration | fl AllowTeamsConsumer — "
                    "ensure it is False."
                )
            )

        ext_value = ext_policy.get("EnableTeamsConsumerAccess") if ext_policy else None
        fed_value = fed_config.get("AllowTeamsConsumer") if fed_config else None

        evidence = [
            Evidence(
                source=(
                    "teams/Get-CsExternalAccessPolicy + "
                    "Get-CsTenantFederationConfiguration"
                ),
                data={
                    "EnableTeamsConsumerAccess": ext_value,
                    "AllowTeamsConsumer": fed_value,
                },
                description="Communication with unmanaged (consumer) Teams accounts.",
            )
        ]

        if ext_value is False or fed_value is False:
            return self._pass(
                "Communication with unmanaged (consumer) Teams users is "
                "disabled.",
                evidence=evidence,
            )
        if ext_value is True or fed_value is True:
            return self._fail(
                "Communication with unmanaged (consumer) Teams users is enabled "
                f"(EnableTeamsConsumerAccess={ext_value!r}, "
                f"AllowTeamsConsumer={fed_value!r}).",
                evidence=evidence,
            )
        return self._manual(
            message=(
                "Could not determine unmanaged Teams communication status from "
                "the available data. Verify manually: Get-CsExternalAccessPolicy "
                "-Identity Global | fl EnableTeamsConsumerAccess, OR "
                "Get-CsTenantFederationConfiguration | fl AllowTeamsConsumer."
            )
        )
