"""
CIS MS365 8.2.1 (L1) – Ensure external domains are restricted in the Teams
admin center (Automated)

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
class CIS_8_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.1",
        title="Ensure external domains are restricted in the Teams admin center",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Teams external access should be configured to restrict communication "
            "to only approved external domains. Communication with all external "
            "Teams tenants should not be allowed by default."
        ),
        rationale=(
            "Unrestricted external Teams access allows users to communicate with "
            "anyone in any Teams tenant, increasing phishing and social engineering "
            "risks. Restricting to approved domains limits exposure."
        ),
        impact="Users will only be able to communicate with users in approved external domains.",
        audit_procedure=(
            "Connect-MicrosoftTeams.\n"
            "  Get-CsExternalAccessPolicy -Identity Global — ensure "
            "EnableFederationAccess is False.\n\n"
            "OR (the organization-level setting takes precedence and is also a "
            "passing state):\n"
            "  Get-CsTenantFederationConfiguration | fl AllowFederatedUsers, "
            "AllowedDomains — passing if AllowFederatedUsers is False, OR "
            "AllowFederatedUsers is True AND AllowedDomains is restricted to specific "
            "authorized domains (not AllowAllKnownDomains)."
        ),
        remediation=(
            "Microsoft Teams admin center → External access.\n"
            "Configure to allow only specific external domains:\n"
            "  1. Change to 'Allow only specific external domains'\n"
            "  2. Add approved partner domains\n\n"
            "Teams PowerShell:\n"
            "  Set-CsTenantFederationConfiguration -AllowedDomainsAsAList @('partner.com')"
        ),
        default_value="All external domains may be allowed by default.",
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
        tags=["teams", "external-access", "federation", "domain-restriction"],
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
                    "External domain restrictions require the Microsoft Teams "
                    "PowerShell bridge (Connect-MicrosoftTeams with certificate "
                    "app-only auth), which is not configured for this scan. Verify "
                    "manually: Get-CsExternalAccessPolicy -Identity Global — "
                    "ensure EnableFederationAccess is False, OR (org-level setting "
                    "takes precedence, also passing) "
                    "Get-CsTenantFederationConfiguration | fl AllowFederatedUsers, "
                    "AllowedDomains — ensure AllowFederatedUsers is False, or True "
                    "with AllowedDomains restricted to specific authorized domains "
                    "(not AllowAllKnownDomains)."
                )
            )

        evidence = [
            Evidence(
                source=(
                    "teams/Get-CsExternalAccessPolicy + "
                    "Get-CsTenantFederationConfiguration"
                ),
                data={
                    "teams_external_access_policy": ext_policy,
                    "teams_tenant_federation_configuration": fed_config,
                },
                description="Teams external access / federation domain restriction settings.",
            )
        ]

        if ext_policy and ext_policy.get("EnableFederationAccess") is False:
            return self._pass(
                "EnableFederationAccess is False on the Global external access "
                "policy.",
                evidence=evidence,
            )

        if fed_config:
            allow_federated = fed_config.get("AllowFederatedUsers")
            if allow_federated is False:
                return self._pass(
                    "AllowFederatedUsers is False on the tenant federation "
                    "configuration.",
                    evidence=evidence,
                )
            if allow_federated is True:
                # AllowedDomains is a complex nested .NET object (either an
                # "allow all known domains" marker or a specific domain list)
                # whose exact ConvertTo-Json shape is not reliably known —
                # deciding PASS/FAIL here would be a guess, so it's left for
                # manual review rather than risking a wrong verdict.
                return self._manual(
                    message=(
                        "AllowFederatedUsers is True. Whether AllowedDomains is "
                        "restricted to specific authorized domains (compliant) or "
                        "set to allow all known domains (non-compliant) requires "
                        "manual review: Get-CsTenantFederationConfiguration | fl "
                        "AllowedDomains."
                    )
                )

        if ext_policy and ext_policy.get("EnableFederationAccess") is True:
            return self._fail(
                "EnableFederationAccess is True and no restricting "
                "AllowFederatedUsers=False override was found, so external Teams "
                "domains are not restricted.",
                evidence=evidence,
            )

        return self._manual(
            message=(
                "Could not determine external domain restriction status from the "
                "available data. Verify manually: Get-CsExternalAccessPolicy "
                "-Identity Global — ensure EnableFederationAccess is False, OR "
                "Get-CsTenantFederationConfiguration | fl AllowFederatedUsers, "
                "AllowedDomains."
            )
        )
