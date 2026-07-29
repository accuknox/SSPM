"""
CIS MS365 7.2.2 (L1) – Ensure SharePoint and OneDrive integration with
Microsoft Entra B2B is enabled (Automated)

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
class CIS_7_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.2",
        title="Ensure SharePoint and OneDrive integration with Microsoft Entra B2B is enabled",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "SharePoint and OneDrive should be integrated with Microsoft Entra B2B "
            "to ensure external users are managed through Entra ID's identity "
            "governance features rather than SharePoint's own guest management."
        ),
        rationale=(
            "Entra B2B integration for SharePoint ensures external users are "
            "properly governed as Entra ID guest accounts with consistent access "
            "controls, MFA requirements, and lifecycle management."
        ),
        impact=(
            "Existing SharePoint-only external users may need to be migrated to "
            "Entra B2B guest accounts."
        ),
        audit_procedure=(
            "Connect to SharePoint Online using Connect-SPOService, then:\n"
            "  Get-SPOTenant | ft EnableAzureADB2BIntegration\n"
            "Ensure the returned value is True."
        ),
        remediation=(
            "SharePoint admin center → Settings > External collaboration.\n"
            "Enable Microsoft Entra B2B integration for SharePoint and OneDrive."
        ),
        default_value="B2B integration setting may vary.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/sharepoint-azureb2b-integration",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "onedrive", "b2b", "external-users"],
    )

    async def check(self, data: CollectedData):
        # EnableAzureADB2BIntegration has no Microsoft Graph equivalent —
        # /admin/sharepoint/settings does not expose it.
        settings, skip = self._spo_tenant_or_skip(
            data, "EnableAzureADB2BIntegration"
        )
        if skip is not None:
            return skip

        b2b_enabled = settings.get("EnableAzureADB2BIntegration")

        evidence = [
            Evidence(
                source="sharepoint/Get-SPOTenant",
                data={"EnableAzureADB2BIntegration": b2b_enabled},
                description="SharePoint/OneDrive Entra B2B integration setting.",
            )
        ]

        if b2b_enabled is True:
            return self._pass(
                "SharePoint/OneDrive Entra B2B integration is enabled.",
                evidence=evidence,
            )

        # Get-SPOTenant always returns the property; its documented default is
        # False, so anything other than True is the non-compliant state.
        return self._fail(
            "SharePoint/OneDrive Entra B2B integration is disabled "
            f"(EnableAzureADB2BIntegration = {b2b_enabled}). External users "
            "are not governed through Entra ID.",
            evidence=evidence,
        )
