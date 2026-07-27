"""
CIS MS365 9.1.3 (L1) – Ensure guest access to content is restricted
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName ElevatedGuestsTenant).
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
class CIS_9_1_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.3",
        title="Ensure guest access to content is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Guest users should not have unrestricted access to Microsoft Fabric "
            "workspaces and content. Access should be limited to specifically "
            "shared items."
        ),
        rationale=(
            "Broad guest access to Fabric workspaces could expose sensitive "
            "business intelligence data and analytics to external parties."
        ),
        impact="Guest users will only access content explicitly shared with them.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Export and sharing settings.\n"
            "  Ensure 'Guest users can browse and access Fabric content' is "
            "Disabled, or Enabled with specific security groups selected.\n\n"
            "Via Fabric REST API (requires delegated Fabric.Admin.All auth):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName ElevatedGuestsTenant.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Restrict guest user access to specific shared content only"
        ),
        default_value="Guest access settings may vary.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-sharing",
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
        tags=["fabric", "power-bi", "guest-access", "content-access"],
    )

    SETTING_NAME = "ElevatedGuestsTenant"

    async def check(self, data: CollectedData):
        if "fabric_tenant_settings" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Microsoft Fabric tenant settings: "
                f"{data.errors.get('fabric_tenant_settings')}"
            )

        setting = self._get_fabric_setting(data, self.SETTING_NAME)
        if setting is None:
            return self._manual(
                message=(
                    "Microsoft Fabric tenant settings are not available "
                    "(requires delegated Fabric.Admin.All authentication, not "
                    "available via client-credentials Graph auth). Verify "
                    f"manually: settingName {self.SETTING_NAME} in the Fabric "
                    "admin portal > Tenant settings > Export and sharing settings."
                )
            )

        evidence = [
            Evidence(
                source="fabric/v1/admin/tenantsettings",
                data=setting,
                description=f"Fabric tenant setting: {self.SETTING_NAME}",
            )
        ]
        if self._fabric_restricted_or_disabled(setting):
            return self._pass(
                "Guest access to Microsoft Fabric content is restricted.",
                evidence=evidence,
            )
        return self._fail(
            "Guest access to Microsoft Fabric content is enabled for the "
            "entire organization (not scoped to specific security groups).",
            evidence=evidence,
        )
