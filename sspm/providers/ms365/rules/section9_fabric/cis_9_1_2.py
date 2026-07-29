"""
CIS MS365 9.1.2 (L1) – Ensure external user invitations are restricted
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName ExternalSharingV2).
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
class CIS_9_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.2",
        title="Ensure external user invitations are restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The ability to invite external users to Microsoft Fabric content should "
            "be restricted to prevent unauthorized sharing of analytical content "
            "with external parties."
        ),
        rationale=(
            "Unrestricted external user invitations can result in sensitive business "
            "intelligence content being shared with external parties without proper "
            "authorization."
        ),
        impact="Users will not be able to invite external users to Fabric content directly.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Export and sharing settings.\n"
            "  Ensure 'Users can invite guest users to collaborate through item "
            "sharing and permissions' is Disabled, or Enabled with specific "
            "security groups selected.\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName ExternalSharingV2.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable 'Invite external users to your organization through Microsoft Fabric'"
        ),
        default_value="External user invitations may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-sharing",
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
        tags=["fabric", "power-bi", "external-invitations", "data-analytics"],
    )

    SETTING_NAME = "ExternalSharingV2"

    async def check(self, data: CollectedData):
        if "fabric_tenant_settings" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Microsoft Fabric tenant settings: "
                f"{data.errors.get('fabric_tenant_settings')}"
            )

        setting = self._get_fabric_setting(data, self.SETTING_NAME)
        if setting is None:
            return self._skip(
                "The Microsoft Fabric admin API did not return a "
                f"{self.SETTING_NAME} setting for this tenant. Verify "
                "manually in the Fabric admin portal > Tenant settings > Export and sharing settings."
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
                "External user invitations to Microsoft Fabric are restricted.",
                evidence=evidence,
            )
        return self._fail(
            "External user invitations to Microsoft Fabric are enabled for "
            "the entire organization (not scoped to specific security groups).",
            evidence=evidence,
        )
