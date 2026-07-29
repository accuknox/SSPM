"""
CIS MS365 9.1.8 (L1) – Ensure enabling of external data sharing is restricted
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName EnableDatasetInPlaceSharing).
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
class CIS_9_1_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.8",
        title="Ensure enabling of external data sharing is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.LOW,
        description=(
            "External data sharing in Microsoft Fabric allows workspace data to be "
            "shared with external organizations' Fabric workspaces. This should be "
            "restricted to prevent uncontrolled data sharing."
        ),
        rationale=(
            "External data sharing can result in live connections to organizational "
            "datasets from external organizations' Fabric environments, creating "
            "ongoing data access that may be difficult to revoke."
        ),
        impact="Users will not be able to set up cross-tenant data sharing for Fabric.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Export and sharing settings.\n"
            "  Ensure 'Allow specific users to turn on external data sharing' "
            "is Disabled, or Enabled with specific security groups selected.\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName EnableDatasetInPlaceSharing.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable or restrict external data sharing"
        ),
        default_value="External data sharing settings may vary.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/governance/external-data-sharing-overview",
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
        tags=["fabric", "power-bi", "external-data-sharing", "cross-tenant"],
    )

    SETTING_NAME = "EnableDatasetInPlaceSharing"

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
                "Enabling of external data sharing is restricted.",
                evidence=evidence,
            )
        return self._fail(
            "Any user can turn on external data sharing (not scoped to "
            "specific security groups).",
            evidence=evidence,
        )
