"""
CIS MS365 9.1.7 (L1) – Ensure shareable links are restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName ShareLinkToEntireOrg).
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
class CIS_9_1_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.7",
        title="Ensure shareable links are restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Shareable links in Microsoft Fabric should be restricted to prevent "
            "users from creating publicly accessible links to reports and dashboards "
            "containing potentially sensitive data."
        ),
        rationale=(
            "Shareable links allow any person with the link to access reports "
            "without authentication. Restricting this feature prevents accidental "
            "public disclosure of business intelligence data."
        ),
        impact="Users will not be able to create shareable links for Fabric content.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Export and sharing settings.\n"
            "  Ensure 'Allow shareable links to grant access to everyone in "
            "your organization' is Disabled, or Enabled with specific "
            "security groups selected.\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName ShareLinkToEntireOrg.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Export and sharing:\n"
            "  Disable or restrict shareable links feature"
        ),
        default_value="Shareable links may be available to all users by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/collaborate-share/service-share-dashboards",
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
        tags=["fabric", "power-bi", "shareable-links", "data-protection"],
    )

    SETTING_NAME = "ShareLinkToEntireOrg"

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
                "Shareable links are restricted.",
                evidence=evidence,
            )
        return self._fail(
            "Shareable links can grant access to everyone in the "
            "organization (not scoped to specific security groups).",
            evidence=evidence,
        )
