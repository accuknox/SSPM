"""
CIS MS365 9.1.6 (L1) – Ensure 'Allow users to apply sensitivity labels for
content' is 'Enabled' (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName EimInformationProtectionEdit).
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
class CIS_9_1_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.6",
        title="Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Sensitivity labels should be enabled for Microsoft Fabric content "
            "to classify and protect analytics content based on its sensitivity."
        ),
        rationale=(
            "Sensitivity labels on Fabric content ensure consistent classification "
            "and protection policies apply to analytical data and reports, extending "
            "information protection to the BI layer."
        ),
        impact="Content creators will be required to apply sensitivity labels to Fabric items.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Information protection.\n"
            "  Ensure 'Allow users to apply sensitivity labels for content' is "
            "Enabled (optionally restricted to specific security groups).\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName EimInformationProtectionEdit.\n"
            "  Pass if enabled=true."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Information protection:\n"
            "  Enable sensitivity labels for Microsoft Fabric"
        ),
        default_value="Sensitivity label integration may not be configured.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/governance/information-protection",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.2",
                title="Establish and Maintain a Data Inventory",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["fabric", "power-bi", "sensitivity-labels", "information-protection"],
    )

    SETTING_NAME = "EimInformationProtectionEdit"

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
                "manually in the Fabric admin portal > Tenant settings > Information protection."
            )

        evidence = [
            Evidence(
                source="fabric/v1/admin/tenantsettings",
                data=setting,
                description=f"Fabric tenant setting: {self.SETTING_NAME}",
            )
        ]
        if setting.get("enabled"):
            return self._pass(
                "Users are allowed to apply sensitivity labels for content.",
                evidence=evidence,
            )
        return self._fail(
            "Users are not allowed to apply sensitivity labels for content.",
            evidence=evidence,
        )
