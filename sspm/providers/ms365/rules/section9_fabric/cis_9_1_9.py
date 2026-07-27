"""
CIS MS365 9.1.9 (L1) – Ensure 'Block ResourceKey Authentication' is 'Enabled'
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName BlockResourceKeyAuthentication).
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
class CIS_9_1_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.9",
        title="Ensure 'Block ResourceKey Authentication' is 'Enabled'",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "ResourceKey authentication in Microsoft Fabric allows access to "
            "datasets and reports using resource keys instead of Azure AD tokens. "
            "This should be blocked to enforce proper authentication."
        ),
        rationale=(
            "ResourceKey authentication bypasses Azure AD-based authentication and "
            "conditional access. Blocking it ensures all access goes through "
            "proper identity verification and MFA enforcement."
        ),
        impact="Applications using ResourceKey authentication will need to migrate to Azure AD.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Developer settings.\n"
            "  Ensure 'Block ResourceKey Authentication' is Enabled.\n\n"
            "Via Fabric REST API (requires delegated Fabric.Admin.All auth):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName BlockResourceKeyAuthentication.\n"
            "  Pass if enabled=true."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Developer settings:\n"
            "  Enable 'Block ResourceKey Authentication'"
        ),
        default_value="ResourceKey authentication may not be blocked by default.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer",
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
        tags=["fabric", "power-bi", "resourcekey-auth", "authentication"],
    )

    SETTING_NAME = "BlockResourceKeyAuthentication"

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
                    "admin portal > Tenant settings > Developer settings."
                )
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
                "ResourceKey authentication is blocked.",
                evidence=evidence,
            )
        return self._fail(
            "ResourceKey authentication is not blocked.",
            evidence=evidence,
        )
