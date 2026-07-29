"""
CIS MS365 9.1.1 (L1) – Ensure guest user access is restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Per the official CIS Microsoft 365 Foundations Benchmark v6.0.1, this control
is Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName AllowGuestUserToAccessSharedContent). The benchmark's own
"Appendix: Summary Table" mislabels the whole Fabric section (9.1.x) as
Manual, but the main body text and audit procedure are unambiguous.
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
class CIS_9_1_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.1",
        title="Ensure guest user access is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Guest user access to Microsoft Fabric should be restricted to prevent "
            "external users from accessing sensitive data analytics and BI content "
            "without proper authorization."
        ),
        rationale=(
            "Microsoft Fabric may contain sensitive business data in datasets, "
            "reports, and dashboards. Restricting guest access prevents unauthorized "
            "external access to potentially sensitive analytical data."
        ),
        impact="Guest users will not be able to access Fabric content without explicit approval.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Export and sharing settings.\n"
            "  Ensure 'Guest users can access Microsoft Fabric' is Disabled, "
            "or Enabled with specific security groups selected.\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName AllowGuestUserToAccessSharedContent.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable 'Allow Azure Active Directory guest users to access Microsoft Fabric'"
        ),
        default_value="Guest access to Fabric may be enabled by default.",
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
        tags=["fabric", "power-bi", "guest-access", "data-analytics"],
    )

    SETTING_NAME = "AllowGuestUserToAccessSharedContent"

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
                "Guest user access to Microsoft Fabric is restricted.",
                evidence=evidence,
            )
        return self._fail(
            "Guest user access to Microsoft Fabric is enabled for the entire "
            "organization (not scoped to specific security groups).",
            evidence=evidence,
        )
