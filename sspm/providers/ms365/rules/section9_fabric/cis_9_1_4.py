"""
CIS MS365 9.1.4 (L1) – Ensure 'Publish to web' is restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName PublishToWebPublishToWeb).
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
class CIS_9_1_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.4",
        title="Ensure 'Publish to web' is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The 'Publish to web' feature in Microsoft Fabric (Power BI) allows "
            "reports to be published publicly on the internet. This should be "
            "disabled or restricted to prevent accidental public exposure of "
            "sensitive data."
        ),
        rationale=(
            "'Publish to web' creates anonymous, publicly accessible links to "
            "reports. If a user accidentally publishes a sensitive report, the "
            "data is exposed to anyone on the internet."
        ),
        impact="Users will not be able to publish reports to the public web.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Export and sharing settings.\n"
            "  Ensure 'Publish to web' is Disabled, or Enabled with 'Choose how "
            "embed codes work' set to 'Only allow existing codes' AND specific "
            "security groups selected.\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName PublishToWebPublishToWeb.\n"
            "  Pass if enabled=false, or enabled=true AND properties.createP2w=false "
            "AND enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable 'Publish to web' or restrict to specific security groups"
        ),
        default_value="Publish to web may be enabled for all users by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/collaborate-share/service-publish-to-web",
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
        tags=["fabric", "power-bi", "publish-to-web", "public-access"],
    )

    SETTING_NAME = "PublishToWebPublishToWeb"

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

        create_p2w = str(
            self._fabric_property(setting, "createP2w", "false")
        ).lower() == "true"
        evidence = [
            Evidence(
                source="fabric/v1/admin/tenantsettings",
                data=setting,
                description=f"Fabric tenant setting: {self.SETTING_NAME}",
            )
        ]

        if not setting.get("enabled"):
            return self._pass(
                "'Publish to web' is disabled in Microsoft Fabric.",
                evidence=evidence,
            )
        if not create_p2w and setting.get("enabledSecurityGroups"):
            return self._pass(
                "'Publish to web' is enabled but restricted to existing embed "
                "codes and specific security groups.",
                evidence=evidence,
            )
        return self._fail(
            "'Publish to web' is enabled without restricting to existing "
            "embed codes and specific security groups.",
            evidence=evidence,
        )
