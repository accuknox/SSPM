"""
CIS MS365 9.1.10 (L1) – Ensure access to APIs by service principals is
restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName ServicePrincipalAccessPermissionAPIs).
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
class CIS_9_1_10(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.10",
        title="Ensure access to APIs by service principals is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Service principals should not have access to the Microsoft Fabric API "
            "unless specifically needed. Broad service principal access can be "
            "exploited if a service principal's credentials are compromised."
        ),
        rationale=(
            "Service principals have persistent, often unmonitored access to Fabric "
            "resources. Restricting API access to service principals reduces the "
            "attack surface and potential for unauthorized data access."
        ),
        impact="Applications using service principals for Fabric API access will need to be reviewed.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Developer settings.\n"
            "  Ensure 'Service principals can call Fabric public APIs' is "
            "Disabled, or Enabled with specific security groups selected.\n\n"
            "Via Fabric REST API (requires delegated Fabric.Admin.All auth):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName ServicePrincipalAccessPermissionAPIs.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Developer settings:\n"
            "  Disable 'Allow service principals to use Fabric APIs' or restrict to specific groups"
        ),
        default_value="Service principal access to Fabric API may be restricted by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/developer/embedded/embed-service-principal",
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
        tags=["fabric", "power-bi", "service-principals", "api-access"],
    )

    SETTING_NAME = "ServicePrincipalAccessPermissionAPIs"

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
        if self._fabric_restricted_or_disabled(setting):
            return self._pass(
                "Access to Fabric public APIs by service principals is "
                "restricted.",
                evidence=evidence,
            )
        return self._fail(
            "Any service principal can call Fabric public APIs (not scoped "
            "to specific security groups).",
            evidence=evidence,
        )
