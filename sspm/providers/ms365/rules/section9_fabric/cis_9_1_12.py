"""
CIS MS365 9.1.12 (L1) – Ensure service principals ability to create
workspaces, connections and deployment pipelines is restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName ServicePrincipalAccessGlobalAPIs).
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
class CIS_9_1_12(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.12",
        title=(
            "Ensure service principals ability to create workspaces, "
            "connections and deployment pipelines is restricted"
        ),
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Service principals should not be able to create Fabric workspaces. "
            "Workspace creation by service principals can lead to uncontrolled "
            "workspace proliferation and makes governance more difficult."
        ),
        rationale=(
            "Restricting workspace creation to humans or authorized service principals "
            "maintains governance over Fabric workspace proliferation and ensures "
            "workspaces are created with proper ownership and purpose."
        ),
        impact="Service principals will not be able to create new Fabric workspaces.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > Developer settings.\n"
            "  Ensure 'Service principals can create workspaces, connections, "
            "and deployment pipelines' is Disabled, or Enabled with specific "
            "security groups selected.\n\n"
            "Via the Fabric admin REST API (app-only; the tenant must enable\n"
            "'Service principals can access read-only admin APIs'):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName ServicePrincipalAccessGlobalAPIs.\n"
            "  Pass if enabled=false, or enabled=true AND "
            "enabledSecurityGroups is non-empty."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Workspace settings:\n"
            "  Restrict workspace creation to specific users/groups only"
        ),
        default_value="Workspace creation restrictions may vary by tenant.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/admin/portal-workspace",
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
        tags=["fabric", "power-bi", "service-principals", "workspace-creation"],
    )

    SETTING_NAME = "ServicePrincipalAccessGlobalAPIs"

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
                "manually in the Fabric admin portal > Tenant settings > Developer settings."
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
                "Service principal ability to create workspaces, "
                "connections, and deployment pipelines is restricted.",
                evidence=evidence,
            )
        return self._fail(
            "Any service principal can create workspaces, connections, and "
            "deployment pipelines (not scoped to specific security groups).",
            evidence=evidence,
        )
