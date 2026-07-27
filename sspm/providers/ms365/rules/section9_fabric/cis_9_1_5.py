"""
CIS MS365 9.1.5 (L2) – Ensure 'Interact with and share R and Python' visuals
is 'Disabled' (Automated)

Profile Applicability: E3 Level 2, E5 Level 2

Automated via the Fabric Admin REST API (GET /v1/admin/tenantsettings,
settingName RScriptVisual).
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
class CIS_9_1_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.5",
        title="Ensure 'Interact with and share R and Python' visuals is 'Disabled'",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "R and Python visuals in Microsoft Fabric execute code that runs "
            "server-side. These should be disabled unless explicitly needed, "
            "as they could be used to execute malicious code."
        ),
        rationale=(
            "R and Python code execution in Fabric visuals can access data and "
            "potentially exfiltrate it or perform unintended operations. "
            "Disabling these reduces the attack surface."
        ),
        impact="Users will not be able to use R or Python visuals in Power BI reports.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin-portal):\n"
            "  Tenant settings > R and Python visuals settings.\n"
            "  Ensure 'Interact with and share R and Python visuals' is Disabled.\n\n"
            "Via Fabric REST API (requires delegated Fabric.Admin.All auth):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings\n"
            "  Locate settingName RScriptVisual. Pass if enabled=false."
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable R visuals and Python visuals"
        ),
        default_value="R and Python visuals may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/visuals/service-r-visuals",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["fabric", "power-bi", "r-visuals", "python-visuals", "code-execution"],
    )

    SETTING_NAME = "RScriptVisual"

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
                    "admin portal > Tenant settings > R and Python visuals settings."
                )
            )

        evidence = [
            Evidence(
                source="fabric/v1/admin/tenantsettings",
                data=setting,
                description=f"Fabric tenant setting: {self.SETTING_NAME}",
            )
        ]
        if not setting.get("enabled"):
            return self._pass(
                "Interact with and share R and Python visuals is disabled.",
                evidence=evidence,
            )
        return self._fail(
            "Interact with and share R and Python visuals is enabled.",
            evidence=evidence,
        )
