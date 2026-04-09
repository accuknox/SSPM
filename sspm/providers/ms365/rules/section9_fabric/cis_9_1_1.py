"""
CIS MS365 9.1.1 (L1) – Ensure guest user access to Microsoft Fabric is
restricted (Manual)

Profile Applicability: E3 Level 1, E5 Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
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
        title="Ensure guest user access to Microsoft Fabric is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Fabric admin portal (app.powerbi.com/admin):\n"
            "  Tenant settings > Export and sharing settings:\n"
            "  Check 'Allow Azure Active Directory guest users to access Microsoft Fabric'\n\n"
            "Or via Fabric REST API (requires delegated auth):\n"
            "  GET https://api.fabric.microsoft.com/v1/admin/tenantsettings"
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

    async def check(self, data: CollectedData):
        fabric_settings = data.get("fabric_tenant_settings")
        if fabric_settings is None:
            return self._manual(
                "Verify guest access to Microsoft Fabric in the admin portal:\n"
                "  1. Go to https://app.powerbi.com/admin\n"
                "  2. Navigate to Tenant settings > Export and sharing settings\n"
                "  3. Check 'Allow Azure Active Directory guest users to access Microsoft Fabric'\n"
                "  Compliant: Setting is disabled\n\n"
                "Note: Fabric tenant settings require delegated authentication "
                "and are not available via application-only Graph API calls."
            )

        # If we somehow got fabric settings, check them
        # Setting names vary; check common field names
        guest_access = (
            fabric_settings.get("allowAADGuestUsersAccess")
            or fabric_settings.get("aadGuestAccess")
        )
        if guest_access is False:
            from sspm.core.models import Evidence
            return self._pass(
                "Guest user access to Microsoft Fabric is restricted.",
                evidence=[Evidence(
                    source="Fabric tenant settings",
                    data={"guestAccessEnabled": False},
                    description="Guest access setting.",
                )],
            )

        return self._manual(
            "Verify guest access to Microsoft Fabric in the admin portal:\n"
            "  https://app.powerbi.com/admin → Tenant settings"
        )
