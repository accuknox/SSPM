"""
CIS MS365 9.1.9 (L1) – Ensure Block ResourceKey authentication in
Microsoft Fabric is enabled (Manual)

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
class CIS_9_1_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.9",
        title="Ensure Block ResourceKey authentication in Microsoft Fabric is enabled",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Developer settings:\n"
            "  Check 'Block ResourceKey Authentication' setting"
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

    async def check(self, data: CollectedData):
        return self._manual()
