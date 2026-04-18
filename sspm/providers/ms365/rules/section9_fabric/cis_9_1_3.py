"""
CIS MS365 9.1.3 (L1) – Ensure guest access to Microsoft Fabric content is
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
class CIS_9_1_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.3",
        title="Ensure guest access to Microsoft Fabric content is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Guest users should not have unrestricted access to Microsoft Fabric "
            "workspaces and content. Access should be limited to specifically "
            "shared items."
        ),
        rationale=(
            "Broad guest access to Fabric workspaces could expose sensitive "
            "business intelligence data and analytics to external parties."
        ),
        impact="Guest users will only access content explicitly shared with them.",
        audit_procedure=(
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Export and sharing settings:\n"
            "  Review guest access permissions"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Restrict guest user access to specific shared content only"
        ),
        default_value="Guest access settings may vary.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-sharing",
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
        tags=["fabric", "power-bi", "guest-access", "content-access"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
