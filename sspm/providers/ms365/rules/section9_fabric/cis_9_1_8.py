"""
CIS MS365 9.1.8 (L2) – Ensure external data sharing in Microsoft Fabric is
restricted (Manual)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_9_1_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.8",
        title="Ensure external data sharing in Microsoft Fabric is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "External data sharing in Microsoft Fabric allows workspace data to be "
            "shared with external organizations' Fabric workspaces. This should be "
            "restricted to prevent uncontrolled data sharing."
        ),
        rationale=(
            "External data sharing can result in live connections to organizational "
            "datasets from external organizations' Fabric environments, creating "
            "ongoing data access that may be difficult to revoke."
        ),
        impact="Users will not be able to set up cross-tenant data sharing for Fabric.",
        audit_procedure=(
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Export and sharing settings:\n"
            "  Check 'External data sharing' settings"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable or restrict external data sharing"
        ),
        default_value="External data sharing settings may vary.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/governance/external-data-sharing-overview",
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
        tags=["fabric", "power-bi", "external-data-sharing", "cross-tenant"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify external data sharing restrictions in Microsoft Fabric:\n"
            "  1. Go to https://app.powerbi.com/admin\n"
            "  2. Navigate to Tenant settings > Export and sharing settings\n"
            "  3. Check external data sharing settings\n"
            "  Compliant: External data sharing is disabled or restricted"
        )
