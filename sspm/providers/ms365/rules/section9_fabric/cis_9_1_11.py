"""
CIS MS365 9.1.11 (L1) – Ensure service principals cannot create profiles in
Microsoft Fabric (Manual)

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
class CIS_9_1_11(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.11",
        title="Ensure service principals cannot create profiles in Microsoft Fabric",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Service principals should not be allowed to create service principal "
            "profiles in Microsoft Fabric. This limits the potential for privilege "
            "escalation through profile creation."
        ),
        rationale=(
            "Service principal profiles in Fabric can be used to access workspace "
            "data. Preventing service principals from creating profiles reduces "
            "the risk of unauthorized data access through compromised service principals."
        ),
        impact="Service principals will not be able to create new profiles.",
        audit_procedure=(
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Developer settings:\n"
            "  Check 'Service principals can create and use profiles' setting"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Developer settings:\n"
            "  Disable 'Service principals can create and use profiles'"
        ),
        default_value="Profile creation by service principals may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/developer/embedded/embed-multi-tenancy",
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
        tags=["fabric", "power-bi", "service-principals", "profiles"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify service principal profile creation in Microsoft Fabric:\n"
            "  1. Go to https://app.powerbi.com/admin\n"
            "  2. Navigate to Tenant settings > Developer settings\n"
            "  3. Check 'Service principals can create and use profiles'\n"
            "  Compliant: Disabled"
        )
