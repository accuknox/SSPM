"""
CIS MS365 9.1.12 (L1) – Ensure service principals workspace creation in
Microsoft Fabric is restricted (Manual)

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
class CIS_9_1_12(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.12",
        title="Ensure service principals workspace creation in Microsoft Fabric is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Workspace settings:\n"
            "  Check if service principals can create workspaces"
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

    async def check(self, data: CollectedData):
        return self._manual()
