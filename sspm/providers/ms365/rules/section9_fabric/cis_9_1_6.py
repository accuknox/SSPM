"""
CIS MS365 9.1.6 (L1) – Ensure sensitivity labels are applied to content in
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
class CIS_9_1_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.6",
        title="Ensure sensitivity labels are applied to content in Microsoft Fabric",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Sensitivity labels should be enabled for Microsoft Fabric content "
            "to classify and protect analytics content based on its sensitivity."
        ),
        rationale=(
            "Sensitivity labels on Fabric content ensure consistent classification "
            "and protection policies apply to analytical data and reports, extending "
            "information protection to the BI layer."
        ),
        impact="Content creators will be required to apply sensitivity labels to Fabric items.",
        audit_procedure=(
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Information protection:\n"
            "  Check if sensitivity labels are enabled for Fabric content"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Information protection:\n"
            "  Enable sensitivity labels for Microsoft Fabric"
        ),
        default_value="Sensitivity label integration may not be configured.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/governance/information-protection",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.2",
                title="Establish and Maintain a Data Inventory",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["fabric", "power-bi", "sensitivity-labels", "information-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify sensitivity labels are enabled for Microsoft Fabric:\n"
            "  1. Go to https://app.powerbi.com/admin\n"
            "  2. Navigate to Tenant settings > Information protection\n"
            "  3. Check if sensitivity label capabilities are enabled for Fabric\n"
            "  Compliant: Sensitivity labels are enabled and applied to content"
        )
