"""
CIS MS365 9.1.10 (L1) – Ensure service principals cannot access the Microsoft
Fabric API (Manual)

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
class CIS_9_1_10(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.10",
        title="Ensure service principals cannot access the Microsoft Fabric API",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Developer settings:\n"
            "  Check 'Allow service principals to use Fabric APIs' setting"
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

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify service principal access to Microsoft Fabric API:\n"
            "  1. Go to https://app.powerbi.com/admin\n"
            "  2. Navigate to Tenant settings > Developer settings\n"
            "  3. Check 'Allow service principals to use Fabric APIs'\n"
            "  Compliant: Disabled or restricted to specific security groups"
        )
