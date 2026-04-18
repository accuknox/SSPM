"""
CIS MS365 9.1.5 (L1) – Ensure R and Python visuals are disabled in
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
class CIS_9_1_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.5",
        title="Ensure R and Python visuals are disabled in Microsoft Fabric",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
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
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > R and Python visuals settings:\n"
            "  Check if R and Python visuals are enabled"
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

    async def check(self, data: CollectedData):
        return self._manual()
