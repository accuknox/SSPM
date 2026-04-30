"""
CIS MS365 5.1.2.6 (L2) – Ensure LinkedIn account connections are disabled
(Manual)

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
class CIS_5_1_2_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.2.6",
        title="Ensure LinkedIn account connections are disabled",
        section="5.1.2 Account Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "LinkedIn account connections allow users to connect their Microsoft "
            "work account with their LinkedIn profile, sharing profile data between "
            "the two services. This should be disabled to prevent data leakage."
        ),
        rationale=(
            "LinkedIn connections can expose employee data to LinkedIn's data "
            "processing and may allow data to flow between Microsoft 365 and "
            "LinkedIn, a third-party service not under organizational control."
        ),
        impact=(
            "Users will not be able to connect their Microsoft work account to "
            "LinkedIn or see LinkedIn profile information within Microsoft apps."
        ),
        audit_procedure=(
            "Microsoft Entra admin center → Identity > Users > User settings.\n"
            "Check 'LinkedIn account connections' setting.\n"
            "Compliant: 'No' (disabled for all users)."
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Users > User settings.\n"
            "Set 'LinkedIn account connections' to 'No'."
        ),
        default_value="LinkedIn account connections are enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/users/linkedin-user-consent",
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
        tags=["identity", "linkedin", "data-protection", "social-integration"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
