"""
CIS MS365 5.2.3.3 (L1) – Ensure password protection is enabled for on-premises
Active Directory (Manual)

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
class CIS_5_2_3_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.3",
        title="Ensure password protection is enabled for on-premises Active Directory",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "For hybrid environments, Microsoft Entra Password Protection agents "
            "should be installed on on-premises Active Directory domain controllers "
            "to enforce the same banned password policies on-premises."
        ),
        rationale=(
            "Without on-premises password protection, users can set weak passwords "
            "in on-premises AD that may be synced to Entra ID, bypassing cloud "
            "password protection policies."
        ),
        impact=(
            "Requires installation of the Microsoft Entra Password Protection proxy "
            "service and DC agent on on-premises infrastructure."
        ),
        audit_procedure=(
            "On-premises Active Directory:\n"
            "  1. Verify Microsoft Entra Password Protection proxy service is installed\n"
            "  2. Verify DC agents are installed on domain controllers\n"
            "  3. Check audit mode vs enforcement mode\n\n"
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Password protection\n"
            "  Check 'Enable password protection on Windows Server Active Directory'"
        ),
        remediation=(
            "1. Download the Microsoft Entra Password Protection proxy installer\n"
            "2. Install on a domain-joined server with connectivity to Entra ID\n"
            "3. Install DC agents on all domain controllers\n"
            "4. Configure enforcement mode in Entra admin center"
        ),
        default_value="On-premises password protection is not installed by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "passwords", "on-premises", "ad", "hybrid"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
