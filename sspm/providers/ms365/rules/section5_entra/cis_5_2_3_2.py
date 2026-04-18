"""
CIS MS365 5.2.3.2 (L1) – Ensure custom banned passwords are set (Automated)

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
class CIS_5_2_3_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.2",
        title="Ensure custom banned passwords are set",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Entra Password Protection should be configured with a "
            "custom banned password list specific to the organization. This "
            "prevents users from using company-specific weak passwords."
        ),
        rationale=(
            "Default banned password lists may not include organization-specific "
            "terms (company name, product names, locations) that attackers commonly "
            "use in password spray attacks. Custom lists enhance protection."
        ),
        impact=(
            "Users attempting to set passwords that match custom banned terms will "
            "be rejected and must choose a different password."
        ),
        audit_procedure=(
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Password protection.\n"
            "Verify:\n"
            "  • 'Enforce custom list' is set to 'Yes'\n"
            "  • Custom banned password list contains organization-relevant terms\n\n"
            "There is no Microsoft Graph API to read the banned password list."
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Password protection.\n"
            "Enable 'Enforce custom list' and add organization-specific terms:\n"
            "  • Company name and abbreviations\n"
            "  • Product names\n"
            "  • Office locations\n"
            "  • Common patterns used by your organization"
        ),
        default_value="Custom banned passwords are not configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad",
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
        tags=["identity", "passwords", "password-protection", "banned-passwords"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
