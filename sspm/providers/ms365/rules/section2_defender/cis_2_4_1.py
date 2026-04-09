"""
CIS MS365 2.4.1 (L1) – Ensure Priority account protection is enabled and
configured (Manual)

Profile Applicability: E5 Level 1
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
class CIS_2_4_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.4.1",
        title="Ensure Priority account protection is enabled and configured",
        section="2.4 Microsoft Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Priority account protection in Microsoft Defender for Office 365 "
            "provides enhanced protection for accounts that are designated as "
            "priority accounts (executives, key financial personnel, etc.)."
        ),
        rationale=(
            "Priority accounts are high-value targets for attackers. Enhanced "
            "protection ensures that these accounts receive additional scrutiny "
            "and tighter security policies."
        ),
        impact=(
            "Priority account users may experience more aggressive filtering "
            "and more frequent authentication challenges."
        ),
        audit_procedure=(
            "Microsoft Defender portal (https://security.microsoft.com):\n"
            "  Settings > Email & collaboration > User tags\n"
            "  Verify priority accounts are tagged and protected.\n\n"
            "Microsoft 365 admin center:\n"
            "  Setup > Priority account protection"
        ),
        remediation=(
            "Microsoft 365 admin center → Setup > Priority account protection:\n"
            "  1. Enable priority account protection\n"
            "  2. Tag key accounts as priority accounts\n"
            "  3. Configure enhanced protection settings"
        ),
        default_value="Priority account protection is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/priority-accounts-turn-on-priority-account-protection",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "priority-accounts", "e5", "email-security"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Priority account protection via Microsoft Defender portal:\n"
            "  1. Go to https://security.microsoft.com\n"
            "  2. Navigate to Settings > Email & collaboration > User tags\n"
            "  3. Verify priority accounts are tagged\n"
            "  4. Verify priority account protection policies are applied\n\n"
            "Or via Microsoft 365 admin center:\n"
            "  Setup > Priority account protection"
        )
