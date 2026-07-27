"""
CIS MS365 2.4.1 (L1) – Ensure Priority account protection is enabled and
configured (Automated)

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
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Microsoft 365 Defender portal (https://security.microsoft.com):\n"
            "  Settings > Email & collaboration > Priority account protection.\n"
            "  Verify priority account protection is turned on.\n\n"
            "Also review:\n"
            "  Settings > Email & collaboration > User tags — confirm accounts "
            "are tagged as 'Priority account'.\n"
            "  Email & collaboration > Policies & rules > Alert policy — confirm "
            "priority-account alert policies are enabled.\n\n"
            "Note: CIS publishes no PowerShell or Microsoft Graph audit method "
            "for this control; it is Defender portal (UI) only."
        ),
        remediation=(
            "Microsoft 365 Defender portal → Settings > Email & collaboration > "
            "Priority account protection:\n"
            "  1. Turn on priority account protection.\n"
            "  2. Tag key accounts as priority accounts (User tags).\n"
            "  3. Enable the related alert policies."
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
        if "priority_account_protection" in (data.errors or {}):
            return self._skip(
                "Could not retrieve priority account protection settings: "
                f"{data.errors.get('priority_account_protection')}"
            )

        # Priority account protection has no Microsoft Graph or PowerShell
        # cmdlet published by CIS at all; it is configured and audited solely
        # through the Microsoft 365 Defender portal.
        return self._manual(
            message=(
                "Priority account protection has no Microsoft Graph API or "
                "PowerShell cmdlet published by CIS — it must be verified "
                "manually in the Microsoft 365 Defender portal: Settings > "
                "Email & collaboration > Priority account protection (confirm "
                "it is turned on), User tags (confirm priority accounts are "
                "tagged), and Alert policies (confirm priority-account alerts "
                "are enabled)."
            )
        )
