"""
CIS MS365 6.5.2 (L2) – Ensure MailTips are enabled for end users (Manual)

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
class CIS_6_5_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.5.2",
        title="Ensure MailTips are enabled for end users",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "MailTips should be enabled to provide users with informational messages "
            "when composing emails that may indicate issues or potential problems, "
            "such as sending to external recipients or large distribution lists."
        ),
        rationale=(
            "MailTips warn users before sending emails that might be sent to the "
            "wrong recipient, contain sensitive data recipients shouldn't see, or "
            "indicate other potential issues, reducing accidental data exposure."
        ),
        impact="No negative impact; MailTips provide helpful reminders to users.",
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, "
            "MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled, "
            "MailTipsLargeAudienceThreshold\n\n"
            "Compliant: MailTipsAllTipsEnabled = True"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-OrganizationConfig -MailTipsAllTipsEnabled $true "
            "-MailTipsExternalRecipientsTipsEnabled $true "
            "-MailTipsGroupMetricsEnabled $true -MailTipsLargeAudienceThreshold 25"
        ),
        default_value="MailTips settings may vary.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/mailtips/mailtips",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="14.1",
                title="Establish and Maintain a Security Awareness Program",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["exchange", "mailtips", "user-awareness", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify MailTips are enabled via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, "
            "MailTipsExternalRecipientsTipsEnabled\n\n"
            "Compliant: MailTipsAllTipsEnabled = True"
        )
