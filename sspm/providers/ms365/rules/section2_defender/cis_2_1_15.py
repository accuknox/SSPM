"""
CIS MS365 2.1.15 (L1) – Ensure outbound anti-spam message limits are in place
(Automated)

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
class CIS_2_1_15(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.15",
        title="Ensure outbound anti-spam message limits are in place",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The outbound spam filter policy should set recipient rate limits and "
            "an action to take once the threshold is reached, so that a "
            "compromised account cannot be used to send large volumes of spam."
        ),
        rationale=(
            "Attackers who compromise email accounts often use them to send large "
            "volumes of spam or phishing emails. Recipient rate limits with an "
            "automatic block action contain the damage a compromised account can do."
        ),
        impact=(
            "Legitimate high-volume senders may be blocked if they exceed the "
            "configured recipient limits. Organizations must evaluate limits "
            "against legitimate business needs."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-HostedOutboundSpamFilterPolicy -Identity Default | fl "
            "RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, "
            "RecipientLimitPerDay, ActionWhenThresholdReached\n\n"
            "Recommended: External <= 500, Internal <= 1000, Daily <= 1000, "
            "ActionWhenThresholdReached = BlockUser. Microsoft's Strict preset "
            "values of 400/800/800 are also compliant (equal or more "
            "restrictive passes). Also verify "
            "NotifyOutboundSpamRecipients contains a monitored mailbox."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-HostedOutboundSpamFilterPolicy -Identity Default "
            "-RecipientLimitExternalPerHour 500 -RecipientLimitInternalPerHour 1000 "
            "-RecipientLimitPerDay 1000 -ActionWhenThresholdReached BlockUser "
            "-NotifyOutboundSpamRecipients admin@contoso.com"
        ),
        default_value="RecipientLimitExternalPerHour=500, "
        "RecipientLimitInternalPerHour=1000, RecipientLimitPerDay=1000, "
        "ActionWhenThresholdReached=BlockUser by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-hostedoutboundspamfilterpolicy",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.5",
                title="Implement DMARC",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "anti-spam", "outbound", "rate-limit", "email-security"],
    )

    async def check(self, data: CollectedData):
        if "hosted_outbound_spam_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the hosted outbound spam filter policy: "
                f"{data.errors.get('hosted_outbound_spam_filter_policy')}"
            )

        # Hosted outbound spam filter policy configuration cannot be read via
        # Microsoft Graph; only Get-HostedOutboundSpamFilterPolicy via
        # Exchange Online Remote PowerShell exposes the recipient rate limit
        # fields and ActionWhenThresholdReached.
        return self._manual(
            message=(
                "Outbound anti-spam recipient limits cannot be read via "
                "Microsoft Graph. Verify via Exchange Online PowerShell: "
                "Get-HostedOutboundSpamFilterPolicy -Identity Default | fl "
                "RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, "
                "RecipientLimitPerDay, ActionWhenThresholdReached (recommended: "
                "External<=500, Internal<=1000, Daily<=1000, "
                "ActionWhenThresholdReached=BlockUser, and "
                "NotifyOutboundSpamRecipients configured)."
            )
        )
