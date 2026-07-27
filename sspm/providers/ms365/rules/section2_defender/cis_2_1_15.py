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
    Evidence,
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

    _MAX_EXTERNAL_PER_HOUR = 500
    _MAX_INTERNAL_PER_HOUR = 1000
    _MAX_PER_DAY = 1000

    async def check(self, data: CollectedData):
        if "hosted_outbound_spam_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the hosted outbound spam filter policy: "
                f"{data.errors.get('hosted_outbound_spam_filter_policy')}"
            )

        policy = data.get("hosted_outbound_spam_filter_policy")
        if policy is None:
            return self._manual(
                "Outbound anti-spam recipient limits require the Exchange "
                "Online PowerShell bridge (Connect-ExchangeOnline with "
                "certificate app-only auth), which is not configured for "
                "this scan. Verify manually: "
                "Get-HostedOutboundSpamFilterPolicy -Identity Default | fl "
                "RecipientLimitExternalPerHour, "
                "RecipientLimitInternalPerHour, RecipientLimitPerDay, "
                "ActionWhenThresholdReached (recommended: External<=500, "
                "Internal<=1000, Daily<=1000, "
                "ActionWhenThresholdReached=BlockUser, and "
                "NotifyOutboundSpamRecipients configured)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-HostedOutboundSpamFilterPolicy",
                data=policy,
                description="Hosted outbound spam filter policy (Default).",
            )
        ]

        external = policy.get("RecipientLimitExternalPerHour")
        internal = policy.get("RecipientLimitInternalPerHour")
        daily = policy.get("RecipientLimitPerDay")
        action = policy.get("ActionWhenThresholdReached")

        limits_ok = (
            isinstance(external, (int, float))
            and 0 < external <= self._MAX_EXTERNAL_PER_HOUR
            and isinstance(internal, (int, float))
            and 0 < internal <= self._MAX_INTERNAL_PER_HOUR
            and isinstance(daily, (int, float))
            and 0 < daily <= self._MAX_PER_DAY
            and action == "BlockUser"
        )

        if not limits_ok:
            return self._fail(
                "Outbound anti-spam recipient rate limits are not "
                f"sufficiently restrictive: RecipientLimitExternalPerHour="
                f"{external!r} (max {self._MAX_EXTERNAL_PER_HOUR}), "
                f"RecipientLimitInternalPerHour={internal!r} (max "
                f"{self._MAX_INTERNAL_PER_HOUR}), RecipientLimitPerDay="
                f"{daily!r} (max {self._MAX_PER_DAY}), "
                f"ActionWhenThresholdReached={action!r} (must be "
                "BlockUser).",
                evidence=evidence,
            )

        notify_recipients = policy.get("NotifyOutboundSpamRecipients")
        note = ""
        if not notify_recipients:
            note = (
                " NOTE: NotifyOutboundSpamRecipients is not configured — "
                "the audit procedure also recommends a monitored mailbox "
                "here, though this does not affect the rate-limit "
                "compliance verdict."
            )

        return self._pass(
            "Outbound anti-spam recipient rate limits are compliant "
            f"(External={external}<= {self._MAX_EXTERNAL_PER_HOUR}, "
            f"Internal={internal}<= {self._MAX_INTERNAL_PER_HOUR}, "
            f"Daily={daily}<= {self._MAX_PER_DAY}, "
            f"ActionWhenThresholdReached={action}).{note}",
            evidence=evidence,
        )
