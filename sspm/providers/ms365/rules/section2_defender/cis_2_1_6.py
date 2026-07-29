"""
CIS MS365 2.1.6 (L1) – Ensure Exchange Online Spam Policies are set to notify
administrators (Automated)

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
class CIS_2_1_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.6",
        title="Ensure Exchange Online Spam Policies are set to notify administrators",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The outbound spam filter policy should be configured to notify "
            "administrators when a user is detected sending suspicious outbound "
            "email, allowing security teams to identify and respond to "
            "compromised accounts."
        ),
        rationale=(
            "Admin notifications for suspicious outbound spam help security teams "
            "identify and respond to compromised accounts before they can be used "
            "to send large volumes of spam or phishing emails."
        ),
        impact=(
            "Administrators will receive notification emails when outbound spam is "
            "detected. This may increase email volume for admin accounts."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, Notify*\n\n"
            "Verify BccSuspiciousOutboundMail = True and NotifyOutboundSpam = True, "
            "with correctly configured notification email addresses."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-spam > Outbound spam filter policy.\n"
            "Enable notifications for suspicious outbound activity.\n\n"
            "PowerShell:\n"
            "  Set-HostedOutboundSpamFilterPolicy -Identity Default "
            "-BccSuspiciousOutboundMail $true "
            "-BccSuspiciousOutboundAdditionalRecipients admin@contoso.com "
            "-NotifyOutboundSpam $true "
            "-NotifyOutboundSpamRecipients admin@contoso.com"
        ),
        default_value="Admin notifications for outbound spam may not be configured.",
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
        tags=["defender", "anti-spam", "notifications", "email-security"],
    )

    async def check(self, data: CollectedData):
        if "hosted_outbound_spam_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the hosted outbound spam filter policy: "
                f"{data.errors.get('hosted_outbound_spam_filter_policy')}"
            )

        policy = data.get("hosted_outbound_spam_filter_policy")
        if policy is None:
            return self._skip(
                "Outbound spam admin notification settings require the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured "
                "for this scan. Verify manually: "
                "Get-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, "
                "Notify* (expect BccSuspiciousOutboundMail=True and "
                "NotifyOutboundSpam=True with correct email addresses)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-HostedOutboundSpamFilterPolicy",
                data=policy,
                description="Hosted outbound spam filter policy (Default).",
            )
        ]

        if (
            policy.get("BccSuspiciousOutboundMail") is True
            and policy.get("NotifyOutboundSpam") is True
        ):
            return self._pass(
                "Admin notifications for outbound spam are enabled "
                "(BccSuspiciousOutboundMail=True, NotifyOutboundSpam=True).",
                evidence=evidence,
            )

        return self._fail(
            "Admin notifications for outbound spam are not fully enabled: "
            f"BccSuspiciousOutboundMail={policy.get('BccSuspiciousOutboundMail')!r}, "
            f"NotifyOutboundSpam={policy.get('NotifyOutboundSpam')!r}.",
            evidence=evidence,
        )
