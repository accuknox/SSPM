"""
CIS MS365 2.1.14 (L1) – Ensure inbound anti-spam policies do not contain
allowed domains (Automated)

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
class CIS_2_1_14(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.14",
        title="Ensure inbound anti-spam policies do not contain allowed domains",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Allowed domains in the inbound anti-spam policy cause all emails from "
            "those domains to bypass spam filtering. This creates a risk if the "
            "domain is compromised or used by attackers to send phishing emails."
        ),
        rationale=(
            "Domains in the allowed domains list bypass spam filtering entirely. "
            "Attackers who know a domain is whitelisted can spoof it or compromise "
            "an account in that domain to send phishing emails that bypass all filtering."
        ),
        impact=(
            "Emails from the removed domains will be subject to normal spam filtering. "
            "This may cause some legitimate emails to be marked as spam initially."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-HostedContentFilterPolicy | ft Identity, "
            "AllowedSenderDomains\n\n"
            "Ensure AllowedSenderDomains is undefined for each inbound policy."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-HostedContentFilterPolicy -Identity Default -AllowedSenderDomains @()\n\n"
            "Remove any domains from the allowed senders list in the anti-spam policy."
        ),
        default_value="AllowedSenderDomains is empty by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-policies-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-hostedcontentfilterpolicy",
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
        tags=["defender", "anti-spam", "allowed-domains", "email-security"],
    )

    async def check(self, data: CollectedData):
        if "hosted_content_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the hosted content filter policy: "
                f"{data.errors.get('hosted_content_filter_policy')}"
            )

        policies = data.get("hosted_content_filter_policy")
        if policies is None:
            return self._skip(
                "Inbound anti-spam allowed sender domains require the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured "
                "for this scan. Verify manually: "
                "Get-HostedContentFilterPolicy | ft Identity, "
                "AllowedSenderDomains (should be undefined/empty for every "
                "inbound policy)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-HostedContentFilterPolicy",
                data=policies,
                description="Hosted content filter policies.",
            )
        ]

        # The audit procedure requires EVERY inbound policy to have no
        # allowed sender domains (not just at least one) — unlike other
        # rules in this section, this is an "all" check, not an "any" check.
        offending = [p for p in policies if p.get("AllowedSenderDomains")]
        if offending:
            names = ", ".join(p.get("Identity", "<unknown>") for p in offending)
            return self._fail(
                f"AllowedSenderDomains is configured on: {names}. This "
                "causes all mail from those domains to bypass spam "
                "filtering.",
                evidence=evidence,
            )

        return self._pass(
            f"AllowedSenderDomains is empty/undefined on all "
            f"{len(policies)} inbound anti-spam policy(ies).",
            evidence=evidence,
        )
