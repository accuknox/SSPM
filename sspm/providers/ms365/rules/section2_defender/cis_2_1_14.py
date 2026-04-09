"""
CIS MS365 2.1.14 (L1) – Ensure the inbound anti-spam policy does not contain
allowed domains (Manual)

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
class CIS_2_1_14(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.14",
        title="Ensure the inbound anti-spam policy does not contain allowed domains",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Using Exchange Online PowerShell:\n"
            "  Get-HostedContentFilterPolicy | Select Name, AllowedSenderDomains\n\n"
            "Compliant: AllowedSenderDomains should be empty or $null for all policies."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-HostedContentFilterPolicy -Identity Default -AllowedSenderDomains @()\n\n"
            "Remove any domains from the allowed senders list in the anti-spam policy."
        ),
        default_value="AllowedSenderDomains is empty by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-policies-configure",
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
        return self._manual(
            "Verify inbound anti-spam allowed domains via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-HostedContentFilterPolicy | Select Name, AllowedSenderDomains\n\n"
            "Compliant: AllowedSenderDomains is empty for all policies."
        )
