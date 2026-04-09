"""
CIS MS365 2.1.7 (L1) – Ensure an anti-phishing policy has been created (Manual)

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
class CIS_2_1_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.7",
        title="Ensure an anti-phishing policy has been created",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "A custom anti-phishing policy should be created in Microsoft Defender "
            "for Office 365 to protect users from impersonation attacks and provide "
            "advanced anti-phishing protection beyond the default settings."
        ),
        rationale=(
            "Anti-phishing policies provide protection against impersonation attacks "
            "where attackers spoof trusted senders or domains. Custom policies allow "
            "organizations to protect their own domains and key users from spoofing."
        ),
        impact=(
            "Emails that appear to impersonate protected users or domains will be "
            "quarantined or tagged, which may cause false positives for legitimate "
            "forwarded emails."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-AntiPhishPolicy | Select Name, Enabled, EnableMailboxIntelligence, "
            "EnableMailboxIntelligenceProtection, EnableSpoofIntelligence, "
            "EnableOrganizationDomainsProtection, TargetedUsersToProtect\n\n"
            "Compliant: A custom policy exists with key anti-phishing features enabled."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-phishing.\n"
            "Create a new anti-phishing policy:\n"
            "  • Enable impersonation protection for key users and domains\n"
            "  • Enable mailbox intelligence\n"
            "  • Enable spoof intelligence\n"
            "  • Configure action to quarantine or redirect\n\n"
            "PowerShell:\n"
            "  New-AntiPhishPolicy -Name 'Custom Anti-Phish' "
            "-EnableMailboxIntelligence $true "
            "-EnableMailboxIntelligenceProtection $true "
            "-EnableSpoofIntelligence $true"
        ),
        default_value="Only the default anti-phishing policy exists.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-mdo-configure",
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
        tags=["defender", "anti-phishing", "email-security", "e5"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify anti-phishing policies via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-AntiPhishPolicy | Select Name, Enabled, "
            "EnableMailboxIntelligence, EnableSpoofIntelligence\n\n"
            "A custom (non-default) policy with impersonation and spoof protection "
            "enabled is compliant."
        )
