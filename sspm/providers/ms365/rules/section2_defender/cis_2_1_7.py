"""
CIS MS365 2.1.7 (L1) – Ensure that an anti-phishing policy has been created
(Automated)

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
        title="Ensure that an anti-phishing policy has been created",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-AntiPhishPolicy | fl <fields> and Get-AntiPhishRule.\n\n"
            "Verify a custom policy exists with: Enabled=True, "
            "PhishThresholdLevel=3, EnableTargetedUserProtection=True, "
            "EnableOrganizationDomainsProtection=True, "
            "EnableMailboxIntelligence=True, "
            "EnableMailboxIntelligenceProtection=True, "
            "EnableSpoofIntelligence=True, "
            "TargetedUserProtectionAction=Quarantine, "
            "TargetedDomainProtectionAction=Quarantine, "
            "MailboxIntelligenceProtectionAction=Quarantine, "
            "EnableFirstContactSafetyTips=True, "
            "EnableSimilarUsersSafetyTips=True, "
            "EnableSimilarDomainsSafetyTips=True, "
            "EnableUnusualCharactersSafetyTips=True, HonorDmarcPolicy=True."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-phishing.\n"
            "Create a new anti-phishing policy:\n"
            "  • Enable impersonation protection for key users and domains\n"
            "  • Enable mailbox intelligence and spoof intelligence\n"
            "  • Enable safety tips\n"
            "  • Configure action to quarantine\n\n"
            "PowerShell:\n"
            "  New-AntiPhishPolicy -Name 'Custom Anti-Phish' "
            "-EnableMailboxIntelligence $true "
            "-EnableMailboxIntelligenceProtection $true "
            "-EnableSpoofIntelligence $true "
            "-HonorDmarcPolicy $true"
        ),
        default_value="Only the default anti-phishing policy exists.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-mdo-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-antiphishpolicy",
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
        if "anti_phishing_policies" in (data.errors or {}):
            return self._skip(
                "Could not retrieve anti-phishing policies: "
                f"{data.errors.get('anti_phishing_policies')}"
            )

        # Anti-phishing policy configuration cannot be read via Microsoft
        # Graph; only Get-AntiPhishPolicy / Get-AntiPhishRule via Exchange
        # Online Remote PowerShell expose these settings.
        return self._manual(
            message=(
                "Anti-phishing policy configuration cannot be read via "
                "Microsoft Graph. Verify via Exchange Online PowerShell: "
                "Get-AntiPhishPolicy | fl Enabled, PhishThresholdLevel, "
                "EnableTargetedUserProtection, "
                "EnableOrganizationDomainsProtection, "
                "EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, "
                "EnableSpoofIntelligence, HonorDmarcPolicy, and Get-AntiPhishRule "
                "to confirm a custom policy is applied to all recipients."
            )
        )
