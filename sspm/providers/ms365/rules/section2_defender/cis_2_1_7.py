"""
CIS MS365 2.1.7 (L1) – Ensure that an anti-phishing policy has been created
(Automated)

Profile Applicability: E5 Level 1
"""

from __future__ import annotations

from typing import ClassVar

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

    _REQUIRED: ClassVar[dict] = {
        "Enabled": True,
        "PhishThresholdLevel": 3,
        "EnableTargetedUserProtection": True,
        "EnableOrganizationDomainsProtection": True,
        "EnableMailboxIntelligence": True,
        "EnableMailboxIntelligenceProtection": True,
        "EnableSpoofIntelligence": True,
        "TargetedUserProtectionAction": "Quarantine",
        "TargetedDomainProtectionAction": "Quarantine",
        "MailboxIntelligenceProtectionAction": "Quarantine",
        "EnableFirstContactSafetyTips": True,
        "EnableSimilarUsersSafetyTips": True,
        "EnableSimilarDomainsSafetyTips": True,
        "EnableUnusualCharactersSafetyTips": True,
        "HonorDmarcPolicy": True,
    }

    def _is_compliant(self, policy: dict) -> bool:
        return all(policy.get(k) == v for k, v in self._REQUIRED.items())

    async def check(self, data: CollectedData):
        if "anti_phishing_policies" in (data.errors or {}):
            return self._skip(
                "Could not retrieve anti-phishing policies: "
                f"{data.errors.get('anti_phishing_policies')}"
            )

        policies = data.get("anti_phishing_policies")
        if policies is None:
            return self._manual(
                "Anti-phishing policy configuration requires the Exchange "
                "Online PowerShell bridge (Connect-ExchangeOnline with "
                "certificate app-only auth), which is not configured for "
                "this scan. Verify manually: Get-AntiPhishPolicy | fl "
                "Enabled, PhishThresholdLevel, EnableTargetedUserProtection, "
                "EnableOrganizationDomainsProtection, "
                "EnableMailboxIntelligence, "
                "EnableMailboxIntelligenceProtection, "
                "EnableSpoofIntelligence, HonorDmarcPolicy, and "
                "Get-AntiPhishRule to confirm a custom policy is applied to "
                "all recipients."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-AntiPhishPolicy",
                data=policies,
                description="Anti-phishing policies.",
            )
        ]

        compliant = [p for p in policies if self._is_compliant(p)]
        if compliant:
            names = ", ".join(p.get("Identity", "<unknown>") for p in compliant)
            return self._pass(
                f"Found a compliant anti-phishing policy: {names}. Rule "
                "scope/priority (Get-AntiPhishRule) was not verified — "
                "confirm it applies to all recipients.",
                evidence=evidence,
            )

        return self._fail(
            "No anti-phishing policy has all required protections enabled "
            f"(checked {len(policies)} policy(ies)).",
            evidence=evidence,
        )
