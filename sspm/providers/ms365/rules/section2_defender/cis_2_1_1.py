"""
CIS MS365 2.1.1 (L1) – Ensure Safe Links for Office Applications is Enabled
(Manual)

Profile Applicability: E5 Level 1

Safe Links scans URLs in real time to protect users from malicious links
in email messages and Office documents.
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
class CIS_2_1_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.1",
        title="Ensure Safe Links for Office Applications is Enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Safe Links in Microsoft Defender for Office 365 provides URL scanning "
            "and rewriting of email messages and Office documents in real time. "
            "It should be enabled for Office applications including Word, Excel, "
            "PowerPoint, and Teams."
        ),
        rationale=(
            "Safe Links protects users from clicking malicious URLs that may have "
            "changed since email delivery. Real-time scanning and blocking of "
            "malicious links significantly reduces the risk of phishing attacks."
        ),
        impact=(
            "URLs in emails and Office documents will be rewritten and checked "
            "before users are allowed to navigate to them. This adds latency to "
            "link clicks."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-SafeLinksPolicy | Select Name, EnableSafeLinksForOffice, "
            "IsEnabled, DeliverMessageAfterScan, EnableForInternalSenders\n\n"
            "Compliant configuration:\n"
            "  • EnableSafeLinksForOffice = True\n"
            "  • IsEnabled = True\n"
            "  • DeliverMessageAfterScan = True\n"
            "  • EnableForInternalSenders = True"
        ),
        remediation=(
            "Microsoft Defender portal (https://security.microsoft.com):\n"
            "  Email & Collaboration > Policies & Rules > Threat policies > Safe Links.\n"
            "  Create or edit a Safe Links policy:\n"
            "  • Enable Safe Links for Office apps\n"
            "  • Apply to all recipients\n\n"
            "PowerShell:\n"
            "  Set-SafeLinksPolicy -Identity 'Default' -EnableSafeLinksForOffice $true "
            "-IsEnabled $true -EnableForInternalSenders $true"
        ),
        default_value="Safe Links is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.3",
                title="Maintain and Enforce Network-Based URL Filters",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "safe-links", "anti-phishing", "email-security"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Safe Links for Office Applications via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-SafeLinksPolicy | Select Name, EnableSafeLinksForOffice, "
            "IsEnabled, DeliverMessageAfterScan\n\n"
            "Compliant: EnableSafeLinksForOffice = True, IsEnabled = True.\n\n"
            "Or verify in Microsoft Defender portal:\n"
            "  https://security.microsoft.com → Email & Collaboration > "
            "Policies & Rules > Threat policies > Safe Links"
        )
