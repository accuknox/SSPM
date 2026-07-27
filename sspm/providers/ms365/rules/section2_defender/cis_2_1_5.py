"""
CIS MS365 2.1.5 (L1) – Ensure Safe Attachments for SharePoint, OneDrive, and
Microsoft Teams is Enabled (Automated)

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
class CIS_2_1_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.5",
        title="Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Safe Attachments for SharePoint, OneDrive, and Teams scans files "
            "stored in these services for malware. When a malicious file is detected, "
            "it is blocked from download and the file owner is notified."
        ),
        rationale=(
            "Files shared via SharePoint, OneDrive, and Teams can spread malware "
            "if not scanned. Enabling Safe Attachments for these services provides "
            "protection against malware propagation through collaboration tools."
        ),
        impact=(
            "Files identified as malicious will be blocked. Users who uploaded "
            "an infected file will be notified."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-AtpPolicyForO365 | fl Name, EnableATPForSPOTeamsODB, "
            "EnableSafeDocs, AllowSafeDocsOpen\n\n"
            "Verify EnableATPForSPOTeamsODB = True, EnableSafeDocs = True, and "
            "AllowSafeDocsOpen = False."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Safe Attachments.\n"
            "Enable 'Turn on Defender for Office 365 for SharePoint, OneDrive, "
            "and Microsoft Teams'.\n\n"
            "PowerShell:\n"
            "  Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true "
            "-EnableSafeDocs $true -AllowSafeDocsOpen $false"
        ),
        default_value="Safe Attachments for SPO/ODB/Teams is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-atppolicyforo365",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.6",
                title="Block Unnecessary File Types",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "safe-attachments", "sharepoint", "teams", "onedrive", "e5"],
    )

    async def check(self, data: CollectedData):
        if "atp_policy_for_o365" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the ATP policy for Office 365: "
                f"{data.errors.get('atp_policy_for_o365')}"
            )

        # ATP policy for Office 365 configuration cannot be read via Microsoft
        # Graph; only Get-AtpPolicyForO365 via Exchange Online Remote
        # PowerShell exposes EnableATPForSPOTeamsODB, EnableSafeDocs, and
        # AllowSafeDocsOpen.
        return self._manual(
            message=(
                "Safe Attachments for SharePoint/OneDrive/Teams cannot be read "
                "via Microsoft Graph. Verify via Exchange Online PowerShell: "
                "Get-AtpPolicyForO365 | fl Name, EnableATPForSPOTeamsODB, "
                "EnableSafeDocs, AllowSafeDocsOpen (expect "
                "EnableATPForSPOTeamsODB=True, EnableSafeDocs=True, "
                "AllowSafeDocsOpen=False)."
            )
        )
