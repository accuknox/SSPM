"""
CIS MS365 2.1.5 (L1) – Ensure Safe Attachments for SharePoint, OneDrive, and
Microsoft Teams is enabled (Manual)

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
        title="Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Using Exchange Online PowerShell:\n"
            "  Get-AtpPolicyForO365 | Select EnableATPForSPOTeamsODB\n\n"
            "Compliant: EnableATPForSPOTeamsODB = True."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Safe Attachments.\n"
            "Enable 'Turn on Defender for Office 365 for SharePoint, OneDrive, "
            "and Microsoft Teams'.\n\n"
            "PowerShell:\n"
            "  Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true"
        ),
        default_value="Safe Attachments for SPO/ODB/Teams is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure",
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
        return self._manual()
