"""
CIS MS365 6.2.3 (L1) – Ensure external sender identification in Outlook is
enabled (Manual)

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
class CIS_6_2_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.2.3",
        title="Ensure external sender identification in Outlook is enabled",
        section="6.2 Mail Transport",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "External sender identification should be enabled to show Outlook users "
            "a visual warning when receiving email from external senders. This helps "
            "users identify potential phishing emails."
        ),
        rationale=(
            "Visual cues that an email comes from an external sender help users "
            "be more cautious about clicking links or opening attachments in those "
            "messages, reducing the risk of successful phishing attacks."
        ),
        impact="Users will see a visual indicator on emails from external senders.",
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-ExternalInOutlook | Select-Object Enabled\n\n"
            "Compliant: Enabled = True"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-ExternalInOutlook -Enabled $true"
        ),
        default_value="External sender identification may not be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-junk-email-settings-on-exo-mailboxes",
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
        tags=["exchange", "external-sender", "phishing-awareness", "outlook"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
