"""
CIS MS365 6.2.3 (L1) – Ensure email from external senders is identified
(Automated)

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
        title="Ensure email from external senders is identified",
        section="6.2 Mail flow",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-ExternalInOutlook\n\n"
            "For each identity verify Enabled = True and that AllowList only "
            "contains explicitly permitted addresses/domains."
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
        # Get-ExternalInOutlook has no Microsoft Graph equivalent; it is only
        # reachable via Exchange Online Remote PowerShell.
        if "external_in_outlook" in (data.errors or {}):
            return self._skip(
                "Could not retrieve external sender identification settings: "
                f"{data.errors.get('external_in_outlook')}"
            )

        return self._manual(
            message=(
                "External sender identification settings cannot be read via "
                "Microsoft Graph. Verify manually via Exchange Online PowerShell: "
                "Get-ExternalInOutlook - Enabled must be True, and AllowList "
                "should only contain explicitly permitted addresses."
            )
        )
