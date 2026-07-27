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
    Evidence,
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

        identities = data.get("external_in_outlook")
        if identities is None:
            return self._manual(
                "External sender identification settings require the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured for "
                "this scan. Verify manually: Get-ExternalInOutlook - Enabled "
                "must be True, and AllowList should only contain explicitly "
                "permitted addresses/domains."
            )

        if not identities:
            return self._manual(
                "Get-ExternalInOutlook returned no identities to evaluate; "
                "verify manually."
            )

        evidence = [
            Evidence(
                source="Get-ExternalInOutlook",
                data=identities,
                description="External sender identification settings per identity.",
            )
        ]

        disabled = [
            i.get("Identity", "") for i in identities if not i.get("Enabled")
        ]
        if disabled:
            return self._fail(
                "External sender identification is not enabled for: "
                + ", ".join(disabled),
                evidence=evidence,
            )

        allow_lists = {
            i.get("Identity", ""): i.get("AllowList")
            for i in identities
            if i.get("AllowList")
        }
        message = "External sender identification (Enabled = True) is configured for all identities."
        if allow_lists:
            message += (
                " Note: one or more identities have an AllowList configured "
                "- manually confirm it only contains explicitly permitted "
                f"addresses/domains: {allow_lists}"
            )

        return self._pass(message, evidence=evidence)
