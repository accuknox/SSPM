"""
CIS MS365 6.5.3 (L2) – Ensure additional storage providers are restricted in
Outlook on the web (Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_6_5_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.5.3",
        title="Ensure additional storage providers are restricted in Outlook on the web",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Outlook on the web (OWA) should be configured to prevent users from "
            "connecting to third-party cloud storage providers like Dropbox, "
            "Box, and Google Drive."
        ),
        rationale=(
            "Third-party storage providers are not subject to organizational "
            "governance and compliance controls. Restricting access ensures "
            "data stays within approved storage systems."
        ),
        impact="Users will not be able to attach files from third-party storage in OWA.",
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | fl "
            "AdditionalStorageProvidersAvailable\n\n"
            "Compliant: AdditionalStorageProvidersAvailable = False"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Get-OwaMailboxPolicy | Set-OwaMailboxPolicy "
            "-AdditionalStorageProvidersAvailable $false"
        ),
        default_value="Additional storage providers are enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/powershell/module/exchange/set-owamailboxpolicy",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["exchange", "owa", "storage", "third-party"],
    )

    async def check(self, data: CollectedData):
        # Get-OwaMailboxPolicy has no Microsoft Graph equivalent; it is only
        # reachable via Exchange Online Remote PowerShell.
        if "owa_mailbox_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the OWA mailbox policy: "
                f"{data.errors.get('owa_mailbox_policy')}"
            )

        return self._manual(
            message=(
                "The OWA mailbox policy cannot be read via Microsoft Graph. "
                "Verify manually via Exchange Online PowerShell: "
                "Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | fl "
                "AdditionalStorageProvidersAvailable - must be False."
            )
        )
