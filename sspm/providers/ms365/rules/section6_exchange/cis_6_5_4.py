"""
CIS MS365 6.5.4 (L1) – Ensure SMTP AUTH is disabled (Manual)

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
class CIS_6_5_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.5.4",
        title="Ensure SMTP AUTH is disabled",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "SMTP Authentication (SMTP AUTH) should be disabled at the organization "
            "level to prevent legacy clients from sending email using Basic "
            "Authentication over SMTP port 587."
        ),
        rationale=(
            "SMTP AUTH uses Basic Authentication which cannot enforce MFA. "
            "Attackers who compromise credentials can use SMTP AUTH to send "
            "emails from compromised accounts without triggering MFA challenges."
        ),
        impact=(
            "Devices and applications that send mail via SMTP AUTH will be unable "
            "to authenticate. They must use Microsoft 365 connectors or modern "
            "auth methods instead."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled\n\n"
            "Compliant: SmtpClientAuthenticationDisabled = True"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-TransportConfig -SmtpClientAuthenticationDisabled $true\n\n"
            "For specific applications that require SMTP AUTH, enable it per-mailbox:\n"
            "  Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false"
        ),
        default_value="SMTP AUTH may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.3",
                title="Require MFA for Externally-Exposed Applications",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["exchange", "smtp-auth", "legacy-auth", "email-security"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
