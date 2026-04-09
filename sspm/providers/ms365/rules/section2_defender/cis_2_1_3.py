"""
CIS MS365 2.1.3 (L1) – Ensure notifications for internal users sending malware
is configured (Manual)

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
class CIS_2_1_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.3",
        title="Ensure notifications for internal users sending malware is configured",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Anti-malware policies should be configured to notify administrators "
            "when internal users send messages containing malware. This provides "
            "early warning of compromised internal accounts."
        ),
        rationale=(
            "When an internal user sends malware, it typically indicates a compromised "
            "account or endpoint. Timely notifications allow security teams to "
            "investigate and respond before significant damage occurs."
        ),
        impact=(
            "Administrators will receive notifications when malware is detected in "
            "messages sent by internal users. This may increase alert volume."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-MalwareFilterPolicy | Select Name, EnableInternalSenderAdminNotifications, "
            "InternalSenderAdminAddress\n\n"
            "Compliant: EnableInternalSenderAdminNotifications = True and "
            "InternalSenderAdminAddress is set to a valid admin email."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-malware.\n"
            "Edit the default policy to enable notifications for internal senders.\n\n"
            "PowerShell:\n"
            "  Set-MalwareFilterPolicy -Identity Default "
            "-EnableInternalSenderAdminNotifications $true "
            "-InternalSenderAdminAddress admin@contoso.com"
        ),
        default_value="Internal sender admin notifications are disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="17.4",
                title="Establish and Maintain an Incident Response Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "anti-malware", "notifications", "email-security"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify internal malware notifications via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-MalwareFilterPolicy | Select Name, "
            "EnableInternalSenderAdminNotifications, InternalSenderAdminAddress\n\n"
            "Compliant: EnableInternalSenderAdminNotifications = True and "
            "InternalSenderAdminAddress is set."
        )
