"""
CIS MS365 2.1.6 (L1) – Ensure Exchange Online Spam Policies notify administrators
(Manual)

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
class CIS_2_1_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.6",
        title="Ensure Exchange Online Spam Policies notify administrators",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Anti-spam content filter policies should be configured to notify "
            "administrators when spam messages are quarantined, allowing security "
            "teams to monitor and respond to spam campaigns."
        ),
        rationale=(
            "Admin notifications for quarantined spam messages help security teams "
            "identify and respond to spam campaigns, phishing attempts, and "
            "potentially compromised accounts sending spam."
        ),
        impact=(
            "Administrators will receive notification emails when spam is quarantined. "
            "This may increase email volume for admin accounts."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-HostedContentFilterPolicy | Select Name, BulkSpamAction, "
            "SpamAction, HighConfidenceSpamAction, QuarantineRetentionPeriod\n\n"
            "Also check:\n"
            "  Get-QuarantinePolicy | Select Name, QuarantinePolicyType, "
            "EndUserQuarantinePermissions"
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-spam.\n"
            "Configure the default inbound spam filter policy to notify "
            "administrators.\n\n"
            "PowerShell:\n"
            "  Set-HostedContentFilterPolicy -Identity Default "
            "-SpamAction Quarantine -HighConfidenceSpamAction Quarantine"
        ),
        default_value="Admin notifications for quarantined spam may not be configured.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-policies-configure",
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
        tags=["defender", "anti-spam", "notifications", "email-security"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify spam policy admin notifications via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-HostedContentFilterPolicy | Select Name, BulkSpamAction, "
            "SpamAction, HighConfidenceSpamAction\n\n"
            "Verify spam is set to Quarantine and notification policies are configured."
        )
