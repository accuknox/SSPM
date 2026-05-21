"""
CIS MS365 8.1.2 (L2) – Ensure users cannot send emails to a channel email
address (Manual)

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
class CIS_8_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.1.2",
        title="Ensure users cannot send emails to a channel email address",
        section="8.1 Teams Client Configuration",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "The ability to email a Teams channel address should be disabled to "
            "reduce the attack surface and prevent use of channel emails for "
            "spam or phishing."
        ),
        rationale=(
            "Channel email addresses can be exploited to inject content into Teams "
            "channels. Disabling this feature reduces the risk of malicious content "
            "being posted via email."
        ),
        impact="Users will not be able to send email messages to Teams channels.",
        audit_procedure=(
            "Microsoft Teams admin center → Teams > Teams settings.\n"
            "Check: 'Email integration' > Allow users to send emails to a channel "
            "email address = Disabled.\n\n"
            "Teams PowerShell:\n"
            "  Get-CsTeamsClientConfiguration | Select-Object AllowEmailIntoChannel"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsClientConfiguration -AllowEmailIntoChannel $false"
        ),
        default_value="Email into channel may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/email-management",
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
        tags=["teams", "email-integration", "channel-email"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
