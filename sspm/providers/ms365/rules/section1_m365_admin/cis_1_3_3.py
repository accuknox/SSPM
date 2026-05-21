"""
CIS MS365 1.3.3 (L2) – Ensure external sharing of calendars is not enabled
(Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_1_3_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.3",
        title="Ensure external sharing of calendars is not enabled",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Sharing calendar details externally can expose sensitive information "
            "about employee schedules and business operations. External calendar "
            "sharing should be disabled unless there is a specific business need."
        ),
        rationale=(
            "Calendar data can reveal meeting participants, meeting subjects, and "
            "availability patterns that could be leveraged by attackers for social "
            "engineering, spear phishing, or physical security attacks."
        ),
        impact=(
            "Users will not be able to share their full calendar details with "
            "external recipients. Free/busy information may still be shared based "
            "on configuration."
        ),
        audit_procedure=(
            "Exchange admin center → Organization > Sharing.\n"
            "Check Organization Sharing policies for external sharing with "
            "calendar details enabled.\n\n"
            "Or via Exchange Online PowerShell:\n"
            "  Get-SharingPolicy | Select Name, Domains, Enabled\n"
            "  Look for policies with CalendarSharing or FreeBusySimple permissions "
            "applied to anonymous or external domains."
        ),
        remediation=(
            "Exchange admin center → Organization > Sharing.\n"
            "Edit or remove sharing policies that allow external calendar detail sharing.\n\n"
            "PowerShell:\n"
            "  Set-SharingPolicy -Identity 'Default Sharing Policy' -Enabled $false\n"
            "  Or restrict to FreeBusySimple for external domains."
        ),
        default_value="External calendar sharing may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies",
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
        tags=["exchange", "calendar", "sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        # Calendar sharing is controlled via Exchange Online sharing policies
        # which are not available through Microsoft Graph API.
        # This requires Exchange Online PowerShell.
        return self._manual()
