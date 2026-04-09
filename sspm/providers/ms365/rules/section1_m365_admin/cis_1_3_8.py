"""
CIS MS365 1.3.8 (L2) – Ensure Sways cannot be shared with people outside of
your organization (Manual)

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
class CIS_1_3_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.8",
        title="Ensure Sways cannot be shared with people outside of your organization",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Microsoft Sway is a presentation and newsletter tool. External sharing "
            "of Sways could expose sensitive business content to unauthorized "
            "external parties."
        ),
        rationale=(
            "Sway content can include sensitive business information. Restricting "
            "sharing to internal users only prevents accidental data exposure "
            "through publicly accessible Sway links."
        ),
        impact=(
            "Users will not be able to share Sway content publicly or with "
            "external recipients."
        ),
        audit_procedure=(
            "Microsoft 365 admin center → Settings > Org settings > Sway.\n"
            "Verify that 'Let people in your organization share their sways with "
            "people outside your organization' is disabled.\n\n"
            "There is no Microsoft Graph API for Sway settings."
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Sway.\n"
            "Disable external sharing for Sway."
        ),
        default_value="Sway external sharing may be enabled by default.",
        references=[
            "https://support.microsoft.com/en-us/office/administrator-settings-for-microsoft-sway",
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
        tags=["sway", "external-sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Sway external sharing restrictions via the admin center:\n"
            "  1. Go to https://admin.microsoft.com\n"
            "  2. Navigate to Settings > Org settings > Sway\n"
            "  3. Verify that external sharing is disabled\n\n"
            "There is no Microsoft Graph API available for this setting."
        )
