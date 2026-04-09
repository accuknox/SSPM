"""
CIS MS365 1.3.9 (L2) – Ensure that Bookings is restricted to internal users
(Manual)

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
class CIS_1_3_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.9",
        title="Ensure that Bookings is restricted to internal users",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Microsoft Bookings allows users to create publicly accessible booking "
            "pages. This capability should be restricted to prevent exposure of "
            "employee availability and information to unauthorized external users."
        ),
        rationale=(
            "Public Bookings pages expose employee availability and contact "
            "information to anyone on the internet, which could be leveraged for "
            "social engineering or spear phishing attacks."
        ),
        impact=(
            "External customers will not be able to book appointments through "
            "public-facing Bookings pages."
        ),
        audit_procedure=(
            "Microsoft 365 admin center → Settings > Org settings > Bookings.\n"
            "Verify that 'Allow your organization to use Bookings' is set to "
            "'Only allow licensed users to create Bookings calendars' or is disabled.\n\n"
            "Also verify 'Allow Bookings pages to be publicly accessible' is disabled.\n\n"
            "There is no Microsoft Graph API for Bookings settings."
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Bookings.\n"
            "Restrict or disable the Bookings feature for external access."
        ),
        default_value="Bookings may be publicly accessible by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/bookings/bookings-faq",
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
        tags=["bookings", "external-sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Bookings restrictions via the admin center:\n"
            "  1. Go to https://admin.microsoft.com\n"
            "  2. Navigate to Settings > Org settings > Bookings\n"
            "  3. Verify that public Bookings pages are restricted or disabled\n"
            "  4. Ensure only licensed users can create Bookings calendars\n\n"
            "There is no Microsoft Graph API available for this setting."
        )
