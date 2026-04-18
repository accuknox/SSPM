"""
CIS GWS 3.1.2.1.1.1 (L1) – Ensure users are warned when they share a file
outside their domain (Manual)

Profile Applicability: Enterprise Level 1
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
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_3_1_2_1_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.1.1",
        title="Ensure users are warned when they share a file outside their domain",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Warn users when they attempt to share a file and/or shared drive "
            "externally, so they can reconsider before sharing sensitive data "
            "outside the organisation."
        ),
        rationale=(
            "The user may not realise the recipient's account is external to the "
            "organisation.  Providing a warning allows the user an opportunity to "
            "identify this and potentially reassess the sharing decision."
        ),
        impact="None, except an additional warning dialogue.  Sharing can still occur.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing Settings → Sharing options\n"
            "  4. Under 'Sharing outside of <Company>'\n"
            "  5. Verify 'For files owned by users in <Company> warn when sharing "
            "outside of <Company>' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing Settings → Sharing options\n"
            "  4. Under 'Sharing outside of <Company>'\n"
            "  5. Enable 'For files owned by users in <Company> warn when sharing "
            "outside of <Company>'\n"
            "  6. Click Save"
        ),
        default_value=(
            "For files owned by users in <Company> warn when sharing outside "
            "of <Company> is checked."
        ),
        references=[
            "https://support.google.com/a/answer/60781",
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
        tags=["drive", "sharing", "external", "warning"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
