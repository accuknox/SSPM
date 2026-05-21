"""
CIS GWS 3.1.2.1.1.4 (L2) – Ensure users are warned when they share a file
with users in an allowlisted domain (Manual)

Profile Applicability: Enterprise Level 2
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
class CIS_3_1_2_1_1_4(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.1.4",
        title="Ensure users are warned when they share a file with allowlisted domain users",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.LOW,
        description=(
            "Warn users when they attempt to share a file with users in an "
            "allowlisted domain.  Even trusted domains should receive a warning "
            "to encourage conscious sharing decisions."
        ),
        rationale=(
            "Users may not realise the recipient's account is in an allowlisted "
            "(external) domain.  Providing a warning allows the user an opportunity "
            "to identify this and potentially reassess the sharing decision."
        ),
        impact="None, except an additional warning dialogue.  Sharing can still occur.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing Settings → Sharing options\n"
            "  4. Under 'Sharing outside of <Company>'\n"
            "  5. Ensure 'Warn when files owned by users or shared drives in "
            "<Company> are shared with users in allowlisted domains' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing Settings → Sharing options\n"
            "  4. Set 'Warn when sharing with users in allowlisted domains' to checked\n"
            "  5. Click Save"
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
        tags=["drive", "sharing", "allowlist", "warning"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
