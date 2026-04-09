"""
CIS GWS 3.1.2.1.1.6 (L1) – Ensure only users inside your organization can
distribute content externally (Manual)

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
class CIS_3_1_2_1_1_6(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.1.6",
        title="Ensure only users inside your organization can distribute content externally",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Control who is allowed to distribute organisational content to shared "
            "drives owned by another organisation.  Only internal users should have "
            "this authority."
        ),
        rationale=(
            "Sharing and collaboration are key; however, only your users should "
            "have the authority over where company content is shared to prevent "
            "unauthorised disclosures of information."
        ),
        impact=(
            "Only people in your organisation with Manager access to a shared drive "
            "can move files from that shared drive to a Drive location in a different "
            "organisation.  Users can still copy content from their My Drive to a "
            "shared drive owned by another organisation."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings, select Sharing options\n"
            "  4. Under 'Distributing content outside of <Company>', ensure "
            "'Only users in <Company>' is selected"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Sharing options\n"
            "  4. Under 'Distributing content outside of <Company>', select "
            "'Only users in <Company>'\n"
            "  5. Click Save"
        ),
        default_value="Distributing content outside of <Company> is 'Anyone'.",
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
        tags=["drive", "sharing", "external", "data-exfiltration"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify only internal users can distribute content externally:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Sharing options\n"
            "  4. Under 'Distributing content outside of <Company>', ensure "
            "'Only users in <Company>' is selected"
        )
