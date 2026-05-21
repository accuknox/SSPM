"""
CIS GWS 3.1.2.1.1.5 (L1) – Ensure Access Checker is configured to limit
file access (Manual)

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
class CIS_3_1_2_1_1_5(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.1.5",
        title="Ensure Access Checker is configured to limit file access",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "When a user shares a file via a Google product other than Docs or Drive "
            "(e.g. by pasting a link in Gmail), Google can check that the recipients "
            "have access.  If not, Google will ask the user to pick how they want to "
            "share the file.  This should be configured to allow access by 'Recipients only'."
        ),
        rationale=(
            "In general, access should be restricted to the smallest group possible. "
            "Allowing only recipients to access shared files prevents unintended "
            "broader access through link forwarding."
        ),
        impact=(
            "Only recipients can access files.  Recipients cannot share access with "
            "others by forwarding the email or link."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Drive and Docs\n"
            "  3. Select Sharing Settings → Sharing Options\n"
            "  4. Under Access Checker\n"
            "  5. Ensure 'Recipients only' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Drive and Docs\n"
            "  3. Select Sharing Settings → Sharing Options\n"
            "  4. Under Access Checker, set 'Recipients only' to checked\n"
            "  5. Click Save"
        ),
        default_value="Access Checker may allow broader access than recipients only.",
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
        tags=["drive", "sharing", "access-checker", "least-privilege"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
