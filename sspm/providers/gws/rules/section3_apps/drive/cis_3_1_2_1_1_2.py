"""
CIS GWS 3.1.2.1.1.2 (L1) – Ensure users cannot publish files to the web or
make them visible to the world as public or unlisted (Manual)

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
class CIS_3_1_2_1_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.1.2",
        title="Ensure users cannot publish files to the web or make visible to the world",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Prevent users from publishing documents to the web or making them "
            "visible to the world as public or unlisted files, which would allow "
            "anyone with the link to access them without authentication."
        ),
        rationale=(
            "Attackers often attempt to expose sensitive information through sharing. "
            "Restricting the ability to publish documents publicly reduces the "
            "risk of accidental or intentional data exfiltration through public links."
        ),
        impact=(
            "Users will not be able to publish documents publicly or make them "
            "visible to anyone with a link without organisational authentication."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Sharing options\n"
            "  4. Under 'Sharing outside of <Company> - ON'\n"
            "  5. Ensure 'When sharing outside of <Company> is allowed, users in "
            "<Company> can make files and published web content visible to anyone "
            "with the link' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Sharing options\n"
            "  4. Uncheck 'When sharing outside of <Company> is allowed, users can "
            "make files and published web content visible to anyone with the link'\n"
            "  5. Click Save"
        ),
        default_value=(
            "When sharing outside of <Company> is allowed, users in <Company> can "
            "make files and published web content visible to anyone with the link is Checked."
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
        tags=["drive", "sharing", "public", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
