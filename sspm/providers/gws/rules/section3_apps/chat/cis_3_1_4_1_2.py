"""
CIS GWS 3.1.4.1.2 (L2) – Ensure internal file sharing in Google Chat and
Hangouts is disabled (Manual)

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
class CIS_3_1_4_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.4.1.2",
        title="Ensure internal file sharing in Google Chat and Hangouts is disabled",
        section="3.1.4 Google Chat",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Prevents users from sharing files with internal participants in "
            "Google Chat and classic Hangouts.  Even within the organisation, "
            "file sharing via Chat can bypass data loss prevention controls "
            "and create uncontrolled copies of sensitive documents."
        ),
        rationale=(
            "Restricting internal file sharing in Chat ensures that document "
            "sharing is performed through controlled channels such as Google "
            "Drive with proper access controls and audit logging, reducing the "
            "risk of accidental data exposure."
        ),
        impact=(
            "Users will not be able to share files directly in Chat messages "
            "with internal colleagues.  They should instead share links to "
            "Drive files with appropriate permissions."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat File Sharing → Setting\n"
            "  4. Ensure 'Internal filesharing' is set to 'No files'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat File Sharing → Setting\n"
            "  4. Set 'Internal filesharing' to 'No files'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Internal filesharing is set to 'Allow all files' by default "
            "(non-compliant for EL2)."
        ),
        references=[
            "https://support.google.com/a/answer/6346296",
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
        tags=["chat", "file-sharing", "internal"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
