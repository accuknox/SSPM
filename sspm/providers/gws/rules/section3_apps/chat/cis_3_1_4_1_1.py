"""
CIS GWS 3.1.4.1.1 (L1) – Ensure external file sharing in Google Chat is
disabled (Manual)

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
class CIS_3_1_4_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.4.1.1",
        title="Ensure external file sharing in Google Chat is disabled",
        section="3.1.4 Google Chat",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Prevents users from sharing files with external (outside the "
            "organisation) participants in Google Chat.  Allowing external "
            "file sharing in Chat creates a channel for uncontrolled data "
            "exfiltration to parties outside the organisation."
        ),
        rationale=(
            "Unrestricted external file sharing in Chat can lead to sensitive "
            "data being shared with unintended recipients or malicious actors "
            "posing as external collaborators."
        ),
        impact=(
            "Users will not be able to share files with external Chat "
            "participants.  External collaboration requiring file sharing "
            "should use approved external sharing platforms."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat File Sharing → Setting\n"
            "  4. Ensure 'External filesharing' is set to 'No files'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat File Sharing → Setting\n"
            "  4. Set 'External filesharing' to 'No files'\n"
            "  5. Click Save"
        ),
        default_value=(
            "External filesharing is set to 'Allow all files' by default "
            "(non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/6346296",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.8",
                title="Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["chat", "file-sharing", "external", "data-exfiltration"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify external file sharing in Google Chat is disabled:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat File Sharing → Setting\n"
            "  4. Ensure 'External filesharing' is set to 'No files'"
        )
