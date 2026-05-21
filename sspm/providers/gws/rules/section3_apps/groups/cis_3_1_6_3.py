"""
CIS GWS 3.1.6.3 (L1) – Ensure default permission to view conversations is
restricted (Manual)

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
class CIS_3_1_6_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.6.3",
        title="Ensure default permission to view conversations is restricted",
        section="3.1.6 Groups for Business",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Sets the default permission for viewing Google Group "
            "conversations to group members only, preventing arbitrary "
            "organisation members or the general public from reading group "
            "email archives."
        ),
        rationale=(
            "Groups may contain sensitive discussions, internal announcements, "
            "or personally identifiable information.  If group conversations "
            "are viewable by anyone in the organisation or the public, this "
            "data is unnecessarily exposed.  Restricting to members enforces "
            "need-to-know access."
        ),
        impact=(
            "Only members of a group will be able to view its conversation "
            "history.  Administrators should communicate this change to group "
            "owners who may rely on public conversation visibility."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Groups for Business\n"
            "  3. Select Sharing Settings\n"
            "  4. Under 'Default permissions', verify that 'View topics' is "
            "set to 'Members of the group' or more restrictive"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Groups for Business\n"
            "  3. Select Sharing Settings\n"
            "  4. Under 'Default permissions', set 'View topics' to "
            "'Members of the group'\n"
            "  5. Click Save"
        ),
        default_value=(
            "View conversations may be set to 'Anyone in the organisation' "
            "by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/167430",
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
        tags=["groups", "conversations", "permissions"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
