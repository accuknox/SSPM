"""
CIS GWS 3.1.6.2 (L1) – Ensure creating groups is restricted (Manual)

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
class CIS_3_1_6_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.6.2",
        title="Ensure creating groups is restricted",
        section="3.1.6 Groups for Business",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Restricts the ability to create new Google Groups to "
            "administrators only, preventing end users from self-provisioning "
            "distribution lists, collaborative inboxes, or access-control "
            "groups without oversight."
        ),
        rationale=(
            "When any user can create a Group, it becomes easy to accidentally "
            "expose sensitive data to unintended audiences, bypass access "
            "controls, or create groups that shadow official distribution "
            "lists.  Centralising group creation ensures all groups are "
            "reviewed and properly configured."
        ),
        impact=(
            "End users will not be able to create new Groups.  Requests for "
            "new groups must be submitted to an administrator, which may "
            "slightly increase administrative overhead."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Groups for Business\n"
            "  3. Select Sharing Settings\n"
            "  4. Under 'Group creation', verify that only admins are "
            "permitted to create groups"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Groups for Business\n"
            "  3. Select Sharing Settings\n"
            "  4. Under 'Group creation', select 'Admins only'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Any user in the organisation can create groups by default "
            "(non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/167430",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["groups", "creation"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
