"""
CIS GWS 3.1.1.1.1 (L1) – Ensure external sharing options for primary
calendars are configured (Manual)

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
class CIS_3_1_1_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.1.1.1",
        title="Ensure external sharing options for primary calendars are configured",
        section="3.1.1 Calendar",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Control how much calendar information users can share externally. "
            "External sharing of primary calendars should be restricted to "
            "'Only free/busy information (hide event details)' or less."
        ),
        rationale=(
            "Unrestricted calendar sharing can expose sensitive meeting titles, "
            "attendees, locations, and notes to external parties.  Restricting "
            "to free/busy information prevents data leakage while still "
            "enabling scheduling coordination."
        ),
        impact=(
            "If you lower the external sharing level, external parties may lose "
            "access to calendar details they could previously see.  External "
            "mobile users who previously synced events may keep seeing restricted "
            "details until their device is wiped and re-synced."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under 'Sharing settings', select 'External sharing options for "
            "primary calendars'\n"
            "  4. Ensure 'Only free/busy information (hide event details)' is selected"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under 'Sharing settings', select 'External sharing options for "
            "primary calendars'\n"
            "  4. Select 'Only free/busy information (hide event details)'\n"
            "  5. Click Save"
        ),
        default_value=(
            "External sharing options for primary calendars is "
            "'Share all information, but outsiders cannot change calendars'."
        ),
        references=[
            "https://support.google.com/a/answer/60765",
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
        tags=["calendar", "sharing", "external"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
