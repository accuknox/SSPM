"""
CIS GWS 3.1.1.2.1 (L1) – Ensure external sharing options for secondary
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
class CIS_3_1_1_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.1.2.1",
        title="Ensure external sharing options for secondary calendars are configured",
        section="3.1.1 Calendar",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Control how much secondary calendar information users can share "
            "externally.  The external sharing level should be restricted to "
            "'Only free/busy information (hide event details)' or less."
        ),
        rationale=(
            "Preventing data leakage by restricting the amount of information "
            "externally viewable when a user shares their secondary calendar with "
            "someone external to the organisation."
        ),
        impact=(
            "Once you limit external sharing, users cannot exceed these limits "
            "when sharing individual events.  External mobile users who previously "
            "synced events may keep seeing restricted details until their device "
            "is wiped and re-synced."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under General settings, select 'External sharing options for "
            "secondary calendars'\n"
            "  4. Ensure 'Only free/busy information (hide event details)' is selected"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under General settings → External sharing options for secondary "
            "calendars\n"
            "  4. Select 'Only free/busy information (hide event details)'\n"
            "  5. Click Save"
        ),
        default_value=(
            "External sharing options for secondary calendars is "
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
        tags=["calendar", "sharing", "external", "secondary"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
