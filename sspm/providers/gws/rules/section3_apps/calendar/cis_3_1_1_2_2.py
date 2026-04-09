"""
CIS GWS 3.1.1.2.2 (L2) – Ensure internal sharing options for secondary
calendars are configured (Manual)

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
class CIS_3_1_1_2_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.1.2.2",
        title="Ensure internal sharing options for secondary calendars are configured",
        section="3.1.1 Calendar",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.LOW,
        description=(
            "Control how much secondary calendar information users can share "
            "internally.  Internal sharing should be restricted to "
            "'Only free/busy information (hide event details)'."
        ),
        rationale=(
            "Not everyone in the organisation needs full visibility into each "
            "other's secondary calendar schedules.  Free/busy information is "
            "sufficient for most scheduling needs."
        ),
        impact=(
            "This will be the default for users' secondary calendars.  The user "
            "can override this setting to allow specific users greater visibility."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under General settings, select 'Internal sharing options for "
            "secondary calendars'\n"
            "  4. Ensure 'Only free/busy information (hide event details)' is selected"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under General settings → Internal sharing options for secondary calendars\n"
            "  4. Select 'Only free/busy information (hide event details)'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Internal sharing options for secondary calendars is 'Share all information'."
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
        tags=["calendar", "sharing", "internal", "secondary"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify internal sharing for secondary calendars:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under General settings → Internal sharing options for secondary calendars\n"
            "  4. Ensure 'Only free/busy information (hide event details)' is selected"
        )
