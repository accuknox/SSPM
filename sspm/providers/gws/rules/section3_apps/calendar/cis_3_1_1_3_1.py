"""
CIS GWS 3.1.1.3.1 (L2) – Ensure calendar web offline is disabled (Manual)

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
class CIS_3_1_1_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.1.3.1",
        title="Ensure calendar web offline is disabled",
        section="3.1.1 Calendar",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.LOW,
        description=(
            "When calendar offline access is enabled, calendar data is cached "
            "locally on the user's browser.  This should be disabled to prevent "
            "data from being stored on unmanaged devices."
        ),
        rationale=(
            "When enabled, users can turn on offline access for each computer they "
            "use.  Calendar data is stored on the computer until offline use is "
            "turned off by the user.  The organisation loses control of where its "
            "data is stored.  Care should be taken regarding which users and groups "
            "have this capability enabled."
        ),
        impact="Users will not be able to access their calendars offline.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under Advanced settings, select 'Calendar web offline'\n"
            "  4. Ensure 'Allow using Calendar on the web when offline' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under Advanced settings → Calendar web offline\n"
            "  4. Set 'Allow using Calendar on the web when offline' to unchecked\n"
            "  5. Click Save"
        ),
        default_value="Allow using Calendar on the web when offline is checked.",
        references=[
            "https://support.google.com/a/answer/1279135",
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
        tags=["calendar", "offline", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify calendar web offline is disabled:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under Advanced settings → Calendar web offline\n"
            "  4. Ensure 'Allow using Calendar on the web when offline' is unchecked"
        )
