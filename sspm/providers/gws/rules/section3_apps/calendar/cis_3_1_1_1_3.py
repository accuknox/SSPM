"""
CIS GWS 3.1.1.1.3 (L1) – Ensure external calendar invitation warnings are
enabled (Manual)

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
class CIS_3_1_1_1_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.1.1.3",
        title="Ensure external calendar invitation warnings are enabled",
        section="3.1.1 Calendar",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.LOW,
        description=(
            "When users receive calendar invitations from external parties, "
            "a warning should be displayed to alert users that the organiser "
            "is external to the organisation."
        ),
        rationale=(
            "External calendar invitations can be used in phishing attacks to "
            "trick users into joining malicious meetings or clicking harmful links "
            "in event descriptions.  Displaying warnings helps users identify "
            "and avoid potentially malicious invitations."
        ),
        impact="Users will see a warning banner on calendar events from external senders.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under 'Sharing settings', verify 'External invitations' shows "
            "'Warn users when inviting external guests' is enabled"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Calendar\n"
            "  3. Under 'Sharing settings', enable 'Warn users when inviting "
            "external guests'\n"
            "  4. Click Save"
        ),
        default_value="External invitation warnings may be disabled by default.",
        references=[
            "https://support.google.com/a/answer/60765",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="14.6",
                title="Protect Information through Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["calendar", "external", "phishing", "warning"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
