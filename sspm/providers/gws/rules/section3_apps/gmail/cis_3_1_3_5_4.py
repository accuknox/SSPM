"""
CIS GWS 3.1.3.5.4 (L1) – Ensure external recipient warnings are enabled
(Manual)

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
class CIS_3_1_3_5_4(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.5.4",
        title="Ensure external recipient warnings are enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Displays a warning banner when a user is composing an email to "
            "an external (outside the organisation) recipient.  This helps "
            "prevent accidental data leakage to external parties."
        ),
        rationale=(
            "Users may inadvertently send sensitive information to external "
            "recipients.  A visible warning when composing email to external "
            "addresses prompts users to review recipients before sending, "
            "reducing accidental data disclosure."
        ),
        impact=(
            "Users see a warning banner when composing email to recipients "
            "outside the organisation."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Ensure 'Warn for external recipients' — 'Highlight any "
            "external recipients in a compose or reply window' is ON"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Enable 'Highlight any external recipients in a compose or "
            "reply window'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Highlight any external recipients in a compose or reply window "
            "is ON by default."
        ),
        references=[
            "https://support.google.com/a/answer/7380041",
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
        tags=["gmail", "external-recipients", "data-loss-prevention", "end-user-access"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
