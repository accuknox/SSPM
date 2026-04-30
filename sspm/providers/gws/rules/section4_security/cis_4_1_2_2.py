"""
CIS GWS 4.1.2.2 (L1) – Ensure user account recovery is enabled (Manual)

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
class CIS_4_1_2_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.2.2",
        title="Ensure user account recovery is enabled",
        section="4.1.2 Account Recovery",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Ensures that standard user accounts have self-service account "
            "recovery options configured, allowing users to regain access to "
            "their accounts without requiring administrator intervention for "
            "every lost-password scenario."
        ),
        rationale=(
            "Without account recovery options, users who forget their "
            "passwords must contact IT support, increasing helpdesk load "
            "and potentially leaving users locked out for extended periods.  "
            "Enabling recovery options with secondary email or phone ensures "
            "users can securely regain access while reducing administrative "
            "burden."
        ),
        impact=(
            "Users will be prompted to configure recovery options when they "
            "have not done so.  Administrators should communicate the "
            "importance of keeping recovery information up to date."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Account recovery\n"
            "  3. Verify that 'User account recovery' is enabled for "
            "the organisation"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Account recovery\n"
            "  3. Enable 'User account recovery'\n"
            "  4. Click Save"
        ),
        default_value=(
            "User account recovery settings vary by configuration; verify "
            "the current state in the Admin Console."
        ),
        references=[
            "https://support.google.com/a/answer/9436964",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["account-recovery", "users"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
