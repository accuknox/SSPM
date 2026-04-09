"""
CIS GWS 3.1.3.5.1 (L2) – Ensure POP and IMAP access is disabled for all
users in Google Workspace Gmail (Manual)

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
class CIS_3_1_3_5_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.5.1",
        title="Ensure POP and IMAP access is disabled for all users in Google Workspace Gmail",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Disabling POP and IMAP prevents users from accessing Gmail via "
            "legacy mail protocols that do not support modern authentication.  "
            "These protocols bypass MFA controls and expose credentials to "
            "brute-force and credential-stuffing attacks."
        ),
        rationale=(
            "POP and IMAP access use basic authentication and do not support "
            "multi-factor authentication, making accounts vulnerable to "
            "credential-based attacks.  Disabling them forces users to "
            "authenticate through the more secure OAuth-based web or app flows."
        ),
        impact=(
            "Users will not be able to access Gmail via POP or IMAP clients "
            "such as traditional desktop mail applications."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Ensure 'POP Access' is unchecked\n"
            "  5. Ensure 'IMAP Access' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Uncheck 'POP Access'\n"
            "  5. Uncheck 'IMAP Access'\n"
            "  6. Click Save"
        ),
        default_value="POP and IMAP access are both enabled by default.",
        references=[
            "https://support.google.com/a/answer/105694",
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
        tags=["gmail", "pop", "imap", "legacy-auth", "end-user-access"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify POP and IMAP access is disabled for all users:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Ensure 'POP Access' is unchecked\n"
            "  5. Ensure 'IMAP Access' is unchecked"
        )
