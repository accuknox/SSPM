"""
CIS GWS 3.1.3.1.1 (L1) – Ensure users cannot delegate access to their
mailbox (Manual)

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
class CIS_3_1_3_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.1.1",
        title="Ensure users cannot delegate access to their mailbox",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Mail delegation allows the delegate to read, send, and delete messages "
            "on behalf of a user.  For example, a manager can delegate Gmail access "
            "to another person in their organization, such as an administrative "
            "assistant.  Only administrators should be able to delegate access to a "
            "user's mailboxes."
        ),
        rationale=(
            "Only administrators should be able to delegate access to a user's "
            "mailboxes.  Allowing users to self-delegate increases the risk of "
            "unauthorised access to email."
        ),
        impact=(
            "Existing delegations will be hidden when this feature is disabled."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under User Settings - Mail delegation, ensure 'Let users delegate "
            "access to their mailbox to other users in the domain' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under User Settings - Mail delegation, set 'Let users delegate "
            "access to their mailbox to other users in the domain' to unchecked\n"
            "  4. Click Save"
        ),
        default_value=(
            "Let users delegate access to their mailbox to other users in the "
            "domain is unchecked."
        ),
        references=[
            "https://support.google.com/a/answer/7223765",
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
        tags=["gmail", "delegation", "access-control", "mail-delegation"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify mail delegation is disabled for end users:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under User Settings → Mail delegation\n"
            "  4. Ensure 'Let users delegate access to their mailbox to other "
            "users in the domain' is unchecked"
        )
