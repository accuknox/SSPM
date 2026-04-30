"""
CIS GWS 3.1.3.3.1 (L1) – Enable quarantine admin notifications for
Gmail (Manual)

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
class CIS_3_1_3_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.3.1",
        title="Enable quarantine admin notifications for Gmail",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Quarantines can help prevent spam, minimise data loss, and protect "
            "confidential information.  They can also help moderate message "
            "attachments so users don't send, open, or click something they "
            "shouldn't.  Admins should be notified periodically when messages "
            "are quarantined so they can take the appropriate actions."
        ),
        rationale=(
            "Admins should be notified periodically when messages are quarantined "
            "so they can take the appropriate actions."
        ),
        impact="Admins will begin receiving quarantine notifications as emails are quarantined.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Manage quarantines, ensure each quarantine has 'Notify "
            "periodically when messages are quarantined' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Manage quarantines, set 'Notify periodically when messages "
            "are quarantined' to checked\n"
            "  4. As required, give appropriate users the 'Access Admin Quarantine' "
            "and/or 'Access restricted quarantine' roles"
        ),
        default_value="Notify periodically when messages are quarantined is unchecked.",
        references=[
            "https://support.google.com/a/answer/6104172",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.6",
                title="Block Unnecessary File Types",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "quarantine", "notifications", "admin"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
