"""
CIS GWS 3.1.3.1.2 (L1) – Ensure offline access to Gmail is disabled
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
class CIS_3_1_3_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.1.2",
        title="Ensure offline access to Gmail is disabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Disables the user's ability to utilise various Gmail functions (read, "
            "write, search, delete, and label email messages) while not connected "
            "to the internet."
        ),
        rationale=(
            "Prevents the organisation's data (user's email) from being copied "
            "to remote computers."
        ),
        impact="Users will need internet access to use Gmail.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Gmail\n"
            "  3. Select User Settings\n"
            "  4. Under Gmail web offline\n"
            "  5. Ensure 'Enable Gmail web offline' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Gmail\n"
            "  3. Select User Settings\n"
            "  4. Select Gmail web offline\n"
            "  5. Set 'Enable Gmail web offline' to unchecked\n"
            "  6. Click Save"
        ),
        default_value="Enable Gmail web offline is unchecked.",
        references=[
            "https://support.google.com/a/answer/7684186",
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
        tags=["gmail", "offline", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
