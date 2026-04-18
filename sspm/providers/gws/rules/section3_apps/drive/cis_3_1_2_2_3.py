"""
CIS GWS 3.1.2.2.3 (L1) – Ensure Add-Ons is disabled (Manual)

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
class CIS_3_1_2_2_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.2.3",
        title="Ensure Add-Ons is disabled",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Prevent users from installing Google Docs add-ons from the add-ons "
            "store.  This setting controls add-on access from outside your "
            "organisation."
        ),
        rationale=(
            "Allowing users to install unapproved add-ons puts the organisation at "
            "risk.  If users need a specific add-on, this can be handled on a "
            "case-by-case basis once the add-on is approved."
        ),
        impact=(
            "Users will not be able to install Google Docs add-ons from the add-ons "
            "store without explicit approval."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Add-Ons\n"
            "  4. Ensure 'Allow users to install Google Docs add-ons from add-ons "
            "store' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Add-Ons\n"
            "  4. Set 'Allow users to install Google Docs add-ons from add-ons "
            "store' to unchecked\n"
            "  5. Click Save"
        ),
        default_value=(
            "Allow users to install Google Docs add-ons from add-ons store is checked."
        ),
        references=[
            "https://support.google.com/a/answer/6089179",
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
        tags=["drive", "add-ons", "marketplace", "app-control"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
