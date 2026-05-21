"""
CIS GWS 3.1.8.1 (L1) – Ensure access to external Google Groups is OFF for
Everyone (Manual)

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
class CIS_3_1_8_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.8.1",
        title="Ensure access to external Google Groups is OFF for Everyone",
        section="3.1.8 Additional Google services",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Disables the ability for organisation users to access external "
            "Google Groups (groups.google.com), preventing them from "
            "subscribing to or posting in public Google Groups outside the "
            "organisation's domain."
        ),
        rationale=(
            "Access to external Google Groups can result in users inadvertently "
            "sharing internal information in public forums or receiving "
            "unsolicited content from external groups.  Restricting this "
            "access reduces information leakage and the risk of social "
            "engineering attacks via public groups."
        ),
        impact=(
            "Users will not be able to access groups.google.com or subscribe "
            "to external Google Groups.  Legitimate business use cases "
            "requiring participation in external groups should be handled "
            "via a formal exception process."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Additional Google services\n"
            "  3. Locate 'Google Groups for Business' or the relevant Groups "
            "service entry\n"
            "  4. Verify that 'Access to external Google Groups' is set to "
            "'OFF for everyone'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Additional Google services\n"
            "  3. Locate 'Google Groups for Business'\n"
            "  4. Set 'Access to external Google Groups' to 'OFF for everyone'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Access to external Google Groups is enabled by default "
            "(non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/167430",
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
        tags=["groups", "external", "access"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
