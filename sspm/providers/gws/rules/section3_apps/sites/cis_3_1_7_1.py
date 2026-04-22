"""
CIS GWS 3.1.7.1 (L1) – Ensure service status for Google Sites is set to off
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
class CIS_3_1_7_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.7.1",
        title="Ensure service status for Google Sites is set to off",
        section="3.1.7 Sites",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Disables the Google Sites service for the organisation, "
            "preventing users from creating public or internal websites that "
            "could expose sensitive corporate information or be used to host "
            "phishing pages."
        ),
        rationale=(
            "Google Sites allows users to easily publish websites, which may "
            "inadvertently expose internal documents, org charts, or project "
            "information.  If the organisation does not have a business need "
            "for Sites, disabling the service reduces the attack surface and "
            "prevents data leakage through published pages."
        ),
        impact=(
            "Users will not be able to create or access Google Sites.  "
            "Existing Sites will become inaccessible.  Organisations that "
            "use Sites for internal wikis or portals should migrate content "
            "to an approved platform before disabling."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Sites\n"
            "  3. Verify that the service status is set to 'OFF for everyone'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Sites\n"
            "  3. Click the service status toggle and select "
            "'OFF for everyone'\n"
            "  4. Click Save"
        ),
        default_value=(
            "Google Sites is enabled for all users by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/1247360",
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
        tags=["sites", "service-status"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
