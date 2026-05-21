"""
CIS GWS 1.2.1.1 (L2) – Ensure that user directory sharing is disabled
(Manual)

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
class CIS_1_2_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-1.2.1.1",
        title="Ensure that user directory sharing is disabled",
        section="1.2 Directory Sharing",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "External directory sharing allows users outside the organisation to "
            "look up users in the Google Workspace directory.  This should be "
            "disabled to prevent enumeration of internal email addresses."
        ),
        rationale=(
            "Exposing the internal user directory externally enables attackers to "
            "enumerate valid email addresses for targeted phishing campaigns.  "
            "Disabling external directory sharing reduces the reconnaissance "
            "surface."
        ),
        impact=(
            "External parties will not be able to search for or look up users in "
            "your directory.  This may affect legitimate use cases such as "
            "external collaborators looking up contacts."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Directory → Directory settings\n"
            "  3. Under 'Sharing settings', verify 'Enable contact sharing' "
            "is unchecked for external directory sharing.\n\n"
            "Verify that external users cannot search for internal users via "
            "Google services."
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Directory → Directory settings\n"
            "  3. Under 'Sharing settings', uncheck 'Enable contact sharing' "
            "for external domains.\n"
            "  4. Click Save."
        ),
        default_value="Directory sharing is enabled by default.",
        references=[
            "https://support.google.com/a/answer/60218",
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
        tags=["identity", "directory", "sharing", "enumeration"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
