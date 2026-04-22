"""
CIS GWS 4.2.5.1 (L2) – Ensure Google Cloud session control is configured
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
class CIS_4_2_5_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.5.1",
        title="Ensure Google Cloud session control is configured",
        section="4.2.5 Google Cloud Session Control",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Configures session duration controls specifically for Google "
            "Cloud (GCP) console and API access.  Cloud console sessions "
            "provide access to infrastructure and should have stricter "
            "session limits than standard Workspace applications."
        ),
        rationale=(
            "Google Cloud console access allows users to manage cloud "
            "infrastructure, which can have significant financial and "
            "security implications.  Shorter session durations for Cloud "
            "access reduce the window of opportunity if a session is "
            "hijacked, and enforce regular re-authentication for cloud "
            "administrators."
        ),
        impact=(
            "Cloud console users will be required to re-authenticate more "
            "frequently.  This may cause minor inconvenience for cloud "
            "administrators who perform long-running operations but "
            "significantly reduces session hijacking risk."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Google Cloud session control\n"
            "  3. Verify that the session duration for Cloud is set to "
            "1 hour or less"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Google Cloud session control\n"
            "  3. Set the Cloud session duration to 1 hour or less\n"
            "  4. Click Save"
        ),
        default_value=(
            "Google Cloud session duration defaults to the general workspace "
            "session duration setting (non-compliant for EL2)."
        ),
        references=[
            "https://support.google.com/a/answer/9368756",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="16.11",
                title="Lock Workstation Sessions After Inactivity",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["session", "cloud", "control"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
