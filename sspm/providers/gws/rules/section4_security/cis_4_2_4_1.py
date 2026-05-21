"""
CIS GWS 4.2.4.1 (L1) – Ensure Google session control is configured (Manual)

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
class CIS_4_2_4_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.4.1",
        title="Ensure Google session control is configured",
        section="4.2.4 Google Session Control",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Configures session duration controls for Google Workspace to "
            "limit how long users can remain authenticated without "
            "re-authenticating.  Setting a session duration of 8 hours or "
            "less reduces the window of opportunity for session hijacking "
            "on unattended or shared devices."
        ),
        rationale=(
            "Long-lived or never-expiring sessions increase the risk of "
            "unauthorised access if a user's device is lost, stolen, or "
            "left unattended.  Session timeouts force re-authentication, "
            "ensuring that stolen session tokens have a limited useful "
            "lifetime."
        ),
        impact=(
            "Users will be required to re-authenticate after the configured "
            "session duration.  This may cause friction for users who work "
            "long hours, but the security benefit outweighs the inconvenience.  "
            "Single Sign-On (SSO) configurations may interact with session "
            "control settings."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Google session control\n"
            "  3. Verify that the session duration is set to 8 hours or less "
            "for all users"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Google session control\n"
            "  3. Set the session duration to 8 hours or less\n"
            "  4. Click Save"
        ),
        default_value=(
            "The default session duration may be set to several days or "
            "indefinitely (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/7576218",
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
        tags=["session", "control", "timeout"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
