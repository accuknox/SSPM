"""
CIS GWS 3.1.4.4.1 (L1) – Ensure allow users to install Chat apps is disabled
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
class CIS_3_1_4_4_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.4.4.1",
        title="Ensure allow users to install Chat apps is disabled",
        section="3.1.4 Google Chat",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Prevents end users from self-installing third-party Chat "
            "applications from the Google Workspace Marketplace into Chat.  "
            "Unapproved Chat apps may request excessive OAuth scopes, "
            "exfiltrate data, or introduce malicious bots into the "
            "organisation's Chat environment."
        ),
        rationale=(
            "Allowing users to install Chat apps without administrative "
            "oversight creates a shadow-IT risk.  Each installed app "
            "represents an additional attack surface and potential data "
            "leakage vector.  Centralised app management ensures only vetted "
            "apps are available."
        ),
        impact=(
            "Users will not be able to install Chat apps from the Marketplace "
            "without administrator approval.  Administrators should maintain "
            "an approved app allowlist and deploy required apps centrally."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Apps\n"
            "  4. Verify that 'Allow users to install Chat apps' is disabled"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Apps\n"
            "  4. Disable 'Allow users to install Chat apps'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Users are allowed to install Chat apps by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/10443538",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["chat", "apps", "marketplace"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
