"""
CIS GWS 3.1.4.3.1 (L1) – Ensure external spaces in Google Chat and Hangouts
are restricted (Manual)

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
class CIS_3_1_4_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.4.3.1",
        title="Ensure external spaces in Google Chat and Hangouts are restricted",
        section="3.1.4 Google Chat",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Controls whether internal users can create or join Google Chat "
            "Spaces that include external (outside-organisation) members.  "
            "External spaces expose internal conversations, files, and "
            "integrations to parties outside the organisation's security "
            "perimeter."
        ),
        rationale=(
            "Unrestricted external spaces allow external users to observe "
            "internal collaboration, access shared content within the space, "
            "and potentially exfiltrate sensitive information.  Restricting "
            "external spaces limits the blast radius of a compromised or "
            "malicious external account."
        ),
        impact=(
            "Users will not be able to create or join Chat Spaces that "
            "include external members.  Cross-organisation collaboration "
            "requiring shared spaces should be evaluated and approved on a "
            "case-by-case basis."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Settings\n"
            "  4. Under 'Spaces', verify that external users are not permitted "
            "to join or create spaces with organisation members"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Settings\n"
            "  4. Under 'Spaces', disable the option that allows external "
            "users in spaces\n"
            "  5. Click Save"
        ),
        default_value=(
            "External spaces are permitted by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/9410487",
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
        tags=["chat", "spaces", "external"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
