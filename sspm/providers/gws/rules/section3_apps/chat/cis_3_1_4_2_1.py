"""
CIS GWS 3.1.4.2.1 (L1) – Ensure Google Chat external sharing is restricted
to allowed domains (Manual)

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
class CIS_3_1_4_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.4.2.1",
        title="Ensure Google Chat external sharing is restricted to allowed domains",
        section="3.1.4 Google Chat",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Limits external Chat communication to a defined allowlist of "
            "trusted domains, preventing users from initiating or accepting "
            "Chat conversations with arbitrary external parties."
        ),
        rationale=(
            "Without domain restrictions, users can communicate via Chat with "
            "any external Gmail or Workspace user, increasing the attack "
            "surface for phishing, social engineering, and data exfiltration. "
            "Restricting to known partner domains enforces the principle of "
            "least privilege for external communications."
        ),
        impact=(
            "Users will only be able to communicate in Chat with external "
            "users from domains explicitly listed in the allowlist.  "
            "Ad-hoc collaboration with users from unlisted domains will "
            "require an allowlist update."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Settings\n"
            "  4. Under 'External Chat', verify that 'Restrict to allowed "
            "external domains' is selected and the allowlist is populated "
            "with approved partner domains"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Settings\n"
            "  4. Under 'External Chat', select 'Restrict to allowed external "
            "domains'\n"
            "  5. Add approved partner domains to the allowlist\n"
            "  6. Click Save"
        ),
        default_value=(
            "External Chat is allowed for all domains by default "
            "(non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/9410487",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="12.2",
                title="Establish and Maintain a Secure Network Architecture",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["chat", "external", "domains"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
