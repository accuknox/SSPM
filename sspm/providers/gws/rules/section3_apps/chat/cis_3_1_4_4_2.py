"""
CIS GWS 3.1.4.4.2 (L1) – Ensure allow users to add and use incoming webhooks
is disabled (Manual)

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
class CIS_3_1_4_4_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.4.4.2",
        title="Ensure allow users to add and use incoming webhooks is disabled",
        section="3.1.4 Google Chat",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Prevents users from creating incoming webhook URLs in Google "
            "Chat Spaces.  Incoming webhooks allow any system or person with "
            "the URL to post messages to a Chat Space, potentially injecting "
            "malicious content or phishing messages."
        ),
        rationale=(
            "Webhook URLs, once created, are long-lived and hard to audit.  "
            "If leaked, they allow any external party to post messages into "
            "internal Chat Spaces, facilitating phishing attacks or "
            "disinformation campaigns within the organisation."
        ),
        impact=(
            "Automated notification systems using Chat webhooks will cease to "
            "function.  Integrations that require posting to Chat should use "
            "service accounts with the Chat API rather than unprotected "
            "webhook URLs."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Apps\n"
            "  4. Verify that 'Allow users to add and use incoming webhooks' "
            "is disabled"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Chat and classic Hangouts\n"
            "  3. Select Chat Apps\n"
            "  4. Disable 'Allow users to add and use incoming webhooks'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Incoming webhooks are enabled by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/10443538",
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
        tags=["chat", "webhooks"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
