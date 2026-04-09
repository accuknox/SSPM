"""
CIS GWS 3.1.3.6.1 (L1) – Ensure enhanced pre-delivery message scanning is
enabled (Manual)

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
class CIS_3_1_3_6_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.6.1",
        title="Ensure enhanced pre-delivery message scanning is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Enables enhanced pre-delivery scanning that holds and re-evaluates "
            "messages flagged as suspicious before delivery.  This provides an "
            "additional layer of protection against malicious emails that may "
            "initially evade standard filtering."
        ),
        rationale=(
            "Standard email scanning occurs at delivery time and may miss "
            "sophisticated threats.  Enhanced pre-delivery scanning applies "
            "additional analysis to borderline messages, reducing the risk of "
            "malicious emails reaching user inboxes."
        ),
        impact=(
            "Emails flagged as potentially malicious may be slightly delayed "
            "in delivery while undergoing enhanced scanning."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Spam, Phishing and Malware\n"
            "  4. Ensure 'Enhanced pre-delivery message scanning' is ON"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Spam, Phishing and Malware\n"
            "  4. Enable 'Enhanced pre-delivery message scanning'\n"
            "  5. Click Save"
        ),
        default_value="Enhanced pre-delivery message scanning is ON by default.",
        references=[
            "https://support.google.com/a/answer/7380368",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.7",
                title="Deploy and Maintain Email Server Anti-Malware Protections",
                ig1=False,
                ig2=False,
                ig3=True,
            ),
        ],
        tags=["gmail", "spam", "phishing", "malware", "pre-delivery-scanning"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify enhanced pre-delivery message scanning is enabled:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Spam, Phishing and Malware\n"
            "  4. Ensure 'Enhanced pre-delivery message scanning' is ON"
        )
