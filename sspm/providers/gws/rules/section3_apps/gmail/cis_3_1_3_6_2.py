"""
CIS GWS 3.1.3.6.2 (L1) – Ensure spam filters are not bypassed for messages
from internal senders (Manual)

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
class CIS_3_1_3_6_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.6.2",
        title="Ensure spam filters are not bypassed for messages from internal senders",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Ensures that spam filters are applied to messages received from "
            "internal senders.  Bypassing spam filters for internal senders "
            "creates a blind spot — a compromised internal account can be used "
            "to distribute malicious email that bypasses all filtering."
        ),
        rationale=(
            "If spam filters are bypassed for internal senders, a compromised "
            "internal mailbox can be used to send phishing or malware emails "
            "that reach all users without being filtered.  Applying spam "
            "filters universally reduces this risk."
        ),
        impact=(
            "Legitimate internal email that looks like spam (e.g. bulk "
            "distribution lists) may occasionally be filtered.  Internal "
            "senders may need to adjust email practices."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Spam, Phishing and Malware\n"
            "  4. Select Spam → Configure\n"
            "  5. Ensure 'Bypass spam filters for messages from internal "
            "senders' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Spam, Phishing and Malware\n"
            "  4. Select Spam → Configure\n"
            "  5. Uncheck 'Bypass spam filters for messages from internal "
            "senders'\n"
            "  6. Click Save"
        ),
        default_value=(
            "Bypass spam filters for messages from internal senders is "
            "checked (enabled) by default — non-compliant."
        ),
        references=[
            "https://support.google.com/a/answer/2368132",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.6",
                title="Block Unnecessary File Types",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "spam", "internal-senders", "phishing", "spam-filter"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify spam filters are not bypassed for internal senders:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Spam, Phishing and Malware\n"
            "  4. Select Spam → Configure\n"
            "  5. Ensure 'Bypass spam filters for messages from internal "
            "senders' is unchecked"
        )
