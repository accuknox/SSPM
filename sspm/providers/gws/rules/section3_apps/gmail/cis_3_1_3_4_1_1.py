"""
CIS GWS 3.1.3.4.1.1 (L1) – Ensure protection against encrypted
attachments from untrusted senders is enabled (Manual)

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
class CIS_3_1_3_4_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.4.1.1",
        title="Ensure protection against encrypted attachments from untrusted senders is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "As a Google Workspace administrator, you can protect incoming mail "
            "against phishing and harmful software (malware).  You can also choose "
            "what action to take based on the type of threat detected.  This setting "
            "protects against encrypted attachments from untrusted senders."
        ),
        rationale=(
            "You should protect your users from potentially malicious attachments.  "
            "Encrypted attachments from untrusted senders cannot be scanned for "
            "malware and should trigger a warning."
        ),
        impact=(
            "Users will be warned when they receive an encrypted attachment from "
            "an untrusted sender."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Attachments, ensure 'Protect against encrypted "
            "attachments from untrusted senders' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Attachments, set 'Protect against encrypted "
            "attachments from untrusted senders' to checked\n"
            "  4. Click Save"
        ),
        default_value="Protect against encrypted attachments from untrusted senders is checked.",
        references=[
            "https://support.google.com/a/answer/9157861",
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
        tags=["gmail", "attachments", "malware", "safety", "phishing"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
