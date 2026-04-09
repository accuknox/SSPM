"""
CIS GWS 3.1.3.4.1.3 (L1) – Ensure protection against anomalous
attachment types in emails is enabled (Manual)

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
class CIS_3_1_3_4_1_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.4.1.3",
        title="Ensure protection against anomalous attachment types in emails is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "As a Google Workspace administrator, you can protect incoming mail "
            "against phishing and harmful software (malware).  This setting protects "
            "against anomalous attachment types — file types that are unusual or "
            "rarely seen in normal business communications."
        ),
        rationale=(
            "You should protect your users from potentially malicious attachments.  "
            "Anomalous attachment types are uncommon file formats that may be used "
            "to deliver malware."
        ),
        impact="Users will be warned when they receive an anomalous attachment.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Attachments, ensure 'Protect against anomalous "
            "attachment types in emails' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Attachments, set 'Protect against anomalous "
            "attachment types in emails' to checked\n"
            "  4. Click Save"
        ),
        default_value="Protect against anomalous attachment types in emails is Unchecked.",
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
        tags=["gmail", "attachments", "anomalous", "malware", "safety"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify protection against anomalous attachment types:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety → Attachments\n"
            "  4. Ensure 'Protect against anomalous attachment types in emails' "
            "is checked"
        )
