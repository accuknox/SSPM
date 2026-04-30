"""
CIS GWS 3.1.3.7.1 (L1) – Ensure comprehensive mail storage is enabled
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
class CIS_3_1_3_7_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.7.1",
        title="Ensure comprehensive mail storage is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Ensures that a copy of all sent and received mail is stored in "
            "associated users' mailboxes, even when messages are sent or "
            "received through third-party applications.  This supports "
            "eDiscovery, compliance, and forensic investigation requirements."
        ),
        rationale=(
            "Without comprehensive mail storage, emails sent through "
            "third-party apps or delegated access may not be retained in the "
            "user's mailbox.  Enabling this setting ensures complete mail "
            "retention for compliance and investigation purposes."
        ),
        impact=(
            "Storage usage in user mailboxes may increase as copies of all "
            "mail (including third-party sent mail) are retained."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Compliance\n"
            "  4. Select Comprehensive mail storage\n"
            "  5. Ensure 'Ensure that a copy of all sent and received mail is "
            "stored in associated users mailboxes' is ON"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Compliance\n"
            "  4. Select Comprehensive mail storage\n"
            "  5. Enable 'Ensure that a copy of all sent and received mail is "
            "stored in associated users mailboxes'\n"
            "  6. Click Save"
        ),
        default_value="Comprehensive mail storage is OFF by default (non-compliant).",
        references=[
            "https://support.google.com/a/answer/3547347",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="8.2",
                title="Collect Audit Logs",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "compliance", "mail-storage", "ediscovery", "retention"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
