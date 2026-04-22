"""
CIS GWS 6.8 (L1) – Ensure Gmail potential employee spoofing alert rule is
configured (Manual)

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
class CIS_6_8(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.8",
        title="Ensure Gmail potential employee spoofing alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures an alert rule in Google Workspace that notifies "
            "administrators when Gmail detects an inbound email that "
            "appears to impersonate an organisation employee.  Employee "
            "spoofing attacks are commonly used in Business Email "
            "Compromise (BEC) and social engineering attacks."
        ),
        rationale=(
            "Business Email Compromise (BEC) attacks that spoof executive "
            "or employee identities result in significant financial losses "
            "globally.  Detecting and alerting on potential spoofing "
            "attempts allows the organisation to warn targeted recipients "
            "and potentially prevent financial fraud or data theft."
        ),
        impact=(
            "Some legitimate emails from external parties with similar "
            "names to employees may trigger false positives.  A triage "
            "process should be established to assess each alert and "
            "communicate with affected users."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'Gmail potential employee spoofing' "
            "alert rule is enabled and routes notifications to the "
            "security team"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'Gmail potential employee spoofing' alert rule\n"
            "  4. Configure notification recipients\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'Gmail potential employee spoofing' alert rule may not "
            "be enabled by default (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.5",
                title="Implement DMARC",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "gmail", "spoofing"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
