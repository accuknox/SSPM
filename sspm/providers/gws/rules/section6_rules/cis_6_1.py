"""
CIS GWS 6.1 (L1) – Ensure User's password changed alert rule is configured
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
class CIS_6_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.1",
        title="Ensure User's password changed alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures an alert rule in Google Workspace that triggers "
            "a notification when a user's password is changed.  Password "
            "change alerts help detect unauthorised account takeover "
            "attempts where an attacker changes the password to lock out "
            "the legitimate user."
        ),
        rationale=(
            "An unexpected password change is a strong indicator of account "
            "compromise.  By alerting on all password changes, administrators "
            "can rapidly identify and respond to account takeover incidents "
            "before the attacker has time to exfiltrate data or cause "
            "further damage."
        ),
        impact=(
            "Alert volume will depend on the size of the organisation and "
            "frequency of legitimate password changes.  Alert tuning may "
            "be required to reduce noise.  Alerts should be routed to a "
            "monitored security team mailbox or SIEM."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that an alert rule for 'User's password changed' "
            "is enabled and configured to notify the appropriate recipients"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Create or enable the 'User's password changed' alert rule\n"
            "  4. Configure notification recipients (security team email "
            "or Pub/Sub topic)\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'User's password changed' alert rule is not enabled by "
            "default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="8.11",
                title="Conduct Audit Log Reviews",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "password"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
