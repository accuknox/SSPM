"""
CIS GWS 6.5 (L1) – Ensure Suspicious programmatic login alert rule is
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
class CIS_6_5(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.5",
        title="Ensure Suspicious programmatic login alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures an alert rule in Google Workspace that notifies "
            "administrators when suspicious programmatic (non-interactive) "
            "login activity is detected.  Programmatic login attacks "
            "typically involve automated credential stuffing or stolen "
            "OAuth tokens being used by malicious scripts."
        ),
        rationale=(
            "Programmatic logins using compromised credentials or stolen "
            "tokens can access large volumes of data quickly without "
            "triggering traditional interactive login anomaly detection.  "
            "Alerting on suspicious programmatic logins enables rapid "
            "detection and response to these automated attacks."
        ),
        impact=(
            "Legitimate automated processes (scripts, service accounts) "
            "may occasionally trigger this alert.  Alert tuning should "
            "be applied to reduce false positives while maintaining "
            "detection coverage."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'Suspicious programmatic login' alert "
            "rule is enabled and routes notifications to the security team"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'Suspicious programmatic login' alert rule\n"
            "  4. Configure notification recipients\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'Suspicious programmatic login' alert rule may not be "
            "enabled by default (verify current configuration)."
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
        tags=["rules", "alerts", "programmatic-login"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
