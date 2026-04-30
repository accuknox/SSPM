"""
CIS GWS 6.7 (L1) – Ensure Leaked password alert rule is configured (Manual)

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
class CIS_6_7(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.7",
        title="Ensure Leaked password alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.CRITICAL,
        description=(
            "Configures an alert rule in Google Workspace that notifies "
            "administrators when Google detects that a user's password "
            "has been found in a third-party data breach.  Leaked password "
            "detection leverages Google's threat intelligence to identify "
            "compromised credentials before they are used against the "
            "organisation."
        ),
        rationale=(
            "Credential stuffing attacks rely on passwords leaked from "
            "third-party breaches being reused on other services.  When "
            "Google detects that an organisation user's password has been "
            "leaked, immediate forced reset is essential to prevent "
            "account compromise.  Early notification enables proactive "
            "remediation before an attack occurs."
        ),
        impact=(
            "When a leaked password is detected, the affected user should "
            "be forced to reset their password immediately.  The "
            "organisation should investigate whether the account was "
            "accessed using the leaked credentials."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'Leaked password' alert rule is enabled "
            "and routes notifications to the security team with high "
            "priority"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'Leaked password' alert rule\n"
            "  4. Configure notification recipients with appropriate "
            "urgency indicators\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'Leaked password' alert rule may not be enabled by "
            "default (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "leaked-password"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
