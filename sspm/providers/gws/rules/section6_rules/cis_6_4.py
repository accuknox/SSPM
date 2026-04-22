"""
CIS GWS 6.4 (L1) – Ensure User granted Admin privilege alert rule is
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
class CIS_6_4(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.4",
        title="Ensure User granted Admin privilege alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures an alert rule in Google Workspace that notifies "
            "administrators whenever a user account is granted "
            "administrative privileges.  Privilege escalation events "
            "must be monitored to detect both unauthorised privilege "
            "escalation and administrative errors."
        ),
        rationale=(
            "Granting administrative privileges is a high-risk action that "
            "should be rare and deliberate.  If an attacker gains access to "
            "an administrator account and creates additional admin accounts "
            "for persistence, this alert will detect the activity.  The "
            "alert also ensures that accidental privilege grants are "
            "detected and corrected promptly."
        ),
        impact=(
            "An alert will be generated each time admin privileges are "
            "granted.  In organisations with frequent legitimate admin "
            "changes, alert filtering may be needed to reduce noise while "
            "maintaining detection coverage."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'User granted Admin privilege' alert rule "
            "is enabled and routes to the security team"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'User granted Admin privilege' alert rule\n"
            "  4. Configure notification recipients\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'User granted Admin privilege' alert rule may not be "
            "enabled by default (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "admin-privilege"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
