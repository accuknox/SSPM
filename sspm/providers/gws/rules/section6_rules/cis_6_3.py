"""
CIS GWS 6.3 (L1) – Ensure User suspended due to suspicious activity alert
rule is configured (Manual)

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
class CIS_6_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.3",
        title="Ensure User suspended due to suspicious activity alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures an alert rule in Google Workspace that notifies "
            "administrators when Google automatically suspends a user "
            "account due to detected suspicious activity.  This alert "
            "enables rapid administrator response to confirm whether "
            "the suspension was warranted and whether further action is "
            "needed."
        ),
        rationale=(
            "When Google automatically suspends an account for suspicious "
            "activity, it indicates a high-confidence security event.  "
            "Administrators must be immediately notified so they can "
            "investigate the root cause, secure the account, assess data "
            "exposure, and determine if other accounts may be affected."
        ),
        impact=(
            "The suspended user will not be able to access their account "
            "until it is restored by an administrator.  The alert should "
            "trigger an investigation before the account is unsuspended."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'User suspended due to suspicious "
            "activity' alert rule is enabled and routes notifications "
            "to the security team"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'User suspended due to suspicious activity' "
            "alert rule\n"
            "  4. Configure notification recipients\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'User suspended due to suspicious activity' alert rule "
            "may not be enabled by default (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="17.6",
                title="Contain Incidents",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "suspicious-activity"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
