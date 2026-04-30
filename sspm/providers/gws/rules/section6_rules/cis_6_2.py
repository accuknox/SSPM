"""
CIS GWS 6.2 (L1) – Ensure Government-backed attacks alert rule is configured
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
class CIS_6_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-6.2",
        title="Ensure Government-backed attacks alert rule is configured",
        section="6 Rules",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.CRITICAL,
        description=(
            "Configures an alert rule in Google Workspace to notify "
            "administrators when Google detects that a user account may "
            "be the target of a government-backed or nation-state attack.  "
            "These are high-confidence, high-severity alerts that require "
            "immediate response."
        ),
        rationale=(
            "Government-backed attacks represent some of the most "
            "sophisticated and dangerous threats facing organisations.  "
            "Google's threat intelligence team identifies these attacks "
            "and can alert the targeted user's organisation.  Enabling "
            "this alert ensures that the organisation is immediately "
            "notified and can take protective action."
        ),
        impact=(
            "Government-backed attack alerts are rare but extremely "
            "high-priority.  When triggered, they should initiate an "
            "immediate incident response process.  The affected user "
            "should be enrolled in the Advanced Protection Program."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Verify that the 'Government-backed attacks' alert rule "
            "is enabled and configured to notify security personnel "
            "immediately"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Rules\n"
            "  3. Enable the 'Government-backed attacks' alert rule\n"
            "  4. Configure notification to reach the security team "
            "immediately (e.g., SMS escalation, PagerDuty integration)\n"
            "  5. Click Save"
        ),
        default_value=(
            "The 'Government-backed attacks' alert rule may not be enabled "
            "by default (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/9420866",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="17.3",
                title="Designate Management Personnel to Support Incident Handling",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["rules", "alerts", "government-attacks"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
