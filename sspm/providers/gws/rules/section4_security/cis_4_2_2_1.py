"""
CIS GWS 4.2.2.1 (L1) – Ensure blocking access from unapproved geographic
locations is configured (Manual)

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
class CIS_4_2_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.2.1",
        title="Ensure blocking access from unapproved geographic locations is configured",
        section="4.2.2 Context-Aware Access",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures Context-Aware Access policies to block sign-ins or "
            "application access from countries or regions where the "
            "organisation does not have legitimate business operations.  "
            "Geo-blocking reduces exposure to threat actors operating in "
            "high-risk jurisdictions."
        ),
        rationale=(
            "A significant proportion of credential stuffing, phishing, and "
            "account takeover attacks originate from specific geographic "
            "regions.  Blocking access from regions where the organisation "
            "has no employees or business partners significantly reduces "
            "the attack surface without impacting legitimate users."
        ),
        impact=(
            "Users attempting to sign in from blocked regions—including "
            "business travellers—will be denied access.  The organisation "
            "should have a defined exception process for users who travel to "
            "blocked regions for business purposes."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Context-Aware Access\n"
            "  3. Verify that access levels or policies are configured to "
            "block access from unapproved geographic regions"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Context-Aware Access\n"
            "  3. Create an access level that specifies approved geographic "
            "regions\n"
            "  4. Assign this access level to a policy applied to all "
            "Google Workspace applications\n"
            "  5. Click Save"
        ),
        default_value=(
            "Context-Aware Access geo-blocking is not configured by default "
            "(non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/9275380",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="13.1",
                title="Centralize Security Event Alerting",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["geo-blocking", "context-aware", "access-control"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
