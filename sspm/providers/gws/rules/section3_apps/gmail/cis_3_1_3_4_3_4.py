"""
CIS GWS 3.1.3.4.3.4 (L1) – Ensure protection against any
unauthenticated emails is enabled (Manual)

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
class CIS_3_1_3_4_3_4(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.4.3.4",
        title="Ensure protection against any unauthenticated emails is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Displays a warning when any message is not authenticated (SPF or DKIM).  "
            "This helps users identify emails that could not be verified as coming "
            "from a legitimate sender."
        ),
        rationale=(
            "You should protect your users from any emails that aren't authenticated "
            "(SPF or DKIM)."
        ),
        impact=(
            "Emails that aren't authenticated (SPF or DKIM) display a warning "
            "message to the recipient."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Spoofing and authentication, ensure 'Protect "
            "against any unauthenticated emails' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Spoofing and authentication, set 'Protect against "
            "any unauthenticated emails' to checked\n"
            "  4. Click Save"
        ),
        default_value="Protect against any unauthenticated emails is unchecked.",
        references=[
            "https://support.google.com/a/answer/9157861",
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
        tags=["gmail", "spoofing", "authentication", "spf", "dkim", "safety"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
