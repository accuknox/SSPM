"""
CIS GWS 3.1.3.5.3 (L1) – Ensure per-user outbound gateways are disabled
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
class CIS_3_1_3_5_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.5.3",
        title="Ensure per-user outbound gateways are disabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Prevents users from configuring a personal outbound mail gateway "
            "that routes their sent mail through a non-Google server.  "
            "Allowing per-user outbound gateways can bypass corporate email "
            "security controls and DLP policies."
        ),
        rationale=(
            "Per-user outbound gateways allow individual users to route their "
            "outbound email through a server of their choice, bypassing "
            "corporate email filtering, archiving, and DLP controls."
        ),
        impact=(
            "Users will not be able to configure a personal outbound mail "
            "server in their Gmail settings."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Ensure 'Allow per-user outbound gateways' is unchecked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Uncheck 'Allow per-user outbound gateways'\n"
            "  5. Click Save"
        ),
        default_value="Allow per-user outbound gateways is unchecked (already secure).",
        references=[
            "https://support.google.com/a/answer/176054",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.8",
                title="Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "outbound-gateway", "mail-routing", "end-user-access"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
