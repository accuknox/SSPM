"""
CIS MS365 2.2.1 (L1) – Ensure that activity monitoring of emergency access
accounts is configured (Manual)

Profile Applicability: E3 Level 1, E5 Level 1
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_2_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.2.1",
        title="Ensure that activity monitoring of emergency access accounts is configured",
        section="2.2 Microsoft 365 Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Emergency access accounts (break-glass accounts) should be monitored "
            "for any sign-in activity. Any use of these accounts should trigger "
            "immediate alerts to security administrators."
        ),
        rationale=(
            "Emergency access accounts are highly privileged accounts that should "
            "only be used in dire circumstances. Monitoring for their use helps "
            "detect unauthorized access and ensures accountability when they are used."
        ),
        impact=(
            "Security team will receive alerts when emergency access accounts are "
            "used, requiring investigation to verify whether the use was legitimate."
        ),
        audit_procedure=(
            "Verify monitoring configuration:\n"
            "  1. Microsoft Entra admin center → Identity > Monitoring & health > "
            "Workbooks > Sign-ins\n"
            "  2. Azure Monitor / Log Analytics:\n"
            "     Create an alert rule for sign-in events from emergency access accounts\n"
            "  3. Microsoft Sentinel:\n"
            "     Configure analytic rules for break-glass account sign-ins\n\n"
            "Verify that alerts are configured for all emergency access account UPNs."
        ),
        remediation=(
            "Azure Monitor → Alerts > Create alert rule:\n"
            "  • Signal type: Log (Log Analytics)\n"
            "  • Signal: SigninLogs\n"
            "  • Condition: UserPrincipalName == '<emergency-account-upn>'\n"
            "  • Action group: Notify security team immediately\n\n"
            "Or use Microsoft Sentinel with a custom analytic rule."
        ),
        default_value="No monitoring is configured for emergency access accounts by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
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
        tags=["monitoring", "emergency-access", "break-glass", "alerting"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
