"""
CIS MS365 6.5.5 (L1) – Ensure direct send submission from devices is rejected
(Manual)

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
class CIS_6_5_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.5.5",
        title="Ensure direct send submissions from devices are rejected",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Exchange Online receive connectors should be configured to reject "
            "direct send submissions from devices that don't authenticate. "
            "Direct send allows devices to bypass spam filters."
        ),
        rationale=(
            "Direct send (unauthenticated SMTP from internal IP) can be used to "
            "send emails that appear to come from internal addresses without proper "
            "authentication, potentially bypassing security controls."
        ),
        impact=(
            "Devices using direct send (printers, scanners, network appliances) "
            "must be reconfigured to use authenticated SMTP relay."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-ReceiveConnector | Select-Object Name, Bindings, "
            "RemoteIPRanges, AuthMechanism, PermissionGroups\n\n"
            "Verify no connectors allow unauthenticated SMTP from broad IP ranges."
        ),
        remediation=(
            "Configure devices to use authenticated SMTP submission:\n"
            "  1. Use SMTP AUTH with a licensed mailbox\n"
            "  2. Or use Microsoft 365 SMTP relay with a specific connector\n"
            "  3. Remove or restrict direct send connectors"
        ),
        default_value="Default receive connectors may allow direct send.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365",
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
        tags=["exchange", "receive-connector", "direct-send", "smtp"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify receive connectors and direct send configuration:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-ReceiveConnector | Select-Object Name, Bindings, "
            "RemoteIPRanges, AuthMechanism\n\n"
            "Verify no receive connectors allow unauthenticated email from broad IP ranges."
        )
