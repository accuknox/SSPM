"""
CIS MS365 6.5.5 (L1) – Ensure Direct Send submissions are rejected
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    Evidence,
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
        title="Ensure Direct Send submissions are rejected",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Direct Send allows devices and applications on the organization's "
            "network to submit mail directly to Exchange Online without "
            "authenticating, using the tenant's default domain. The "
            "RejectDirectSend organization setting should be enabled to reject "
            "these unauthenticated submissions."
        ),
        rationale=(
            "Direct Send (unauthenticated SMTP submission using the tenant's "
            "accepted domain) can be abused by attackers to spoof internal "
            "senders and bypass authentication-based security controls. "
            "Rejecting Direct Send submissions forces devices to use "
            "authenticated methods instead."
        ),
        impact=(
            "Devices using Direct Send (printers, scanners, network appliances) "
            "must be reconfigured to use authenticated SMTP (SMTP AUTH) or an "
            "Microsoft 365 SMTP relay connector."
        ),
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | fl RejectDirectSend\n\n"
            "Compliant: RejectDirectSend = True"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-OrganizationConfig -RejectDirectSend $true\n\n"
            "Reconfigure devices to use authenticated SMTP submission:\n"
            "  1. Use SMTP AUTH with a licensed mailbox\n"
            "  2. Or use a Microsoft 365 SMTP relay connector"
        ),
        default_value="RejectDirectSend may be False by default.",
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
        tags=["exchange", "direct-send", "smtp", "spoofing"],
    )

    async def check(self, data: CollectedData):
        # Get-OrganizationConfig has no Microsoft Graph equivalent; it is only
        # reachable via Exchange Online Remote PowerShell.
        if "organization_config" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange organization configuration: "
                f"{data.errors.get('organization_config')}"
            )

        org_config = data.get("organization_config")
        if org_config is None:
            return self._manual(
                "RejectDirectSend requires the Exchange Online PowerShell "
                "bridge (Connect-ExchangeOnline with certificate app-only "
                "auth), which is not configured for this scan. Verify "
                "manually: Get-OrganizationConfig | fl RejectDirectSend - "
                "must be True."
            )

        reject_direct_send = org_config.get("RejectDirectSend")
        evidence = [
            Evidence(
                source="Get-OrganizationConfig",
                data={"RejectDirectSend": reject_direct_send},
                description="Organization-level Direct Send rejection setting.",
            )
        ]

        if not reject_direct_send:
            return self._fail(
                "RejectDirectSend is not True; unauthenticated Direct Send "
                "submissions are still accepted.",
                evidence=evidence,
            )

        return self._pass(
            "RejectDirectSend is True.",
            evidence=evidence,
        )
