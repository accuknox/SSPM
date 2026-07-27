"""
CIS MS365 6.1.1 (L1) – Ensure 'AuditDisabled' organizationally is set to
'False' (Automated)

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
class CIS_6_1_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.1.1",
        title="Ensure 'AuditDisabled' organizationally is set to 'False'",
        section="6.1 Audit",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The AuditDisabled organization configuration in Exchange Online should "
            "be set to False to ensure mailbox auditing is enabled at the organization "
            "level."
        ),
        rationale=(
            "Organization-level audit settings control the default audit behavior "
            "for all mailboxes. If AuditDisabled is True, mailbox audit logging "
            "is disabled by default, impeding security investigations."
        ),
        impact="Minimal - enables audit logging which is generally desirable.",
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | Format-List AuditDisabled\n\n"
            "Compliant: AuditDisabled is False."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-OrganizationConfig -AuditDisabled $false"
        ),
        default_value="AuditDisabled = False by default in new tenants.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="8.2",
                title="Collect Audit Logs",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["exchange", "audit", "logging", "compliance"],
    )

    async def check(self, data: CollectedData):
        # Get-OrganizationConfig has no Microsoft Graph equivalent; it is only
        # reachable via Exchange Online Remote PowerShell.  If collection
        # errored, surface the error; otherwise always return MANUAL.
        if "organization_config" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange organization configuration: "
                f"{data.errors.get('organization_config')}"
            )

        return self._manual(
            message=(
                "AuditDisabled cannot be read via Microsoft Graph. Verify manually "
                "via Exchange Online PowerShell: Get-OrganizationConfig | "
                "Format-List AuditDisabled - must be False."
            )
        )
