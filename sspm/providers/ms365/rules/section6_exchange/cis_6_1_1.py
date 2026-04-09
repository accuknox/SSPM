"""
CIS MS365 6.1.1 (L1) – Ensure 'AuditDisabled' organizationally is set to
'False' (Manual)

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
        assessment_status=AssessmentStatus.MANUAL,
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
            "Using Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | Select-Object AuditDisabled\n\n"
            "Compliant: AuditDisabled = False"
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
        return self._manual(
            "Verify Exchange Online audit configuration:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | Select-Object AuditDisabled\n\n"
            "Compliant: AuditDisabled = False"
        )
