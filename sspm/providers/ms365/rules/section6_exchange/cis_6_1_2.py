"""
CIS MS365 6.1.2 (L1) – Ensure mailbox auditing for all users is enabled
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
class CIS_6_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.1.2",
        title="Ensure mailbox auditing for all users is enabled",
        section="6.1 Audit",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Mailbox audit logging should be enabled for all mailboxes to record "
            "access and actions taken on mailboxes. This supports security "
            "investigations and compliance requirements."
        ),
        rationale=(
            "Mailbox audit logs record who accessed a mailbox and what actions "
            "they performed. This is essential for detecting unauthorized access "
            "and supporting forensic investigations."
        ),
        impact="Minimal - enables audit logging which uses additional storage.",
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-Mailbox -ResultSize Unlimited | Select-Object UserPrincipalName, "
            "AuditEnabled, AuditLogAgeLimit\n\n"
            "Compliant: AuditEnabled = True for all mailboxes.\n"
            "Also verify AuditAdmin, AuditDelegate, and AuditOwner contain "
            "recommended actions."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true\n\n"
            "Also configure comprehensive audit actions:\n"
            "  Set-Mailbox -AuditAdmin @{Add='Copy','Create','FolderBind',...}\n"
            "  Set-Mailbox -AuditOwner @{Add='MailboxLogin','Move','MoveToDeletedItems',...}"
        ),
        default_value="Mailbox auditing is enabled by default in Exchange Online.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/enable-or-disable",
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
        tags=["exchange", "audit", "mailbox", "logging"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify mailbox audit logging via Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-Mailbox -ResultSize Unlimited | "
            "Where-Object {$_.AuditEnabled -ne $true} | "
            "Select-Object UserPrincipalName, AuditEnabled\n\n"
            "Compliant: All mailboxes have AuditEnabled = True."
        )
