"""
CIS MS365 6.1.3 (L1) – Ensure 'AuditBypassEnabled' is not enabled for any
mailbox (Manual)

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
class CIS_6_1_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.1.3",
        title="Ensure 'AuditBypassEnabled' is not enabled for any mailbox",
        section="6.1 Audit",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "No mailboxes should have audit bypass enabled. Audit bypass allows "
            "specific accounts to access mailboxes without generating audit log "
            "entries, which could be used to hide unauthorized access."
        ),
        rationale=(
            "Audit bypass provides a way to access mailboxes without leaving "
            "an audit trail. This can be abused by attackers or malicious insiders "
            "to cover their tracks when accessing sensitive mailboxes."
        ),
        impact="Removing audit bypass ensures all mailbox access is logged.",
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-MailboxAuditBypassAssociation -ResultSize Unlimited | "
            "Where-Object {$_.AuditBypassEnabled -eq $true}\n\n"
            "Compliant: No mailboxes with AuditBypassEnabled = True."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Get-MailboxAuditBypassAssociation -ResultSize Unlimited | "
            "Where-Object {$_.AuditBypassEnabled} | "
            "ForEach-Object { Set-MailboxAuditBypassAssociation "
            "-Identity $_.Identity -AuditBypassEnabled $false }"
        ),
        default_value="Audit bypass is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/bypass-mailbox-audit-logging",
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
        tags=["exchange", "audit", "bypass", "logging"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
