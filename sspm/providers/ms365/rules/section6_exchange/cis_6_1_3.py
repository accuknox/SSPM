"""
CIS MS365 6.1.3 (L1) – Ensure 'AuditBypassEnabled' is not enabled on
mailboxes (Automated)

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
        title="Ensure 'AuditBypassEnabled' is not enabled on mailboxes",
        section="6.1 Audit",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-MailboxAuditBypassAssociation -ResultSize unlimited | "
            "where AuditBypassEnabled -eq $true | select Name,AuditBypassEnabled\n\n"
            "Compliant: no accounts are returned (no accounts bypass auditing)."
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
        # Get-MailboxAuditBypassAssociation has no Microsoft Graph equivalent;
        # it is only reachable via Exchange Online Remote PowerShell.
        if "mailbox_audit_bypass_association" in (data.errors or {}):
            return self._skip(
                "Could not retrieve mailbox audit bypass associations: "
                f"{data.errors.get('mailbox_audit_bypass_association')}"
            )

        return self._manual(
            message=(
                "Mailbox audit bypass associations cannot be read via Microsoft "
                "Graph. Verify manually via Exchange Online PowerShell: "
                "Get-MailboxAuditBypassAssociation -ResultSize unlimited | where "
                "AuditBypassEnabled -eq $true - no accounts should be returned."
            )
        )
