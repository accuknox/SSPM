"""
CIS MS365 6.1.2 (L1) – Ensure mailbox audit actions are configured
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1
"""

from __future__ import annotations

from typing import ClassVar

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
class CIS_6_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.1.2",
        title="Ensure mailbox audit actions are configured",
        section="6.1 Audit",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Mailbox audit logging should be enabled for all user mailboxes, and "
            "the AuditAdmin, AuditDelegate, and AuditOwner action sets should "
            "include the full recommended list of actions to record."
        ),
        rationale=(
            "Mailbox audit logs record who accessed a mailbox and what actions "
            "they performed. This is essential for detecting unauthorized access "
            "and supporting forensic investigations."
        ),
        impact="Minimal - enables audit logging which uses additional storage.",
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-EXOMailbox -PropertySets Audit,Minimum -ResultSize Unlimited | "
            "Where-Object { $_.RecipientTypeDetails -eq 'UserMailbox' }\n\n"
            "For each mailbox verify:\n"
            "  AuditEnabled = True\n"
            "  AuditAdmin includes: ApplyRecord, Copy, Create, FolderBind, "
            "HardDelete, MailItemsAccessed, Move, MoveToDeletedItems, SendAs, "
            "SendOnBehalf, Send, SoftDelete, Update, UpdateCalendarDelegation, "
            "UpdateFolderPermissions, UpdateInboxRules\n"
            "  AuditDelegate includes: ApplyRecord, Create, FolderBind, "
            "HardDelete, Move, MailItemsAccessed, MoveToDeletedItems, SendAs, "
            "SendOnBehalf, SoftDelete, Update, UpdateFolderPermissions, "
            "UpdateInboxRules\n"
            "  AuditOwner includes: ApplyRecord, Create, HardDelete, "
            "MailboxLogin, Move, MailItemsAccessed, MoveToDeletedItems, Send, "
            "SoftDelete, Update, UpdateCalendarDelegation, "
            "UpdateFolderPermissions, UpdateInboxRules"
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

    # Recommended action sets per the CIS audit procedure above.
    _REQUIRED_ADMIN: ClassVar[set] = {
        "ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete",
        "MailItemsAccessed", "Move", "MoveToDeletedItems", "SendAs",
        "SendOnBehalf", "Send", "SoftDelete", "Update",
        "UpdateCalendarDelegation", "UpdateFolderPermissions",
        "UpdateInboxRules",
    }
    _REQUIRED_DELEGATE: ClassVar[set] = {
        "ApplyRecord", "Create", "FolderBind", "HardDelete", "Move",
        "MailItemsAccessed", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
        "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules",
    }
    _REQUIRED_OWNER: ClassVar[set] = {
        "ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move",
        "MailItemsAccessed", "MoveToDeletedItems", "Send", "SoftDelete",
        "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions",
        "UpdateInboxRules",
    }

    async def check(self, data: CollectedData):
        # Per-mailbox audit settings (Get-EXOMailbox -PropertySets Audit) are
        # only available via Exchange Online Remote PowerShell - there is no
        # Microsoft Graph equivalent.
        if "mailbox_audit_settings" in (data.errors or {}):
            return self._skip(
                "Could not retrieve mailbox audit settings: "
                f"{data.errors.get('mailbox_audit_settings')}"
            )

        mailboxes = data.get("mailbox_audit_settings")
        if mailboxes is None:
            return self._skip(
                "Per-mailbox audit action configuration requires the Exchange "
                "Online PowerShell bridge (Connect-ExchangeOnline with "
                "certificate app-only auth), which is not configured for this "
                "scan. Verify manually: Get-EXOMailbox -PropertySets "
                "Audit,Minimum -ResultSize Unlimited | Where "
                "RecipientTypeDetails -eq UserMailbox - check AuditEnabled, "
                "AuditAdmin, AuditDelegate, and AuditOwner for each mailbox."
            )

        user_mailboxes = [
            m for m in mailboxes if m.get("RecipientTypeDetails") == "UserMailbox"
        ]
        if not user_mailboxes:
            return self._pass(
                "No user mailboxes were found to evaluate for audit action "
                "configuration."
            )

        non_compliant = []
        for mbx in user_mailboxes:
            name = mbx.get("DisplayName") or mbx.get("Name") or mbx.get("Identity", "")
            issues = []
            if not mbx.get("AuditEnabled"):
                issues.append("AuditEnabled is False")
            missing_admin = self._REQUIRED_ADMIN - set(mbx.get("AuditAdmin") or [])
            if missing_admin:
                issues.append(f"AuditAdmin missing: {', '.join(sorted(missing_admin))}")
            missing_delegate = self._REQUIRED_DELEGATE - set(mbx.get("AuditDelegate") or [])
            if missing_delegate:
                issues.append(
                    f"AuditDelegate missing: {', '.join(sorted(missing_delegate))}"
                )
            missing_owner = self._REQUIRED_OWNER - set(mbx.get("AuditOwner") or [])
            if missing_owner:
                issues.append(f"AuditOwner missing: {', '.join(sorted(missing_owner))}")
            if issues:
                non_compliant.append(f"{name}: {'; '.join(issues)}")

        evidence = [
            Evidence(
                source="Get-EXOMailbox -PropertySets Audit,Minimum",
                data={"mailbox_count": len(user_mailboxes)},
                description="User mailboxes evaluated for audit action configuration.",
            )
        ]

        if non_compliant:
            return self._fail(
                f"{len(non_compliant)} of {len(user_mailboxes)} user mailbox(es) "
                "have incomplete audit configuration: " + " | ".join(non_compliant),
                evidence=evidence,
            )

        return self._pass(
            f"All {len(user_mailboxes)} user mailbox(es) have AuditEnabled = True "
            "and the recommended AuditAdmin, AuditDelegate, and AuditOwner "
            "action sets configured.",
            evidence=evidence,
        )
