"""
CIS MS365 3.1.1 (L1) – Ensure Microsoft 365 audit log search is Enabled (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

The Microsoft Purview unified audit log must be enabled so that administrator
and user activity is recorded and available for security investigations.

Per the official CIS audit procedure, this is read via Exchange Online /
Security & Compliance PowerShell (Get-AdminAuditLogConfig ->
UnifiedAuditLogIngestionEnabled). There is no Microsoft Graph field that
reflects this specific setting — sign-in log query accessibility (previously
used here as a proxy) does not actually verify it.
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
class CIS_3_1_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-3.1.1",
        title="Ensure Microsoft 365 audit log search is Enabled",
        section="3.1 Audit",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The Microsoft 365 unified audit log records user and administrator "
            "activity across Exchange Online, SharePoint Online, OneDrive for Business, "
            "Microsoft Teams, and other services.  It must be enabled for effective "
            "security monitoring and incident investigation."
        ),
        rationale=(
            "Without audit logging, security teams cannot investigate incidents, "
            "detect malicious activity, or meet compliance requirements that mandate "
            "audit trails of administrative and user actions."
        ),
        impact="Minimal.  Audit logging has negligible performance impact.",
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled\n"
            "  Ensure UnifiedAuditLogIngestionEnabled is True.\n\n"
            "Microsoft Purview (https://purview.microsoft.com) → Solutions > Audit → "
            "verify search results are returned for a recent activity."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true\n\n"
            "Or in Microsoft Purview compliance portal:\n"
            "  Audit → Turn on auditing."
        ),
        default_value="Enabled by default in new tenants since 2019.",
        references=[
            "https://learn.microsoft.com/en-us/purview/audit-log-enable-disable",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/set-adminauditlogconfig",
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
            CISControl(
                version="v7",
                control_id="6.2",
                title="Activate Audit Logging",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["audit", "logging", "compliance", "purview"],
    )

    async def check(self, data: CollectedData):
        if "admin_audit_log_config" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange admin audit log configuration: "
                f"{data.errors.get('admin_audit_log_config')}"
            )
        # Get-AdminAuditLogConfig has no Microsoft Graph equivalent; it is
        # only reachable via Exchange Online / Security & Compliance Remote
        # PowerShell. Sign-in log query accessibility (a Graph signal) does
        # not verify UnifiedAuditLogIngestionEnabled specifically.
        return self._manual(
            message=(
                "UnifiedAuditLogIngestionEnabled cannot be read via Microsoft "
                "Graph. Verify manually via Exchange Online PowerShell: "
                "Get-AdminAuditLogConfig | Select-Object "
                "UnifiedAuditLogIngestionEnabled — must be True."
            )
        )
