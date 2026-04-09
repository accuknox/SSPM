"""
CIS MS365 3.1.1 (L1) – Ensure Microsoft 365 audit log search is Enabled (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

The Microsoft Purview unified audit log must be enabled so that administrator
and user activity is recorded and available for security investigations.
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
            "  Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled\n"
            "  Expected: UnifiedAuditLogIngestionEnabled = True\n\n"
            "Or check via Microsoft Purview compliance portal:\n"
            "  https://compliance.microsoft.com → Audit > Start recording user and "
            "admin activity."
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
        # Purview audit log status is checked via Graph beta security endpoint
        audit_settings = data.get("audit_log_settings")

        if audit_settings is None:
            return self._skip(
                "Could not retrieve audit log settings. "
                "Requires Compliance Administrator role."
            )

        # If the API returned results (queries work), auditing is enabled
        # A more precise check requires Exchange Online PowerShell
        if isinstance(audit_settings, list):
            return self._pass(
                "Microsoft 365 unified audit log appears to be enabled "
                "(audit log queries are accessible).",
                evidence=[
                    Evidence(
                        source="graph/security/auditLog/queries",
                        data={"queryable": True},
                        description="Audit log API is accessible.",
                    )
                ],
            )

        return self._manual(
            "Verify audit log status via Exchange Online PowerShell: "
            "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled"
        )
