"""CIS Azure 6.1.1.8 – Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Entra Activity Logs to an Appropriate Destination (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_8(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.8",
        title="Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Entra Activity Logs to an Appropriate Destination",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "A Microsoft Entra diagnostic setting should be configured to forward Entra activity "
            "logs (audit logs and sign-in logs) to a Log Analytics workspace, storage account, "
            "or Event Hub for long-term retention and centralized analysis."
        ),
        rationale=(
            "Microsoft Entra activity logs record sign-in events and directory audit actions. "
            "Without a diagnostic setting, these logs are retained for only 30 days (or 7 days "
            "on the free tier), making forensic investigation of security incidents difficult."
        ),
        impact=(
            "Log ingestion costs depend on the number of users and sign-in volume. Configure "
            "appropriate retention policies to manage costs."
        ),
        audit_procedure=(
            "Entra admin center → Monitoring → Diagnostic settings: verify that a diagnostic "
            "setting exists with AuditLogs and SignInLogs (and optionally other log categories) "
            "enabled and forwarded to a valid destination."
        ),
        remediation=(
            "Entra admin center → Monitoring → Diagnostic settings → Add diagnostic setting → "
            "select AuditLogs and SignInLogs categories → configure destination (Log Analytics "
            "workspace recommended) → Save."
        ),
        default_value="No Entra diagnostic settings exist by default; logs retained for 30 days maximum.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-integrate-activity-logs-with-azure-monitor-logs",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying Microsoft Entra activity log diagnostic settings requires manual review "
            "via Entra admin center → Monitoring → Diagnostic settings."
        )
