"""CIS Azure 6.1.1.9 – Ensure that Intune Logs are Captured and Sent to Log Analytics (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_9(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.9",
        title="Ensure that Intune Logs are Captured and Sent to Log Analytics",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.LOW,
        description=(
            "Microsoft Intune diagnostic logs (audit logs and operational logs) should be "
            "configured to forward to a Log Analytics workspace for centralized monitoring "
            "and long-term retention."
        ),
        rationale=(
            "Intune logs capture device enrollment, compliance policy evaluation, and "
            "configuration changes. Centralizing these logs enables detection of unauthorized "
            "device management activity and supports compliance reporting."
        ),
        impact=(
            "Log ingestion costs depend on the number of managed devices and Intune activity "
            "volume. Configure appropriate retention policies."
        ),
        audit_procedure=(
            "Intune admin center (intune.microsoft.com) → Reports → Diagnostic settings: "
            "verify that a diagnostic setting exists forwarding AuditLogs and OperationalLogs "
            "to a Log Analytics workspace or other destination."
        ),
        remediation=(
            "Intune admin center → Reports → Diagnostic settings → Add diagnostic setting → "
            "select AuditLogs and OperationalLogs → configure destination → Save."
        ),
        default_value="No Intune diagnostic settings are configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/mem/intune/fundamentals/review-logs-using-azure-monitor",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying Intune diagnostic log configuration requires manual review via the "
            "Intune admin center → Reports → Diagnostic settings."
        )
