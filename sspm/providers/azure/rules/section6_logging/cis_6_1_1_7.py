"""CIS Azure 6.1.1.7 – Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Graph Activity Logs to an Appropriate Destination (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.7",
        title="Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Graph Activity Logs to an Appropriate Destination",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "A Microsoft Entra diagnostic setting should be configured to forward Microsoft Graph "
            "activity logs to a Log Analytics workspace, storage account, or Event Hub for "
            "long-term retention and analysis."
        ),
        rationale=(
            "Microsoft Graph activity logs record API calls made to the Graph API, including "
            "read and write operations on directory objects. Forwarding these logs enables "
            "detection of suspicious enumeration, data access, or configuration changes via "
            "the Graph API."
        ),
        impact=(
            "Log ingestion costs depend on the volume of Graph API activity. Configure "
            "appropriate retention policies to manage costs."
        ),
        audit_procedure=(
            "Entra admin center → Monitoring → Diagnostic settings: verify that a diagnostic "
            "setting exists with the 'MicrosoftGraphActivityLogs' category enabled and a "
            "valid destination (Log Analytics workspace, storage account, or Event Hub) configured."
        ),
        remediation=(
            "Entra admin center → Monitoring → Diagnostic settings → Add diagnostic setting → "
            "select 'MicrosoftGraphActivityLogs' category → configure destination → Save."
        ),
        default_value="No Entra diagnostic settings for Graph activity logs exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-microsoft-graph-activity-logs",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying Microsoft Graph activity log diagnostic settings requires manual review "
            "via Entra admin center → Monitoring → Diagnostic settings."
        )
