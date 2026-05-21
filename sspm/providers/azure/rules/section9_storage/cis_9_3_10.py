"""CIS Azure 9.3.10 – Ensure Azure Resource Manager ReadOnly Locks are Considered for Azure Storage Accounts (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_10(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.10",
        title="Ensure Azure Resource Manager ReadOnly Locks are Considered for Azure Storage Accounts",
        section="9 Storage Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.LOW,
        description=(
            "Azure Resource Manager ReadOnly locks should be considered for storage accounts "
            "whose configuration should not change. A ReadOnly lock prevents modifications to "
            "account properties, network rules, and access settings without first removing the lock."
        ),
        rationale=(
            "ReadOnly locks protect storage account configuration from unauthorized or accidental "
            "changes. For accounts hosting critical data with stable configurations, a ReadOnly "
            "lock provides an additional layer of protection against configuration drift and "
            "insider threats."
        ),
        impact="ReadOnly locks prevent any modification to the storage account resource, including "
               "adding new private endpoints, changing firewall rules, or updating configuration. "
               "The lock must be removed before performing legitimate administrative changes.",
        audit_procedure=(
            "ARM: for each storage account, call "
            "GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/"
            "storageAccounts/{name}/providers/Microsoft.Authorization/locks — assess whether "
            "a ReadOnly lock is appropriate for the account's use case and risk profile."
        ),
        remediation=(
            "az lock create --name <lock-name> --lock-type ReadOnly "
            "--resource-group <rg> --resource-name <sa-name> "
            "--resource-type Microsoft.Storage/storageAccounts "
            "(apply selectively based on risk assessment)."
        ),
        default_value="No resource locks are applied to storage accounts by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.1", title="Establish and Maintain a Data Recovery Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Evaluating whether ReadOnly locks are appropriate for storage accounts requires "
            "manual review of each account's use case and change frequency. Review via the "
            "Azure portal (Storage account → Locks) and assess whether static-configuration "
            "accounts benefit from ReadOnly lock protection. Apply selectively based on "
            "risk assessment."
        )
