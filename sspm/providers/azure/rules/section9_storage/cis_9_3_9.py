"""CIS Azure 9.3.9 – Ensure Azure Resource Manager Delete Locks are Applied to Azure Storage Accounts (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_9(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.9",
        title="Ensure Azure Resource Manager Delete Locks are Applied to Azure Storage Accounts",
        section="9 Storage Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Resource Manager (ARM) delete locks should be applied to critical storage "
            "accounts to prevent accidental or unauthorized deletion of the storage account "
            "and its data."
        ),
        rationale=(
            "A delete lock on a storage account prevents any user (including subscription "
            "owners) from deleting the account without first removing the lock. This provides "
            "a safeguard against accidental deletion, insider threats, and supply chain attacks "
            "targeting infrastructure resources."
        ),
        impact="Storage accounts with delete locks cannot be deleted without first explicitly "
               "removing the lock, which requires appropriate permissions.",
        audit_procedure=(
            "ARM: for each storage account, call "
            "GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/"
            "storageAccounts/{name}/providers/Microsoft.Authorization/locks — verify at least "
            "one lock with lockLevel=CanNotDelete exists."
        ),
        remediation=(
            "az lock create --name <lock-name> --lock-type CanNotDelete "
            "--resource-group <rg> --resource-name <sa-name> "
            "--resource-type Microsoft.Storage/storageAccounts."
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
            "Verifying that ARM delete locks are applied to storage accounts requires checking "
            "resource locks on each storage account. Review via the Azure portal "
            "(Storage account → Locks) or PowerShell: Get-AzResourceLock. Confirm that critical "
            "storage accounts have a CanNotDelete lock applied."
        )
