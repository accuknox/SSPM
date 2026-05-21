"""CIS Azure 6.1.1.3 – Ensure the Storage Account Containing the Container with Activity Logs is Encrypted with Customer-managed Key (CMK) (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.3",
        title="Ensure the Storage Account Containing the Container with Activity Logs is Encrypted with Customer-managed Key (CMK)",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "If activity logs are archived to a storage account, that storage account should be "
            "encrypted using a customer-managed key (CMK) stored in Azure Key Vault to provide "
            "an additional layer of control over the encryption keys."
        ),
        rationale=(
            "Activity logs may contain sensitive information about administrative actions. "
            "Encrypting the storage account with a CMK ensures that the organization retains "
            "full control over the encryption keys and can revoke access to the logs if required."
        ),
        impact=(
            "Requires an Azure Key Vault with a key and appropriate access configuration. "
            "CMK encryption adds operational complexity for key rotation and management."
        ),
        audit_procedure=(
            "Identify the storage account configured as the destination for activity log "
            "diagnostic settings. Navigate to the storage account → Encryption → verify that "
            "Encryption type is set to 'Customer-managed keys' and a Key Vault key is configured."
        ),
        remediation=(
            "Navigate to the storage account used for activity log archival → Encryption → "
            "select 'Customer-managed keys' → select the Key Vault and key → Save. Ensure the "
            "storage account's managed identity has Get, Wrap Key, and Unwrap Key permissions "
            "on the Key Vault key."
        ),
        default_value="Storage accounts are encrypted with Microsoft-managed keys by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.11", title="Encrypt Sensitive Data at Rest", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying CMK encryption on the activity log storage account requires manual "
            "inspection of the storage account encryption settings in the Azure portal."
        )
