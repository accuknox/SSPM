"""CIS Azure 2.1.8 – Ensure Critical Data in Azure Databricks is Encrypted with Customer-managed Keys (CMK) (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_8(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.8",
        title="Ensure Critical Data in Azure Databricks is Encrypted with Customer-managed Keys (CMK)",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Azure Databricks supports customer-managed keys (CMK) for encrypting managed disks, "
            "DBFS root storage, and managed services. Critical data should be encrypted using "
            "CMK stored in Azure Key Vault rather than Microsoft-managed keys, providing full "
            "control over key lifecycle and access."
        ),
        rationale=(
            "Microsoft-managed encryption keys are managed entirely by Microsoft. CMK encryption "
            "gives organizations control to rotate, revoke, or expire keys, meeting regulatory "
            "requirements such as GDPR, HIPAA, and PCI-DSS that mandate customer control over "
            "encryption keys for sensitive data."
        ),
        impact=(
            "CMK configuration for Databricks managed disks requires Premium SKU workspace. "
            "Key Vault soft-delete and purge protection must be enabled. Key revocation will "
            "render all encrypted data inaccessible until the key is restored."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace check: "
            "properties.encryption.entities.managedDisk.keySource == 'Microsoft.Keyvault' for "
            "managed disk CMK, and properties.encryption.entities.managedServices.keySource == "
            "'Microsoft.Keyvault' for managed services CMK. Also verify DBFS root CMK via "
            "the Azure Portal → Databricks workspace → Encryption."
        ),
        remediation=(
            "Azure Portal → Databricks workspace → Encryption → enable Customer-Managed Key "
            "for Managed Disks and/or Managed Services → select Key Vault and key → Save. "
            "For new workspaces, configure CMK during workspace creation via ARM template or "
            "Terraform using the encryption block in workspace properties."
        ),
        default_value="Azure Databricks uses Microsoft-managed keys for encryption by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/security/keys/customer-managed-keys-managed-disk-azure",
            "https://learn.microsoft.com/en-us/azure/databricks/security/keys/customer-managed-key-managed-services-azure",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.11",
                title="Encrypt Sensitive Data at Rest",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
