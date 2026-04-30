"""CIS Azure 2.1.3 – Ensure that Traffic is Encrypted Between Cluster Worker Nodes (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.3",
        title="Ensure that Traffic is Encrypted Between Cluster Worker Nodes",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Databricks supports encrypting traffic between cluster worker nodes using "
            "AES-128 encryption over TLS 1.2. This feature must be enabled per cluster or "
            "via cluster policy to protect data in transit within the cluster."
        ),
        rationale=(
            "Without intra-cluster encryption, data shuffled between worker nodes during "
            "Spark operations is transmitted in plaintext within the VNet. An attacker with "
            "network access could intercept sensitive data being processed by the cluster."
        ),
        impact=(
            "Enabling intra-cluster encryption adds CPU overhead for encryption/decryption "
            "and may reduce cluster performance for network-intensive workloads."
        ),
        audit_procedure=(
            "In the Databricks workspace, navigate to Compute → select a cluster → Edit → "
            "Advanced Options → Spark → confirm that 'Enable encryption of traffic between "
            "cluster worker nodes' is checked. Alternatively, inspect the cluster JSON "
            "configuration for 'spark.databricks.cluster.profile' settings and the "
            "'enable_local_disk_encryption' field. Review all active cluster policies."
        ),
        remediation=(
            "Edit each cluster configuration: Compute → cluster → Edit → Advanced Options → "
            "Spark → check 'Enable encryption of traffic between cluster worker nodes' → "
            "Confirm. For new clusters, enforce this via a cluster policy with "
            "spark.databricks.workerEnv.DATABRICKS_ENABLE_INTRA_CLUSTER_ENCRYPTION = true."
        ),
        default_value="Intra-cluster traffic encryption is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/security/network/encryption",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.10",
                title="Encrypt Sensitive Data in Transit",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
