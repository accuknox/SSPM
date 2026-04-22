"""CIS Azure 8.3.10 – Ensure that Azure Key Vault Managed HSM is Used when Required (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_10(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.10",
        title="Ensure that Azure Key Vault Managed HSM is Used when Required",
        section="8.3 Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "For workloads that require FIPS 140-2 Level 3 validated hardware security modules, "
            "Azure Key Vault Managed HSM should be used instead of standard Key Vault to ensure "
            "that cryptographic keys are protected by dedicated hardware."
        ),
        rationale=(
            "Standard Key Vault uses software-protected keys or shared HSM hardware. Managed "
            "HSM provides dedicated, single-tenant HSM hardware that satisfies regulatory and "
            "compliance requirements for the highest level of key protection."
        ),
        impact="Managed HSM incurs higher cost than standard Key Vault.",
        audit_procedure=(
            "Review the organization's data classification policy and cryptographic key "
            "management standard to identify workloads requiring HSM-backed keys. "
            "Verify that such workloads use Key Vault Managed HSM."
        ),
        remediation=(
            "For workloads with HSM requirements: deploy a Managed HSM pool, migrate relevant "
            "keys, and update application key URIs to reference the Managed HSM endpoint."
        ),
        default_value="Standard Key Vault is used by default; Managed HSM must be explicitly provisioned.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.11", title="Encrypt Sensitive Data at Rest", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
