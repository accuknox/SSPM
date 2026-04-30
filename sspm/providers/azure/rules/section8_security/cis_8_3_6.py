"""CIS Azure 8.3.6 – Enable Role Based Access Control for Azure Key Vault (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.6",
        title="Enable Role Based Access Control for Azure Key Vault",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Key Vault should use Azure RBAC (``enableRbacAuthorization=true``) rather than "
            "legacy vault access policies so permissions are managed through Entra ID roles."
        ),
        rationale=(
            "RBAC provides unified access governance, fine-grained data-plane roles, and "
            "integrates with PIM/Conditional Access — unlike legacy access policies which are "
            "flat, vault-local, and easy to over-grant."
        ),
        impact="Existing access policies must be migrated to equivalent RBAC role assignments.",
        audit_procedure=(
            "ARM: GET each vault — properties.enableRbacAuthorization must be true."
        ),
        remediation="az keyvault update --name <vault> --enable-rbac-authorization true.",
        default_value="Legacy access policy mode on vaults created before 2021.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vaults = data.get("key_vaults")
        if vaults is None:
            return self._skip("Key Vaults could not be retrieved.")
        if not vaults:
            return self._pass("No Key Vaults in subscription.")

        offenders = [
            v.get("name", "?")
            for v in vaults
            if not v.get("properties", {}).get("enableRbacAuthorization")
        ]
        evidence = [Evidence(source="arm:keyVaults", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Key Vault(s) still use access policies: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vaults)} Key Vault(s) use RBAC authorization.",
            evidence=evidence,
        )
