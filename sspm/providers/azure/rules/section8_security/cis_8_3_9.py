"""CIS Azure 8.3.9 – Ensure Automatic Key Rotation is Enabled within Azure Key Vault (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_9(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.9",
        title="Ensure Automatic Key Rotation is Enabled within Azure Key Vault",
        section="8.3 Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "All enabled cryptographic keys stored in Azure Key Vault should have an automatic "
            "rotation policy configured so that keys are periodically regenerated without "
            "manual intervention."
        ),
        rationale=(
            "Manual key rotation is error-prone and often deferred. Automatic rotation ensures "
            "that the cryptographic material is refreshed regularly, limiting the damage caused "
            "by any undetected key compromise."
        ),
        impact="Applications must be able to retrieve the latest key version after rotation.",
        audit_procedure=(
            "ARM: list keys for each vault — every enabled key must have "
            "properties.rotationPolicy configured (non-empty object)."
        ),
        remediation=(
            "Key Vault → Keys → select each key → Rotation policy → configure rotation "
            "schedule (e.g. rotate every 90 days) → Save."
        ),
        default_value="No rotation policy is configured on keys by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.2", title="Establish an Access Revoking Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        keys_map = data.get("key_vault_keys")
        if keys_map is None:
            return self._skip("Key vault keys metadata could not be retrieved.")

        offenders: list[str] = []
        for vault_id, keys in keys_map.items():
            # Extract a short vault name from the vault ID
            vault_label = vault_id.split("/")[-1] if "/" in vault_id else vault_id
            for key in keys:
                attrs = key.get("properties", {}).get("attributes", {})
                if not attrs.get("enabled", True):
                    continue  # Skip disabled keys
                rotation_policy = key.get("properties", {}).get("rotationPolicy")
                if not rotation_policy:
                    offenders.append(f"{vault_label}/{key.get('name', '?')}")

        evidence = [Evidence(
            source="arm:Microsoft.KeyVault/vaults/keys",
            data={"keys_without_rotation_policy": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} key(s) have no automatic rotation policy configured: "
                f"{', '.join(offenders[:5])}.",
                evidence=evidence,
            )
        return self._pass(
            "All enabled Key Vault keys have an automatic rotation policy configured.",
            evidence=evidence,
        )
