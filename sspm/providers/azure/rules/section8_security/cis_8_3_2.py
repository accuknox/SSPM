"""CIS Azure 8.3.2 – Ensure that the Expiration Date is set for All Keys in Key Vaults using access policies (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.2",
        title="Ensure that the Expiration Date is set for All Keys in Key Vaults using access policies (legacy)",
        section="8.3 Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "All enabled cryptographic keys stored in legacy access-policy Azure Key Vaults "
            "must have an expiration date set to ensure that stale or potentially compromised "
            "keys are rotated on a scheduled basis."
        ),
        rationale=(
            "Keys without expiry dates remain valid indefinitely, increasing the window of "
            "exposure if they are ever compromised. Enforcing expiry ensures routine rotation "
            "and limits the blast radius of a key compromise."
        ),
        impact="Applications that rely on non-expiring keys must be updated to handle key rotation.",
        audit_procedure=(
            "ARM: list keys for each access-policy Key Vault — every enabled key must have "
            "properties.attributes.exp set to a non-null Unix timestamp."
        ),
        remediation=(
            "Key Vault → Keys → select each key → set an expiration date → Save."
        ),
        default_value="Keys are created without an expiry date by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.2", title="Establish an Access Revoking Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vaults = data.get("key_vaults") or []
        keys_map = data.get("key_vault_keys")
        if keys_map is None:
            return self._skip("Key vault keys metadata could not be retrieved.")

        offenders: list[str] = []
        for vault in vaults:
            if vault.get("properties", {}).get("enableRbacAuthorization"):
                continue  # Only check access-policy (legacy) vaults
            vid = vault.get("id", "")
            vname = vault.get("name", vid)
            for key in keys_map.get(vid, []):
                attrs = key.get("properties", {}).get("attributes", {})
                if not attrs.get("enabled", True):
                    continue  # Skip disabled keys
                if not attrs.get("exp"):
                    offenders.append(f"{vname}/{key.get('name', '?')}")

        evidence = [Evidence(
            source="arm:Microsoft.KeyVault/vaults/keys",
            data={"keys_without_expiry": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} key(s) in access-policy vaults lack an expiry date: "
                f"{', '.join(offenders[:5])}.",
                evidence=evidence,
            )
        return self._pass(
            "All enabled keys in access-policy Key Vaults have an expiry date set.",
            evidence=evidence,
        )
