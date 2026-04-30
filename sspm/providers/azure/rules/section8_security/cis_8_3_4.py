"""CIS Azure 8.3.4 – Ensure that the Expiration Date is set for All Secrets in Key Vaults using access policies (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.4",
        title="Ensure that the Expiration Date is set for All Secrets in Key Vaults using access policies (legacy)",
        section="8.3 Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "All enabled secrets stored in legacy access-policy Azure Key Vaults must have an "
            "expiration date set to ensure that stale credentials and tokens are rotated on a "
            "scheduled basis."
        ),
        rationale=(
            "Secrets without expiry remain valid indefinitely, which extends the impact of "
            "any credential compromise. Setting an expiration date forces periodic secret "
            "rotation and reduces the risk window."
        ),
        impact="Applications that consume non-expiring secrets must be updated to handle rotation.",
        audit_procedure=(
            "ARM: list secrets for each access-policy Key Vault — every enabled secret must "
            "have properties.attributes.exp set to a non-null Unix timestamp."
        ),
        remediation=(
            "Key Vault → Secrets → select each secret → set an expiration date → Save."
        ),
        default_value="Secrets are created without an expiry date by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.2", title="Establish an Access Revoking Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vaults = data.get("key_vaults") or []
        secrets_map = data.get("key_vault_secrets")
        if secrets_map is None:
            return self._skip("Key vault secrets metadata could not be retrieved.")

        offenders: list[str] = []
        for vault in vaults:
            if vault.get("properties", {}).get("enableRbacAuthorization"):
                continue  # Only check access-policy (legacy) vaults
            vid = vault.get("id", "")
            vname = vault.get("name", vid)
            for secret in secrets_map.get(vid, []):
                attrs = secret.get("properties", {}).get("attributes", {})
                if not attrs.get("enabled", True):
                    continue  # Skip disabled secrets
                if not attrs.get("exp"):
                    offenders.append(f"{vname}/{secret.get('name', '?')}")

        evidence = [Evidence(
            source="arm:Microsoft.KeyVault/vaults/secrets",
            data={"secrets_without_expiry": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} secret(s) in access-policy vaults lack an expiry date: "
                f"{', '.join(offenders[:5])}.",
                evidence=evidence,
            )
        return self._pass(
            "All enabled secrets in access-policy Key Vaults have an expiry date set.",
            evidence=evidence,
        )
