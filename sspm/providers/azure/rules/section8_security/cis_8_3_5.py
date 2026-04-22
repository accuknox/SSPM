"""CIS Azure 8.3.5 – Ensure the Key Vault is Recoverable (Purge Protection Enabled) (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.5",
        title="Ensure the Key Vault is Recoverable (Soft Delete + Purge Protection)",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Every Key Vault must have soft-delete enabled and purge protection turned on so "
            "that vaults and secrets cannot be permanently destroyed inside the retention window."
        ),
        rationale=(
            "Purge protection defeats the 'delete and re-create' attack used by ransomware and "
            "malicious insiders to erase cryptographic material that unlocks critical data."
        ),
        impact=(
            "Deleted vaults/secrets cannot be force-purged for the retention period (7-90 days); "
            "plan resource-name reuse accordingly."
        ),
        audit_procedure=(
            "ARM: GET each vault — properties.enableSoftDelete must be true and "
            "properties.enablePurgeProtection must be true."
        ),
        remediation=(
            "az keyvault update --name <vault> --enable-purge-protection true "
            "(soft delete is on by default and cannot be disabled)."
        ),
        default_value="Soft delete on; purge protection off.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.1", title="Establish and Maintain a Data Recovery Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vaults = data.get("key_vaults")
        if vaults is None:
            return self._skip("Key Vaults could not be retrieved.")
        if not vaults:
            return self._pass("No Key Vaults in subscription.")

        offenders: list[str] = []
        for v in vaults:
            props = v.get("properties", {})
            name = v.get("name", "?")
            soft = props.get("enableSoftDelete")
            purge = props.get("enablePurgeProtection")
            # Soft delete defaults to true for modern vaults; explicit False is non-compliant.
            if soft is False or not purge:
                offenders.append(
                    f"{name} (soft_delete={'on' if soft else 'off'}, "
                    f"purge_protection={'on' if purge else 'off'})"
                )

        evidence = [Evidence(source="arm:keyVaults", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Key Vault(s) are not fully recoverable: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vaults)} Key Vault(s) have soft-delete + purge protection enabled.",
            evidence=evidence,
        )
