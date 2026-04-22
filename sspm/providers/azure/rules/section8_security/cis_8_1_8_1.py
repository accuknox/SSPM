"""CIS Azure 8.1.8.1 – Ensure Microsoft Defender for Key Vault Is Set To 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_8_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.8.1",
        title="Ensure Microsoft Defender for Key Vault Is Set To 'On'",
        section="8.1.8 Defender Plan: Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for Key Vault detects unusual and potentially harmful attempts "
            "to access or exploit Key Vault accounts, such as suspicious access patterns, "
            "brute-force attacks, and anomalous operations."
        ),
        rationale=(
            "Key Vaults hold the cryptographic keys, certificates, and secrets that protect "
            "the rest of the environment. Defender for Key Vault provides the first line of "
            "detection when those credentials are targeted."
        ),
        impact="Defender for Key Vault incurs per-vault monthly pricing.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/KeyVaults — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Key Vault → "
            "toggle Plan to On → Save."
        ),
        default_value="Defender for Key Vault is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.1", title="Centralize Security Event Alerting", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        plan = next(
            (p for p in pricings if (p.get("name") or "").lower() == "keyvaults"),
            None,
        )
        if plan is None:
            return self._fail("Defender for Key Vault plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"KeyVaults": tier})]
        if tier == "standard":
            return self._pass("Defender for Key Vault plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for Key Vault plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
