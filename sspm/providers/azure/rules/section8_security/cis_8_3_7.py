"""CIS Azure 8.3.7 – Ensure that Public Network Access is Disabled for Azure Key Vault (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.7",
        title="Ensure that Public Network Access is Disabled for Azure Key Vault",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.HIGH,
        description=(
            "Key Vaults should only be reachable through Private Endpoints or trusted services. "
            "``properties.publicNetworkAccess`` must be ``Disabled`` and the network ACL default "
            "action must be ``Deny``."
        ),
        rationale=(
            "Public endpoints expose vault authentication surfaces to the entire Internet. "
            "Private Endpoints ensure secrets never traverse the public network."
        ),
        impact="Clients must access the vault over an approved VNet / private link.",
        audit_procedure=(
            "ARM: GET each vault. Compliant when properties.publicNetworkAccess == 'Disabled' OR "
            "(publicNetworkAccess == 'Enabled' AND properties.networkAcls.defaultAction == 'Deny')."
        ),
        remediation=(
            "Key Vault → Networking → Disable public access (or Selected networks with default Deny)."
        ),
        default_value="Public network access is Enabled.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.3", title="Configure Data Access Control Lists", ig1=True, ig2=True, ig3=True),
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
            name = v.get("name", "?")
            props = v.get("properties", {})
            public = (props.get("publicNetworkAccess") or "").lower()
            default_action = (
                (props.get("networkAcls") or {}).get("defaultAction") or ""
            ).lower()
            if public == "disabled":
                continue
            if public == "enabled" and default_action == "deny":
                continue
            offenders.append(f"{name} (public={public or 'enabled'}, default={default_action or 'allow'})")

        evidence = [Evidence(source="arm:keyVaults", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Key Vault(s) accept unrestricted public access: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vaults)} Key Vault(s) have public network access restricted.",
            evidence=evidence,
        )
