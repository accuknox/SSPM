"""CIS Azure 9.3.2.2 – Ensure that Public Network Access is Disabled on Storage Accounts (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_2_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.2.2",
        title="Ensure that 'Public Network Access' is Disabled for Storage Accounts",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Storage accounts should block public network access, routing clients through "
            "Private Endpoints or selected VNets instead."
        ),
        rationale=(
            "Public endpoints expose data-plane authentication surfaces to the entire Internet. "
            "Disabling public access ensures traffic originates only from trusted networks."
        ),
        impact="External clients must use Private Link or a trusted VNet.",
        audit_procedure=(
            "ARM: GET each storage account — properties.publicNetworkAccess must be 'Disabled'."
        ),
        remediation=(
            "Storage account → Networking → Public network access → Disabled → Save."
        ),
        default_value="'Enabled from all networks'.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.3", title="Configure Data Access Control Lists", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        accounts = data.get("storage_accounts")
        if accounts is None:
            return self._skip("Storage accounts could not be retrieved.")
        if not accounts:
            return self._pass("No storage accounts in subscription.")

        offenders: list[str] = []
        for sa in accounts:
            name = sa.get("name", "?")
            value = (sa.get("properties", {}).get("publicNetworkAccess") or "").lower()
            if value != "disabled":
                offenders.append(f"{name} ({value or 'enabled'})")

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) have public network access enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) disable public network access.",
            evidence=evidence,
        )
