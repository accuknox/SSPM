"""CIS Azure 9.3.11 – Ensure Redundancy is Set to 'geo-redundant storage (GRS)' on Critical Azure Storage Accounts (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_11(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.11",
        title="Ensure Redundancy is Set to 'geo-redundant storage (GRS)' on Critical Azure Storage Accounts",
        section="9 Storage Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Critical storage accounts should use geo-redundant storage (GRS, RAGRS, GZRS, or "
            "RAGZRS) to ensure that data is replicated to a secondary Azure region. This "
            "protects against regional outages and data loss."
        ),
        rationale=(
            "Locally redundant (LRS) and zone-redundant (ZRS) storage replicate data only "
            "within a single region. A regional disaster would result in permanent data loss. "
            "Geo-redundant storage replicates asynchronously to a paired region hundreds of "
            "miles away, providing recovery options during regional failures."
        ),
        impact="Geo-redundant storage has a higher cost than LRS/ZRS; evaluate per account based "
               "on data criticality and RTO/RPO requirements.",
        audit_procedure=(
            "ARM: GET each storage account — sku.name must be one of: "
            "Standard_GRS, Standard_RAGRS, Standard_GZRS, Standard_RAGZRS, Premium_GRS, "
            "Premium_RAGRS (any value containing 'GRS', 'RAGRS', 'GZRS', or 'RAGZRS')."
        ),
        remediation=(
            "az storage account update --name <name> --sku Standard_RAGRS "
            "(or via portal: Storage account → Configuration → Replication → "
            "select geo-redundant option)."
        ),
        default_value="Storage accounts default to LRS (locally-redundant storage).",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.2", title="Perform Automated Backups", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        accounts = data.get("storage_accounts")
        if accounts is None:
            return self._skip("Storage accounts could not be retrieved.")
        if not accounts:
            return self._pass("No storage accounts in subscription.")

        _GEO_REDUNDANT = {"GRS", "RAGRS", "GZRS", "RAGZRS"}

        offenders: list[str] = []
        for sa in accounts:
            name = sa.get("name", "?")
            sku_name = (sa.get("sku") or {}).get("name") or ""
            # Check if the SKU name contains any geo-redundant tier suffix
            if not any(geo in sku_name.upper() for geo in _GEO_REDUNDANT):
                offenders.append(f"{name} ({sku_name or 'unknown SKU'})")

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) are not using geo-redundant storage: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) use geo-redundant storage.",
            evidence=evidence,
        )
