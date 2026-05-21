"""CIS Azure 9.2.3 – Ensure 'Versioning' is Set to 'Enabled' on Azure Blob Storage Storage Accounts (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_2_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.2.3",
        title="Ensure 'Versioning' is Set to 'Enabled' on Azure Blob Storage Storage Accounts",
        section="9.2 Azure Blob Storage",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Blob versioning should be enabled on storage accounts to automatically maintain "
            "previous versions of a blob, allowing recovery from accidental overwrites or "
            "deletions."
        ),
        rationale=(
            "Blob versioning preserves the state of every blob modification. If data is "
            "accidentally overwritten or deleted (including by ransomware), a previous version "
            "can be restored without requiring a separate backup process."
        ),
        impact="Each version of a blob consumes storage; implement lifecycle policies to manage "
               "version retention costs.",
        audit_procedure=(
            "ARM: GET each storage account's blobServices/default — "
            "properties.isVersioningEnabled must be true."
        ),
        remediation=(
            "az storage account blob-service-properties update --account-name <name> "
            "--enable-versioning true."
        ),
        default_value="Blob versioning is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.2", title="Perform Automated Backups", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        blob_services = data.get("storage_blob_services") or {}
        if not blob_services:
            return self._skip("Storage blob services could not be retrieved.")

        offenders: list[str] = []
        for acct_id, svc in blob_services.items():
            name = acct_id.split("/")[-1]
            if not (svc.get("properties") or {}).get("isVersioningEnabled"):
                offenders.append(name)

        evidence = [Evidence(source="arm:storage/blobServices", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) do not have blob versioning enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(blob_services)} storage account(s) have blob versioning enabled.",
            evidence=evidence,
        )
