"""CIS Azure 9.2.2 – Ensure that Soft Delete for Containers on Azure Blob Storage is Enabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_2_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.2.2",
        title="Ensure that Soft Delete for Containers on Azure Blob Storage Storage Accounts is Enabled",
        section="9.2 Azure Blob Storage",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Container-level soft delete must be enabled on blob storage accounts so that "
            "accidentally or maliciously deleted containers and their blobs can be recovered "
            "during the retention window."
        ),
        rationale=(
            "Without container soft delete, an entire container and all its blobs can be "
            "permanently destroyed in a single delete operation. Container soft delete provides "
            "a recovery window even when blob-level soft delete is enabled."
        ),
        impact="Deleted containers continue to consume storage until the retention window elapses.",
        audit_procedure=(
            "ARM: GET each storage account's blobServices/default — "
            "properties.containerDeleteRetentionPolicy.enabled must be true."
        ),
        remediation=(
            "Storage account → Data protection → Enable soft delete for containers → "
            "set retention days >= 7 → Save."
        ),
        default_value="Container soft delete is disabled by default on older accounts.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview",
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
            policy = (svc.get("properties") or {}).get("containerDeleteRetentionPolicy") or {}
            if not policy.get("enabled"):
                offenders.append(name)

        evidence = [Evidence(source="arm:storage/blobServices", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) do not have container soft delete enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(blob_services)} storage account(s) have container soft delete enabled.",
            evidence=evidence,
        )
