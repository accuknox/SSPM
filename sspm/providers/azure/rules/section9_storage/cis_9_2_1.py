"""CIS Azure 9.2.1 – Ensure Soft Delete for Blobs is Enabled on Storage Accounts (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_2_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.2.1",
        title="Ensure Soft Delete for Blobs is Enabled on Storage Accounts",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Blob soft delete must be enabled so that overwritten or deleted blobs can be "
            "recovered during the retention window."
        ),
        rationale=(
            "Soft delete preserves the previous version of blobs after deletion or overwrite, "
            "preventing permanent data loss from mistakes or malicious action."
        ),
        impact="Retained versions consume storage for the retention period.",
        audit_procedure=(
            "ARM: GET each storage account's blobServices/default — "
            "properties.deleteRetentionPolicy.enabled must be true with days >= 7."
        ),
        remediation=(
            "Storage account → Data protection → Enable soft delete for blobs → retention days >= 7."
        ),
        default_value="Enabled on newer accounts with 7-day retention.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.1", title="Establish and Maintain a Data Recovery Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        accounts = data.get("storage_accounts")
        blob_svc = data.get("storage_blob_services") or {}
        if accounts is None:
            return self._skip("Storage accounts could not be retrieved.")
        if not accounts:
            return self._pass("No storage accounts in subscription.")

        offenders: list[str] = []
        for sa in accounts:
            acct_id = sa.get("id", "")
            name = sa.get("name", "?")
            svc = blob_svc.get(acct_id)
            if svc is None:
                offenders.append(f"{name} (blob service properties unavailable)")
                continue
            policy = svc.get("properties", {}).get("deleteRetentionPolicy", {}) or {}
            if not policy.get("enabled") or int(policy.get("days", 0)) < 7:
                offenders.append(
                    f"{name} ({'on' if policy.get('enabled') else 'off'}, "
                    f"{policy.get('days', 0)}d)"
                )

        evidence = [Evidence(source="arm:storage/blobServices", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) lack blob soft delete: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) have blob soft delete enabled.",
            evidence=evidence,
        )
