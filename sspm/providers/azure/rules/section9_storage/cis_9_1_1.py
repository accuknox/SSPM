"""CIS Azure 9.1.1 – Ensure that 'Soft Delete' is Enabled for Azure File Shares (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_1_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.1.1",
        title="Ensure that 'Soft Delete' is Enabled for Azure File Shares",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Files soft delete must be enabled so that accidentally or maliciously deleted "
            "file shares can be restored during the retention window."
        ),
        rationale=(
            "Without soft delete a single misplaced delete (or a ransomware actor) can "
            "permanently destroy SMB/NFS share data without an undo path."
        ),
        impact="Retained shares continue to consume storage until the retention window elapses.",
        audit_procedure=(
            "ARM: GET each storage account's fileServices/default — "
            "properties.shareDeleteRetentionPolicy.enabled must be true with days >= 7."
        ),
        remediation=(
            "Storage account → File shares → Soft delete → Enable → retention days >= 7."
        ),
        default_value="File share soft delete is enabled with 7-day retention on new accounts.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-prevent-file-share-deletion",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.1", title="Establish and Maintain a Data Recovery Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        accounts = data.get("storage_accounts")
        file_svc = data.get("storage_file_services") or {}
        if accounts is None:
            return self._skip("Storage accounts could not be retrieved.")
        if not accounts:
            return self._pass("No storage accounts in subscription.")

        offenders: list[str] = []
        for sa in accounts:
            acct_id = sa.get("id", "")
            name = sa.get("name", "?")
            svc = file_svc.get(acct_id)
            if svc is None:
                continue  # no file service — skip (applies only when file shares exist)
            policy = svc.get("properties", {}).get("shareDeleteRetentionPolicy", {}) or {}
            if not policy.get("enabled") or int(policy.get("days", 0)) < 7:
                offenders.append(
                    f"{name} ({'on' if policy.get('enabled') else 'off'}, "
                    f"{policy.get('days', 0)}d)"
                )

        evidence = [Evidence(source="arm:storage/fileServices", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) lack file-share soft delete: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            "All storage accounts with file services have soft delete enabled.",
            evidence=evidence,
        )
