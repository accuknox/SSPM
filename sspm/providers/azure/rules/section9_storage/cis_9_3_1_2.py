"""CIS Azure 9.3.1.2 – Ensure That Storage Account Access Keys are Periodically Regenerated (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_1_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.1.2",
        title="Ensure That Storage Account Access keys are Periodically Regenerated",
        section="9.3.1 Secrets and Keys",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Storage account access keys should be periodically regenerated. Configuring a "
            "key expiration policy (``keyExpirationPeriodInDays``) ensures keys are rotated "
            "on a scheduled basis, reducing the window of exposure for any compromised key."
        ),
        rationale=(
            "Storage access keys grant unrestricted access to all data in a storage account. "
            "Keys that are never rotated remain valid indefinitely even after a breach. "
            "Periodic regeneration limits the blast radius of a leaked credential."
        ),
        impact="Applications using storage account keys must be updated when keys are regenerated; "
               "use managed identities or SAS tokens to minimize this operational burden.",
        audit_procedure=(
            "ARM: GET each storage account — "
            "properties.keyPolicy.keyExpirationPeriodInDays must be non-null and > 0."
        ),
        remediation=(
            "az storage account update --name <name> --key-exp-days 90 "
            "(or via portal: Storage account → Access keys → set rotation reminder → "
            "rotate keys on schedule)."
        ),
        default_value="No key expiration policy is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.2", title="Establish an Access Revoking Process", ig1=True, ig2=True, ig3=True),
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
            key_policy = (sa.get("properties") or {}).get("keyPolicy") or {}
            expiry_days = key_policy.get("keyExpirationPeriodInDays")
            if not expiry_days or int(expiry_days) <= 0:
                offenders.append(name)

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) do not have a key expiration/regeneration policy: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) have a key expiration policy configured.",
            evidence=evidence,
        )
