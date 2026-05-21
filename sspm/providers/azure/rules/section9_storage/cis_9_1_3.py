"""CIS Azure 9.1.3 – Ensure 'SMB channel encryption' is Set to 'AES-256-GCM' or Higher for SMB file shares (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_1_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.1.3",
        title="Ensure 'SMB channel encryption' is Set to 'AES-256-GCM' or Higher for SMB file shares",
        section="9.1 Azure Files",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Files SMB channel encryption settings should include AES-256-GCM to ensure "
            "strong encryption for data in transit. AES-128-CCM and AES-128-GCM provide weaker "
            "protection and should not be the only permitted cipher."
        ),
        rationale=(
            "AES-256-GCM provides stronger encryption with a larger key size compared to "
            "AES-128 variants. Requiring AES-256-GCM ensures that SMB traffic is protected "
            "with the strongest available cipher for Azure Files."
        ),
        impact="Older clients that only support AES-128 channel encryption will be unable to mount shares.",
        audit_procedure=(
            "ARM: GET each storage account's fileServices/default — "
            "properties.protocolSettings.smb.channelEncryption must include 'AES-256-GCM'."
        ),
        remediation=(
            "Azure portal → Storage account → File shares → File share settings → "
            "SMB channel encryption → select AES-256-GCM only → Save."
        ),
        default_value="Azure Files allows all supported cipher suites by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-smb-protocol-version",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.10", title="Encrypt Sensitive Data in Transit", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        file_services = data.get("storage_file_services") or {}
        if not file_services:
            return self._skip("Storage file services could not be retrieved.")

        offenders: list[str] = []
        for acct_id, svc in file_services.items():
            name = acct_id.split("/")[-1]
            smb = (svc.get("properties", {}).get("protocolSettings") or {}).get("smb") or {}
            channel_enc = smb.get("channelEncryption") or ""
            if not channel_enc:
                continue  # No explicit setting; skip
            if "AES-256-GCM" not in channel_enc:
                offenders.append(f"{name} ({channel_enc.strip(';')})")

        evidence = [Evidence(source="arm:storage/fileServices", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) do not include AES-256-GCM in SMB channel encryption: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            "All storage accounts with file services include AES-256-GCM in SMB channel encryption.",
            evidence=evidence,
        )
