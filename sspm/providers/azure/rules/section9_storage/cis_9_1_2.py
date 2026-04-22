"""CIS Azure 9.1.2 – Ensure 'SMB protocol version' is Set to 'SMB 3.1.1' or Higher for SMB file shares (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_1_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.1.2",
        title="Ensure 'SMB protocol version' is Set to 'SMB 3.1.1' or Higher for SMB file shares",
        section="9.1 Azure Files",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Files SMB protocol settings should restrict connections to SMB 3.1.1 or "
            "higher. Older versions (SMB 2.1, SMB 3.0) lack critical security features including "
            "pre-authentication integrity and encryption."
        ),
        rationale=(
            "SMB 2.1 and SMB 3.0 lack pre-authentication integrity checks, making them "
            "vulnerable to man-in-the-middle attacks. SMB 3.1.1 introduced mandatory "
            "pre-authentication integrity that prevents protocol downgrade attacks."
        ),
        impact="Legacy clients that do not support SMB 3.1.1 will be unable to mount file shares.",
        audit_procedure=(
            "ARM: GET each storage account's fileServices/default — "
            "properties.protocolSettings.smb.versions must not include 'SMB2.1' or 'SMB3.0'."
        ),
        remediation=(
            "az storage account file-service-properties update --account-name <name> "
            "--version SMB3.1.1 (or via portal: Storage account → File shares → "
            "File share settings → SMB protocol version)."
        ),
        default_value="Azure Files defaults to allowing all SMB versions for broad compatibility.",
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

        _WEAK_VERSIONS = {"SMB2.1", "SMB3.0"}
        offenders: list[str] = []
        for acct_id, svc in file_services.items():
            name = acct_id.split("/")[-1]
            smb = (svc.get("properties", {}).get("protocolSettings") or {}).get("smb") or {}
            versions_str = smb.get("versions") or ""
            if not versions_str:
                continue  # No explicit version restriction; Azure default is >=3.1.1
            # Parse semicolon-separated version list
            versions = {v.strip() for v in versions_str.split(";") if v.strip()}
            if versions & _WEAK_VERSIONS:
                offenders.append(f"{name} ({versions_str.strip(';')})")

        evidence = [Evidence(source="arm:storage/fileServices", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) allow weak SMB versions: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            "All storage accounts with file services restrict to SMB 3.1.1 or higher.",
            evidence=evidence,
        )
