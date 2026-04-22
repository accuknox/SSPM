"""CIS Azure 8.3.11 – Ensure Certificate 'Validity Period (in months)' is Less Than or Equal to '12' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData

_MONTH_SECONDS = 30 * 24 * 3600
_MAX_MONTHS = 12
# Allow 1 month buffer for practical issuance timing
_MAX_SECONDS = (_MAX_MONTHS + 1) * _MONTH_SECONDS


@registry.rule
class CIS_8_3_11(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.11",
        title="Ensure Certificate 'Validity Period (in months)' is Less Than or Equal to '12'",
        section="8.3 Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "TLS/SSL certificates stored in Azure Key Vault should have a validity period of "
            "12 months or less to align with industry best practices and reduce the risk "
            "associated with long-lived certificates."
        ),
        rationale=(
            "Long certificate validity periods increase the window during which a compromised "
            "private key can be exploited without detection. Short-lived certificates force "
            "regular renewal and limit exposure from key compromise."
        ),
        impact="Shorter validity periods require more frequent certificate renewal processes.",
        audit_procedure=(
            "ARM: list certificates for each Key Vault — for every certificate, "
            "(exp - created) / (30 * 24 * 3600) must be <= 13 months (12 + 1 month buffer)."
        ),
        remediation=(
            "Key Vault → Certificates → select each certificate → Advanced policy configuration → "
            "set Validity Period (months) to 12 → Update."
        ),
        default_value="Certificates are issued with 12-month validity by default, but some may differ.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.2", title="Establish an Access Revoking Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        certs_map = data.get("key_vault_certificates")
        if certs_map is None:
            return self._skip("Key vault certificates metadata could not be retrieved.")

        offenders: list[str] = []
        for vault_id, certs in certs_map.items():
            vault_label = vault_id.split("/")[-1] if "/" in vault_id else vault_id
            for cert in certs:
                attrs = cert.get("properties", {}).get("attributes", {})
                if not attrs.get("enabled", True):
                    continue  # Skip disabled certificates
                exp = attrs.get("exp")
                created = attrs.get("created")
                if exp is None or created is None:
                    # Cannot determine validity; flag it
                    offenders.append(f"{vault_label}/{cert.get('name', '?')} (missing timestamps)")
                    continue
                validity_seconds = exp - created
                if validity_seconds > _MAX_SECONDS:
                    validity_months = round(validity_seconds / _MONTH_SECONDS, 1)
                    offenders.append(
                        f"{vault_label}/{cert.get('name', '?')} ({validity_months} months)"
                    )

        evidence = [Evidence(
            source="arm:Microsoft.KeyVault/vaults/certificates",
            data={"certificates_exceeding_12_months": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} certificate(s) have a validity period exceeding 12 months: "
                f"{', '.join(offenders[:5])}.",
                evidence=evidence,
            )
        return self._pass(
            "All Key Vault certificates have a validity period of 12 months or less.",
            evidence=evidence,
        )
