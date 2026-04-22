"""CIS Azure 6.1.1.4 – Ensure that Logging for Azure Key Vault is 'Enabled' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.4",
        title="Ensure that Logging for Azure Key Vault is 'Enabled'",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Every Key Vault must have a diagnostic setting that captures ``AuditEvent`` (or "
            "``allLogs``) so that key, secret, and certificate access is auditable."
        ),
        rationale=(
            "Key Vault logs record every interaction with cryptographic material. Without them, "
            "unauthorized access or mass-exfiltration attempts cannot be detected or investigated."
        ),
        impact="Minor storage cost for log retention.",
        audit_procedure=(
            "For each Key Vault, GET "
            "/providers/Microsoft.Insights/diagnosticSettings — at least one setting must enable "
            "the AuditEvent (or allLogs) log category."
        ),
        remediation=(
            "Key Vault → Monitoring → Diagnostic settings → Add diagnostic setting → tick "
            "``AuditEvent`` (or ``allLogs``) and choose a destination."
        ),
        default_value="No diagnostic settings are configured on new Key Vaults.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/general/logging",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vaults = data.get("key_vaults")
        diag_map = data.get("key_vault_diagnostic_settings", {})
        if vaults is None:
            return self._skip("Key Vaults could not be retrieved.")
        if not vaults:
            return self._pass("No Key Vaults in subscription — nothing to audit.")

        offenders: list[str] = []
        for v in vaults:
            vid = v.get("id", "")
            name = v.get("name", vid)
            settings = diag_map.get(vid, [])
            has_audit = False
            for s in settings:
                for log in s.get("properties", {}).get("logs", []) or []:
                    cat = (log.get("category") or "").lower()
                    grp = (log.get("categoryGroup") or "").lower()
                    if log.get("enabled") and (cat == "auditevent" or grp in ("audit", "alllogs")):
                        has_audit = True
                        break
                if has_audit:
                    break
            if not has_audit:
                offenders.append(name)

        evidence = [Evidence(
            source="arm:diagnosticSettings",
            data={"vaults_without_audit_logging": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} Key Vault(s) lack AuditEvent logging: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vaults)} Key Vault(s) have AuditEvent logging enabled.",
            evidence=evidence,
        )
