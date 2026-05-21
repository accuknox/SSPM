"""
CIS Microsoft Azure Foundations Benchmark v4.0.0 rule registrations.

Each v4 rule is a thin subclass of the corresponding v6.0.0 legacy class,
inheriting its check() implementation while carrying updated metadata
(id, section, benchmark) that match v4.0.0 section numbering.

Section mapping (v6.0.0 → v4.0.0):
  2 Analytics        → 3 Analytics Services
  3 Compute          → 4 Compute Services
  5 Identity         → 6 Identity Services
  6 Management       → 7 Management and Governance Services
  7 Networking       → 8 Networking Services
  8 Security         → 9 Security Services
  9 Storage          → 10 Storage Services

Rules present in v6.0.0 but absent from v4.0.0 are skipped:
  Analytics 2.1.9-2.1.12, Identity 5.3.5-5.3.7 / 5.7,
  Security 8.1.5.2 / 8.3.11 / 8.5, Storage 9.2.2.
"""

from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule

_V4_BENCHMARK = "CIS Microsoft Azure Foundations Benchmark v4.0.0"
_V4_VERSION = "v4.0.0"

_MANUAL = AssessmentStatus.MANUAL
_AUTO = AssessmentStatus.AUTOMATED


def _v4(
    base_cls: type,
    rule_id: str,
    section: str,
    assessment_status: AssessmentStatus | None = None,
) -> type:
    """Return a new class that re-uses *base_cls*.check() under v4 metadata.

    Pass *assessment_status* to override the inherited assessment status.
    When upgrading an AUTOMATED rule to MANUAL the check() is also replaced
    so it returns _manual() instead of running the automated logic.
    """
    bm = base_cls.metadata
    effective_status = assessment_status if assessment_status is not None else bm.assessment_status
    meta = RuleMetadata(
        id=rule_id,
        title=bm.title,
        section=section,
        benchmark=_V4_BENCHMARK,
        benchmark_version=_V4_VERSION,
        assessment_status=effective_status,
        profiles=list(bm.profiles),
        severity=bm.severity,
        description=bm.description,
        rationale=bm.rationale,
        impact=bm.impact,
        audit_procedure=bm.audit_procedure,
        remediation=bm.remediation,
        default_value=bm.default_value,
        references=list(bm.references),
        cis_controls=list(bm.cis_controls),
    )
    cls_name = rule_id.replace("-", "_").replace(".", "_")
    overrides: dict = {"metadata": meta}
    if effective_status == _MANUAL and bm.assessment_status != _MANUAL:
        async def _manual_check(self, data):  # noqa: E306
            return self._manual()
        overrides["check"] = _manual_check
    cls = type(cls_name, (base_cls,), overrides)
    registry.register(cls())
    return cls


def _v4_stub(
    rule_id: str,
    title: str,
    section: str,
    assessment_status: AssessmentStatus,
    severity: Severity = Severity.MEDIUM,
    profiles: list | None = None,
    description: str = "",
    audit_procedure: str = "",
    remediation: str = "",
) -> None:
    """Register a v4-only rule that has no v6/legacy counterpart."""
    _is_manual = assessment_status == _MANUAL
    meta = RuleMetadata(
        id=rule_id,
        title=title,
        section=section,
        benchmark=_V4_BENCHMARK,
        benchmark_version=_V4_VERSION,
        assessment_status=assessment_status,
        profiles=profiles or [CISProfile.AZURE_L1],
        severity=severity,
        description=description or title,
        rationale="",
        impact="",
        audit_procedure=audit_procedure or "See CIS Microsoft Azure Foundations Benchmark v4.0.0.",
        remediation=remediation or "See CIS Microsoft Azure Foundations Benchmark v4.0.0.",
    )

    async def _check(self, data):  # noqa: E306
        if _is_manual:
            return self._manual()
        return self._skip("Automated check not yet implemented for this control.")

    cls_name = rule_id.replace("-", "_").replace(".", "_")
    cls = type(cls_name, (AzureRule,), {"metadata": meta, "check": _check})
    registry.register(cls())


# ---------------------------------------------------------------------------
# 2 Common Reference Recommendations  (v4-only — no v6 counterpart)
# ---------------------------------------------------------------------------
# 2.1 Secrets and Keys
_v4_stub(
    "azure-cis-v4-2.1.1.1.1",
    "Ensure Critical Data is Encrypted with Microsoft Managed Keys (MMK)",
    "2.1.1.1 Microsoft Managed Keys",
    _MANUAL,
    severity=Severity.MEDIUM,
)
_v4_stub(
    "azure-cis-v4-2.1.1.2.1",
    "Ensure Critical Data is Encrypted with Customer Managed Keys (CMK)",
    "2.1.1.2 Customer Managed Keys",
    _MANUAL,
    severity=Severity.MEDIUM,
    profiles=[CISProfile.AZURE_L2],
)

# 2.2 Networking — cross-service reference checks; evaluated per-service in sections 3–10
_v4_stub(
    "azure-cis-v4-2.2.1.1",
    "Ensure public network access is Disabled",
    "2.2.1 Virtual Networks (VNets)",
    _AUTO,
    severity=Severity.HIGH,
    description=(
        "Common reference: public network access should be disabled for all Azure services "
        "that support it. Specific per-service checks are in sections 3–10."
    ),
)
_v4_stub(
    "azure-cis-v4-2.2.1.2",
    "Ensure Network Access Rules are set to Deny-by-default",
    "2.2.1 Virtual Networks (VNets)",
    _AUTO,
    severity=Severity.HIGH,
    description=(
        "Common reference: network access rules should default to Deny for all Azure services "
        "that support it. Specific per-service checks are in sections 3–10."
    ),
)
_v4_stub(
    "azure-cis-v4-2.2.2.1",
    "Ensure Private Endpoints are used to access Azure Services",
    "2.2.2 Private Endpoints",
    _AUTO,
    severity=Severity.HIGH,
    description=(
        "Common reference: private endpoints should be used to access Azure services where "
        "supported. Specific per-service checks are in sections 3–10."
    ),
)

# ---------------------------------------------------------------------------
# 3 Analytics Services  (v6: 2)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section2_analytics.cis_2_1_1 import CIS_2_1_1  # noqa: E402
from sspm.providers.azure.rules.section2_analytics.cis_2_1_2 import CIS_2_1_2
from sspm.providers.azure.rules.section2_analytics.cis_2_1_3 import CIS_2_1_3
from sspm.providers.azure.rules.section2_analytics.cis_2_1_4 import CIS_2_1_4
from sspm.providers.azure.rules.section2_analytics.cis_2_1_5 import CIS_2_1_5
from sspm.providers.azure.rules.section2_analytics.cis_2_1_6 import CIS_2_1_6
from sspm.providers.azure.rules.section2_analytics.cis_2_1_7 import CIS_2_1_7
from sspm.providers.azure.rules.section2_analytics.cis_2_1_8 import CIS_2_1_8

_v4(CIS_2_1_1, "azure-cis-v4-3.1.1", "3.1 Azure Databricks")
_v4(CIS_2_1_2, "azure-cis-v4-3.1.2", "3.1 Azure Databricks", _MANUAL)  # Manual in v4
_v4(CIS_2_1_3, "azure-cis-v4-3.1.3", "3.1 Azure Databricks", _MANUAL)  # Manual in v4
_v4(CIS_2_1_4, "azure-cis-v4-3.1.4", "3.1 Azure Databricks", _MANUAL)  # Manual in v4
_v4(CIS_2_1_5, "azure-cis-v4-3.1.5", "3.1 Azure Databricks", _MANUAL)  # Manual in v4
_v4(CIS_2_1_6, "azure-cis-v4-3.1.6", "3.1 Azure Databricks", _MANUAL)  # Manual in v4
_v4(CIS_2_1_7, "azure-cis-v4-3.1.7", "3.1 Azure Databricks", _MANUAL)  # Manual in v4
def _register_3_1_8() -> None:
    """3.1.8 is Automated + L2 in v4 (base class is Manual + L1 in v6)."""
    bm = CIS_2_1_8.metadata
    meta = RuleMetadata(
        id="azure-cis-v4-3.1.8",
        title="Ensure that data at rest and in transit is encrypted in Azure Databricks using customer managed keys (CMK)",
        section="3.1 Azure Databricks",
        benchmark=_V4_BENCHMARK,
        benchmark_version=_V4_VERSION,
        assessment_status=_AUTO,
        profiles=[CISProfile.AZURE_L2],
        severity=bm.severity,
        description=(
            "Azure Databricks encrypts data in transit using TLS 1.2+. By default, data at rest "
            "is encrypted using Microsoft-managed keys. Organizations with stricter needs should "
            "enable customer-managed keys (CMK) for managed disks and managed services via "
            "Azure Key Vault."
        ),
        rationale=bm.rationale,
        impact=(
            "Enabling CMK encryption requires additional configuration. Key management introduces "
            "maintenance overhead (rotation, revocation, lifecycle management). Potential access "
            "issues will be encountered if keys are deleted or rotated incorrectly."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace verify "
            "properties.encryption.entities.managedDisk.keySource == 'Microsoft.Keyvault' and "
            "properties.encryption.entities.managedServices.keySource == 'Microsoft.Keyvault'."
        ),
        remediation=(
            "az databricks workspace update --name <name> --resource-group <rg> "
            "--key-source 'Microsoft.KeyVault' --key-name <key-name> --keyvault-uri <uri>. "
            "Also configure managed services CMK via the workspace Encryption settings."
        ),
        default_value=bm.default_value,
        references=list(bm.references),
        cis_controls=[
            CISControl(version="v8", control_id="3.11", title="Encrypt Sensitive Data at Rest", ig1=False, ig2=True, ig3=True),
            CISControl(version="v8", control_id="3.10", title="Encrypt Sensitive Data in Transit", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def _check(self, data):
        workspaces = data.get("databricks_workspaces")
        if workspaces is None:
            return self._skip("Databricks workspaces could not be retrieved.")
        if not workspaces:
            return self._skip("No Databricks workspaces in subscription.")
        offenders: list[str] = []
        for ws in workspaces:
            name = ws.get("name", ws.get("id", "unknown"))
            entities = (ws.get("properties") or {}).get("encryption", {}).get("entities", {})
            disk_src = ((entities.get("managedDisk") or {}).get("keySource") or "").lower()
            svc_src = ((entities.get("managedServices") or {}).get("keySource") or "").lower()
            if disk_src != "microsoft.keyvault" or svc_src != "microsoft.keyvault":
                offenders.append(name)
        evidence = [Evidence(
            source="arm:Microsoft.Databricks/workspaces",
            data={"total": len(workspaces), "without_cmk": len(offenders), "offenders": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} Databricks workspace(s) lack CMK encryption on managed disks "
                f"and/or managed services: {', '.join(offenders)}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(workspaces)} Databricks workspace(s) have CMK encryption enabled.",
            evidence=evidence,
        )

    cls = type("azure_cis_v4_3_1_8", (CIS_2_1_8,), {"metadata": meta, "check": _check})
    registry.register(cls())


_register_3_1_8()
# 2.1.9–2.1.12 were added in v6 and have no v4 equivalent

# ---------------------------------------------------------------------------
# 4 Compute Services  (v6: 3)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section3_compute.cis_3_1_1 import CIS_3_1_1  # noqa: E402

_v4(CIS_3_1_1, "azure-cis-v4-4.1.1", "4.1 Virtual Machines")

# ---------------------------------------------------------------------------
# 6 Identity Services  (v6: 5)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section5_identity.cis_5_1_1 import CIS_5_1_1  # noqa: E402
from sspm.providers.azure.rules.section5_identity.cis_5_1_2 import CIS_5_1_2
from sspm.providers.azure.rules.section5_identity.cis_5_1_3 import CIS_5_1_3
from sspm.providers.azure.rules.section5_identity.cis_5_1_4 import CIS_5_1_4
from sspm.providers.azure.rules.section5_identity.cis_5_3_1 import CIS_5_3_1
from sspm.providers.azure.rules.section5_identity.cis_5_3_2 import CIS_5_3_2
from sspm.providers.azure.rules.section5_identity.cis_5_3_3 import CIS_5_3_3
from sspm.providers.azure.rules.section5_identity.cis_5_3_4 import CIS_5_3_4
from sspm.providers.azure.rules.section5_identity.cis_5_4 import CIS_5_4
from sspm.providers.azure.rules.section5_identity.cis_5_5 import CIS_5_5
from sspm.providers.azure.rules.section5_identity.cis_5_6 import CIS_5_6

# Security Defaults (v6 5.1 → v4 6.1); all three are Manual in v4
_v4(CIS_5_1_1, "azure-cis-v4-6.1.1", "6.1 Security Defaults (Per-User MFA)", _MANUAL)
_v4(CIS_5_1_3, "azure-cis-v4-6.1.2", "6.1 Security Defaults (Per-User MFA)", _MANUAL)
_v4(CIS_5_1_4, "azure-cis-v4-6.1.3", "6.1 Security Defaults (Per-User MFA)", _MANUAL)

# 6.2 Conditional Access — new in v4, all Manual
_SEC_CA = "6.2 Conditional Access"
_v4_stub("azure-cis-v4-6.2.1", "Ensure that 'trusted locations' are defined", _SEC_CA, _MANUAL)
_v4_stub("azure-cis-v4-6.2.2", "Ensure that an exclusionary geographic Conditional Access policy is considered", _SEC_CA, _MANUAL)
_v4_stub("azure-cis-v4-6.2.3", "Ensure that an exclusionary device code flow policy is considered", _SEC_CA, _MANUAL)
_v4_stub("azure-cis-v4-6.2.4", "Ensure that a multifactor authentication policy exists for all users", _SEC_CA, _MANUAL)
_v4_stub("azure-cis-v4-6.2.5", "Ensure that multifactor authentication is required for risky sign-ins", _SEC_CA, _MANUAL)
_v4_stub("azure-cis-v4-6.2.6", "Ensure that multifactor authentication is required for Windows Azure Service Management API", _SEC_CA, _MANUAL)
_v4_stub("azure-cis-v4-6.2.7", "Ensure that multifactor authentication is required to access Microsoft Admin Portals", _SEC_CA, _MANUAL)

# Periodic Identity Reviews (v6 5.3.1-5.3.4 → v4 6.3.1-6.3.4)
_v4(CIS_5_3_1, "azure-cis-v4-6.3.1", "6.3 Periodic Identity Reviews", _MANUAL)
_v4(CIS_5_3_2, "azure-cis-v4-6.3.2", "6.3 Periodic Identity Reviews", _MANUAL)
_v4(CIS_5_3_3, "azure-cis-v4-6.3.3", "6.3 Periodic Identity Reviews")
_v4(CIS_5_3_4, "azure-cis-v4-6.3.4", "6.3 Periodic Identity Reviews", _MANUAL)
# 5.3.5-5.3.7 are new in v6 and have no v4 equivalent

# 6.4 – 6.21: additional identity checks in v4 (new or not yet in v6 codebase)
_SEC_ID = "6 Identity Services"
_v4_stub("azure-cis-v4-6.4",  "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'", _SEC_ID, _AUTO, severity=Severity.MEDIUM)
_v4_stub("azure-cis-v4-6.5",  "Ensure that 'Number of methods required to reset' is set to '2'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.6",  "Ensure that account 'Lockout threshold' is less than or equal to '10'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.7",  "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.8",  "Ensure that a 'Custom banned password list' is set to 'Enforce'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.9",  "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.10", "Ensure that 'Notify users on password resets?' is set to 'Yes'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.11", "Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.12", "Ensure that 'User consent for applications' is set to 'Do not allow user consent'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.13", "Ensure that 'User consent for applications' is set to 'Allow user consent for apps from verified publishers, for selected permissions'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.14", "Ensure that 'Users can register applications' is set to 'No'", _SEC_ID, _AUTO, severity=Severity.MEDIUM)
_v4_stub("azure-cis-v4-6.15", "Ensure that 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'", _SEC_ID, _AUTO, severity=Severity.MEDIUM)
_v4_stub("azure-cis-v4-6.16", "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users'", _SEC_ID, _AUTO, severity=Severity.MEDIUM)
_v4_stub("azure-cis-v4-6.17", "Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.18", "Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.19", "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.20", "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'", _SEC_ID, _MANUAL)
_v4_stub("azure-cis-v4-6.21", "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'", _SEC_ID, _MANUAL)

# Standalone identity rules
_v4(CIS_5_1_2, "azure-cis-v4-6.22", _SEC_ID)   # require MFA register/join
_v4(CIS_5_4,   "azure-cis-v4-6.23", _SEC_ID)   # no custom subscription admin
_v4(CIS_5_5,   "azure-cis-v4-6.24", _SEC_ID)   # custom role for resource locks
_v4(CIS_5_6,   "azure-cis-v4-6.25", _SEC_ID)   # subscription leaving tenant
# 6.26: fewer than 5 global admins — v4 new check
_v4_stub("azure-cis-v4-6.26", "Ensure fewer than 5 users have global administrator assignment", _SEC_ID, _MANUAL, severity=Severity.HIGH)

# ---------------------------------------------------------------------------
# 7 Management and Governance Services  (v6: 6)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_1 import CIS_6_1_1_1  # noqa: E402
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_2 import CIS_6_1_1_2
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_3 import CIS_6_1_1_3
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_4 import CIS_6_1_1_4
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_5 import CIS_6_1_1_5
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_6 import CIS_6_1_1_6
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_7 import CIS_6_1_1_7
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_8 import CIS_6_1_1_8
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_9 import CIS_6_1_1_9
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_1 import CIS_6_1_2_1
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_2 import CIS_6_1_2_2
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_3 import CIS_6_1_2_3
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_4 import CIS_6_1_2_4
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_5 import CIS_6_1_2_5
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_6 import CIS_6_1_2_6
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_7 import CIS_6_1_2_7
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_8 import CIS_6_1_2_8
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_9 import CIS_6_1_2_9
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_10 import CIS_6_1_2_10
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_11 import CIS_6_1_2_11
from sspm.providers.azure.rules.section6_logging.cis_6_1_3_1 import CIS_6_1_3_1
from sspm.providers.azure.rules.section6_logging.cis_6_1_4 import CIS_6_1_4
from sspm.providers.azure.rules.section6_logging.cis_6_1_5 import CIS_6_1_5
from sspm.providers.azure.rules.section6_logging.cis_6_2 import CIS_6_2

_DIAG = "7.1.1 Configuring Diagnostic Settings"
_v4(CIS_6_1_1_1, "azure-cis-v4-7.1.1.1", _DIAG, _MANUAL)  # Manual in v4
_v4(CIS_6_1_1_2, "azure-cis-v4-7.1.1.2", _DIAG)
def _register_7_1_1_3() -> None:
    """7.1.1.3 is Automated + L2 in v4 (base class is Manual + L1 in v6)."""
    bm = CIS_6_1_1_3.metadata
    meta = RuleMetadata(
        id="azure-cis-v4-7.1.1.3",
        title="Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)",
        section=_DIAG,
        benchmark=_V4_BENCHMARK,
        benchmark_version=_V4_VERSION,
        assessment_status=_AUTO,
        profiles=[CISProfile.AZURE_L2],
        severity=bm.severity,
        description=(
            "Storage accounts with activity log exports can be configured to use Customer "
            "Managed Keys (CMK). Configuring CMK provides additional confidentiality controls "
            "on log data."
        ),
        rationale=bm.rationale,
        impact=bm.impact,
        audit_procedure=(
            "1. GET /subscriptions/<id>/providers/Microsoft.Insights/diagnosticSettings — "
            "collect all storageAccountId values. "
            "2. For each storage account check properties.encryption.keySource == "
            "'Microsoft.Keyvault' and keyVaultProperties is not null."
        ),
        remediation=(
            "az storage account update --name <name> --resource-group <rg> "
            "--encryption-key-source Microsoft.Keyvault "
            "--encryption-key-vault <Key Vault URI> "
            "--encryption-key-name <KeyName> --encryption-key-version <Key Version>."
        ),
        default_value="By default, keySource is set to Microsoft.Storage.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview",
            "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=cli#managing-legacy-log-profiles",
        ],
        cis_controls=list(bm.cis_controls),
    )

    async def _check(self, data):
        settings = data.get("activity_log_diagnostic_settings")
        if settings is None:
            return self._skip("Activity log diagnostic settings could not be retrieved.")
        storage_ids: set[str] = set()
        for s in settings:
            sa_id = ((s.get("properties") or {}).get("storageAccountId") or "")
            if sa_id:
                storage_ids.add(sa_id.lower())
        if not storage_ids:
            return self._skip(
                "No storage account destinations found in activity log diagnostic settings."
            )
        accounts = data.get("storage_accounts") or []
        sa_map = {sa.get("id", "").lower(): sa for sa in accounts}
        offenders: list[str] = []
        skipped: list[str] = []
        for sa_id in storage_ids:
            sa = sa_map.get(sa_id)
            if sa is None:
                skipped.append(sa_id)
                continue
            enc = (sa.get("properties") or {}).get("encryption") or {}
            key_source = (enc.get("keySource") or "").lower()
            kv_props = enc.get("keyVaultProperties") or {}
            if key_source != "microsoft.keyvault" or not kv_props:
                offenders.append(sa.get("name", sa_id))
        evidence = [Evidence(
            source="arm:storageAccounts+diagnosticSettings",
            data={
                "activity_log_storage_accounts": len(storage_ids),
                "without_cmk": offenders,
                "not_found_in_inventory": skipped,
            },
        )]
        if skipped and not offenders:
            return self._skip(
                f"Could not retrieve details for {len(skipped)} storage account(s) used by "
                "activity log diagnostic settings — manual verification required."
            )
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) used for activity log archival are not "
                f"encrypted with CMK: {', '.join(offenders)}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(storage_ids)} storage account(s) used for activity log archival are "
            "encrypted with a Customer Managed Key.",
            evidence=evidence,
        )

    cls = type("azure_cis_v4_7_1_1_3", (CIS_6_1_1_3,), {"metadata": meta, "check": _check})
    registry.register(cls())


_register_7_1_1_3()
_v4(CIS_6_1_1_4, "azure-cis-v4-7.1.1.4", _DIAG)
_v4(CIS_6_1_1_5, "azure-cis-v4-7.1.1.5", _DIAG)
# 7.1.1.6: AppService HTTP logs (Automated) — v6 has no direct equivalent at this position
_v4_stub(
    "azure-cis-v4-7.1.1.6",
    "Ensure that logging for Azure AppService 'HTTP logs' is enabled",
    _DIAG,
    _AUTO,
    severity=Severity.MEDIUM,
)
# v6 6.1.1.6 (VNet Flow Logs) → v4 7.1.1.7; v6 6.1.1.7-9 shift +1 accordingly
_v4(CIS_6_1_1_6, "azure-cis-v4-7.1.1.7",  _DIAG)   # VNet flow logs
_v4(CIS_6_1_1_7, "azure-cis-v4-7.1.1.8",  _DIAG)   # Entra Graph activity logs
_v4(CIS_6_1_1_8, "azure-cis-v4-7.1.1.9",  _DIAG)   # Entra activity logs
_v4(CIS_6_1_1_9, "azure-cis-v4-7.1.1.10", _DIAG)   # Intune logs

_ACTLOG = "7.1.2 Monitoring Using Activity Log Alerts"
_v4(CIS_6_1_2_1,  "azure-cis-v4-7.1.2.1",  _ACTLOG)
_v4(CIS_6_1_2_2,  "azure-cis-v4-7.1.2.2",  _ACTLOG)
_v4(CIS_6_1_2_3,  "azure-cis-v4-7.1.2.3",  _ACTLOG)
_v4(CIS_6_1_2_4,  "azure-cis-v4-7.1.2.4",  _ACTLOG)
_v4(CIS_6_1_2_5,  "azure-cis-v4-7.1.2.5",  _ACTLOG)
_v4(CIS_6_1_2_6,  "azure-cis-v4-7.1.2.6",  _ACTLOG)
_v4(CIS_6_1_2_7,  "azure-cis-v4-7.1.2.7",  _ACTLOG)
_v4(CIS_6_1_2_8,  "azure-cis-v4-7.1.2.8",  _ACTLOG)
_v4(CIS_6_1_2_9,  "azure-cis-v4-7.1.2.9",  _ACTLOG)
_v4(CIS_6_1_2_10, "azure-cis-v4-7.1.2.10", _ACTLOG)
_v4(CIS_6_1_2_11, "azure-cis-v4-7.1.2.11", _ACTLOG)

_v4(CIS_6_1_3_1, "azure-cis-v4-7.1.3.1", "7.1.3 Configuring Application Insights")
_v4(CIS_6_1_4,   "azure-cis-v4-7.1.4",   "7.1 Logging and Monitoring")
_v4(CIS_6_1_5,   "azure-cis-v4-7.1.5",   "7.1 Logging and Monitoring")
_v4(CIS_6_2,     "azure-cis-v4-7.2",     "7 Management and Governance Services")

# ---------------------------------------------------------------------------
# 8 Networking Services  (v6: 7)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section7_networking.cis_7_1 import CIS_7_1  # noqa: E402
from sspm.providers.azure.rules.section7_networking.cis_7_2 import CIS_7_2
from sspm.providers.azure.rules.section7_networking.cis_7_3 import CIS_7_3
from sspm.providers.azure.rules.section7_networking.cis_7_4 import CIS_7_4
from sspm.providers.azure.rules.section7_networking.cis_7_5 import CIS_7_5
from sspm.providers.azure.rules.section7_networking.cis_7_6 import CIS_7_6
from sspm.providers.azure.rules.section7_networking.cis_7_7 import CIS_7_7
from sspm.providers.azure.rules.section7_networking.cis_7_8 import CIS_7_8

_NET = "8 Networking Services"
_v4(CIS_7_1, "azure-cis-v4-8.1", _NET)
_v4(CIS_7_2, "azure-cis-v4-8.2", _NET)
_v4(CIS_7_3, "azure-cis-v4-8.3", _NET)
_v4(CIS_7_4, "azure-cis-v4-8.4", _NET)
_v4(CIS_7_5, "azure-cis-v4-8.5", _NET)
_v4(CIS_7_6, "azure-cis-v4-8.6", _NET)
_v4(CIS_7_7, "azure-cis-v4-8.7", _NET)
_v4(CIS_7_8, "azure-cis-v4-8.8", _NET)
# 7.9-7.16 (WAF, subnets, SSL, HTTP2, WAF body, bot protection, VNet NSP, auth type)
# were added in v6 and have no v4 equivalent

# ---------------------------------------------------------------------------
# 9 Security Services  (v6: 8)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section8_security.cis_8_1_1_1 import CIS_8_1_1_1  # noqa: E402
from sspm.providers.azure.rules.section8_security.cis_8_1_2_1 import CIS_8_1_2_1
from sspm.providers.azure.rules.section8_security.cis_8_1_3_1 import CIS_8_1_3_1
from sspm.providers.azure.rules.section8_security.cis_8_1_3_2 import CIS_8_1_3_2
from sspm.providers.azure.rules.section8_security.cis_8_1_3_3 import CIS_8_1_3_3
from sspm.providers.azure.rules.section8_security.cis_8_1_3_4 import CIS_8_1_3_4
from sspm.providers.azure.rules.section8_security.cis_8_1_3_5 import CIS_8_1_3_5
from sspm.providers.azure.rules.section8_security.cis_8_1_4_1 import CIS_8_1_4_1
from sspm.providers.azure.rules.section8_security.cis_8_1_5_1 import CIS_8_1_5_1
from sspm.providers.azure.rules.section8_security.cis_8_1_6_1 import CIS_8_1_6_1
from sspm.providers.azure.rules.section8_security.cis_8_1_7_1 import CIS_8_1_7_1
from sspm.providers.azure.rules.section8_security.cis_8_1_7_2 import CIS_8_1_7_2
from sspm.providers.azure.rules.section8_security.cis_8_1_7_3 import CIS_8_1_7_3
from sspm.providers.azure.rules.section8_security.cis_8_1_7_4 import CIS_8_1_7_4
from sspm.providers.azure.rules.section8_security.cis_8_1_8_1 import CIS_8_1_8_1
from sspm.providers.azure.rules.section8_security.cis_8_1_9_1 import CIS_8_1_9_1
from sspm.providers.azure.rules.section8_security.cis_8_1_10 import CIS_8_1_10
from sspm.providers.azure.rules.section8_security.cis_8_1_11 import CIS_8_1_11
from sspm.providers.azure.rules.section8_security.cis_8_1_12 import CIS_8_1_12
from sspm.providers.azure.rules.section8_security.cis_8_1_13 import CIS_8_1_13
from sspm.providers.azure.rules.section8_security.cis_8_1_14 import CIS_8_1_14
from sspm.providers.azure.rules.section8_security.cis_8_1_15 import CIS_8_1_15
from sspm.providers.azure.rules.section8_security.cis_8_1_16 import CIS_8_1_16
from sspm.providers.azure.rules.section8_security.cis_8_2_1 import CIS_8_2_1
from sspm.providers.azure.rules.section8_security.cis_8_3_1 import CIS_8_3_1
from sspm.providers.azure.rules.section8_security.cis_8_3_2 import CIS_8_3_2
from sspm.providers.azure.rules.section8_security.cis_8_3_3 import CIS_8_3_3
from sspm.providers.azure.rules.section8_security.cis_8_3_4 import CIS_8_3_4
from sspm.providers.azure.rules.section8_security.cis_8_3_5 import CIS_8_3_5
from sspm.providers.azure.rules.section8_security.cis_8_3_6 import CIS_8_3_6
from sspm.providers.azure.rules.section8_security.cis_8_3_7 import CIS_8_3_7
from sspm.providers.azure.rules.section8_security.cis_8_3_8 import CIS_8_3_8
from sspm.providers.azure.rules.section8_security.cis_8_3_9 import CIS_8_3_9
from sspm.providers.azure.rules.section8_security.cis_8_3_10 import CIS_8_3_10
from sspm.providers.azure.rules.section8_security.cis_8_4_1 import CIS_8_4_1
# 8.1.5.2 (ATP Alerts monitored), 8.3.11 (certificate validity), 8.5 (DDoS)
# are new in v6 and have no v4 equivalent

_v4(CIS_8_1_1_1, "azure-cis-v4-9.1.1.1", "9.1.1 Microsoft Cloud Security Posture Management (CSPM)")
_v4(CIS_8_1_2_1, "azure-cis-v4-9.1.2.1", "9.1.2 Defender Plan: APIs")

_DEF_SERVERS = "9.1.3 Defender Plan: Servers"
_v4(CIS_8_1_3_1, "azure-cis-v4-9.1.3.1", _DEF_SERVERS)
_v4(CIS_8_1_3_2, "azure-cis-v4-9.1.3.2", _DEF_SERVERS, _MANUAL)  # Manual in v4
_v4(CIS_8_1_3_3, "azure-cis-v4-9.1.3.3", _DEF_SERVERS, _MANUAL)  # Manual in v4
_v4(CIS_8_1_3_4, "azure-cis-v4-9.1.3.4", _DEF_SERVERS, _MANUAL)  # Manual in v4
_v4(CIS_8_1_3_5, "azure-cis-v4-9.1.3.5", _DEF_SERVERS, _MANUAL)  # Manual in v4

_v4(CIS_8_1_4_1, "azure-cis-v4-9.1.4.1", "9.1.4 Defender Plan: Containers")
_v4(CIS_8_1_5_1, "azure-cis-v4-9.1.5.1", "9.1.5 Defender Plan: Storage")
_v4(CIS_8_1_6_1, "azure-cis-v4-9.1.6.1", "9.1.6 Defender Plan: App Service")

_DEF_DB = "9.1.7 Defender Plan: Databases"
_v4(CIS_8_1_7_1, "azure-cis-v4-9.1.7.1", _DEF_DB)
_v4(CIS_8_1_7_2, "azure-cis-v4-9.1.7.2", _DEF_DB)
_v4(CIS_8_1_7_3, "azure-cis-v4-9.1.7.3", _DEF_DB)
_v4(CIS_8_1_7_4, "azure-cis-v4-9.1.7.4", _DEF_DB)

_v4(CIS_8_1_8_1, "azure-cis-v4-9.1.8.1", "9.1.8 Defender Plan: Key Vault")
_v4(CIS_8_1_9_1, "azure-cis-v4-9.1.9.1", "9.1.9 Defender Plan: Resource Manager")

_MDC = "9.1 Microsoft Defender for Cloud"
_v4(CIS_8_1_10, "azure-cis-v4-9.1.10", _MDC)
_v4(CIS_8_1_11, "azure-cis-v4-9.1.11", _MDC)
_v4(CIS_8_1_12, "azure-cis-v4-9.1.12", _MDC)
_v4(CIS_8_1_13, "azure-cis-v4-9.1.13", _MDC)
_v4(CIS_8_1_14, "azure-cis-v4-9.1.14", _MDC)
_v4(CIS_8_1_15, "azure-cis-v4-9.1.15", _MDC)
_v4(CIS_8_1_16, "azure-cis-v4-9.1.16", _MDC)

_v4(CIS_8_2_1, "azure-cis-v4-9.2.1", "9.2 Microsoft Defender for IoT")

_KV = "9.3 Key Vault"
_v4(CIS_8_3_1,  "azure-cis-v4-9.3.1",  _KV)
_v4(CIS_8_3_2,  "azure-cis-v4-9.3.2",  _KV)
_v4(CIS_8_3_3,  "azure-cis-v4-9.3.3",  _KV)
_v4(CIS_8_3_4,  "azure-cis-v4-9.3.4",  _KV)
_v4(CIS_8_3_5,  "azure-cis-v4-9.3.5",  _KV)
_v4(CIS_8_3_6,  "azure-cis-v4-9.3.6",  _KV)
_v4(CIS_8_3_7,  "azure-cis-v4-9.3.7",  _KV)
_v4(CIS_8_3_8,  "azure-cis-v4-9.3.8",  _KV)
_v4(CIS_8_3_9,  "azure-cis-v4-9.3.9",  _KV)
_v4(CIS_8_3_10, "azure-cis-v4-9.3.10", _KV)

_v4(CIS_8_4_1, "azure-cis-v4-9.4.1", "9.4 Azure Bastion")

# ---------------------------------------------------------------------------
# 10 Storage Services  (v6: 9)
# ---------------------------------------------------------------------------
from sspm.providers.azure.rules.section9_storage.cis_9_1_1 import CIS_9_1_1  # noqa: E402
from sspm.providers.azure.rules.section9_storage.cis_9_1_2 import CIS_9_1_2
from sspm.providers.azure.rules.section9_storage.cis_9_1_3 import CIS_9_1_3
from sspm.providers.azure.rules.section9_storage.cis_9_2_1 import CIS_9_2_1
from sspm.providers.azure.rules.section9_storage.cis_9_2_3 import CIS_9_2_3
from sspm.providers.azure.rules.section9_storage.cis_9_3_1_1 import CIS_9_3_1_1
from sspm.providers.azure.rules.section9_storage.cis_9_3_1_2 import CIS_9_3_1_2
from sspm.providers.azure.rules.section9_storage.cis_9_3_1_3 import CIS_9_3_1_3
from sspm.providers.azure.rules.section9_storage.cis_9_3_2_1 import CIS_9_3_2_1
from sspm.providers.azure.rules.section9_storage.cis_9_3_2_2 import CIS_9_3_2_2
from sspm.providers.azure.rules.section9_storage.cis_9_3_2_3 import CIS_9_3_2_3
from sspm.providers.azure.rules.section9_storage.cis_9_3_3_1 import CIS_9_3_3_1
from sspm.providers.azure.rules.section9_storage.cis_9_3_4 import CIS_9_3_4
from sspm.providers.azure.rules.section9_storage.cis_9_3_5 import CIS_9_3_5
from sspm.providers.azure.rules.section9_storage.cis_9_3_6 import CIS_9_3_6
from sspm.providers.azure.rules.section9_storage.cis_9_3_7 import CIS_9_3_7
from sspm.providers.azure.rules.section9_storage.cis_9_3_8 import CIS_9_3_8
from sspm.providers.azure.rules.section9_storage.cis_9_3_9 import CIS_9_3_9
from sspm.providers.azure.rules.section9_storage.cis_9_3_10 import CIS_9_3_10
from sspm.providers.azure.rules.section9_storage.cis_9_3_11 import CIS_9_3_11

_v4(CIS_9_1_1, "azure-cis-v4-10.1.1", "10.1 Azure Files")
_v4(CIS_9_1_2, "azure-cis-v4-10.1.2", "10.1 Azure Files")
_v4(CIS_9_1_3, "azure-cis-v4-10.1.3", "10.1 Azure Files")

_v4(CIS_9_2_1, "azure-cis-v4-10.2.1", "10.2 Azure Blob Storage")
# 9.2.2 (soft delete for containers) was added in v6; not in v4
_v4(CIS_9_2_3, "azure-cis-v4-10.2.2", "10.2 Azure Blob Storage")   # versioning

_SK = "10.3.1 Secrets and Keys"
_v4(CIS_9_3_1_1, "azure-cis-v4-10.3.1.1", _SK, _MANUAL)  # Manual in v4
_v4(CIS_9_3_1_2, "azure-cis-v4-10.3.1.2", _SK, _MANUAL)  # Manual in v4
_v4(CIS_9_3_1_3, "azure-cis-v4-10.3.1.3", _SK)

_SNET = "10.3.2 Networking"
_v4(CIS_9_3_2_1, "azure-cis-v4-10.3.2.1", _SNET)
_v4(CIS_9_3_2_2, "azure-cis-v4-10.3.2.2", _SNET)
_v4(CIS_9_3_2_3, "azure-cis-v4-10.3.2.3", _SNET)

_v4(CIS_9_3_3_1, "azure-cis-v4-10.3.3.1", "10.3.3 Identity and Access Management")

_SA = "10.3 Storage Accounts"
_v4(CIS_9_3_4,  "azure-cis-v4-10.3.4",  _SA)
_v4(CIS_9_3_5,  "azure-cis-v4-10.3.5",  _SA)
# 10.3.6: Soft Delete for Containers and Blob Storage — use blob soft-delete rule as proxy
_v4(CIS_9_2_1,  "azure-cis-v4-10.3.6",  _SA)
_v4(CIS_9_3_6,  "azure-cis-v4-10.3.7",  _SA)   # Min TLS
_v4(CIS_9_3_7,  "azure-cis-v4-10.3.8",  _SA)   # Cross Tenant Replication
_v4(CIS_9_3_8,  "azure-cis-v4-10.3.9",  _SA)   # Allow Blob Anonymous Access (Automated)
_v4(CIS_9_3_9,  "azure-cis-v4-10.3.10", _SA)   # Delete Locks (Manual)
_v4(CIS_9_3_10, "azure-cis-v4-10.3.11", _SA)   # ReadOnly Locks (Manual)
_v4(CIS_9_3_11, "azure-cis-v4-10.3.12", _SA)   # GRS Redundancy
