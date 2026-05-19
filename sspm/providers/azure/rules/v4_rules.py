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

from sspm.core.models import RuleMetadata
from sspm.core.registry import registry

_V4_BENCHMARK = "CIS Microsoft Azure Foundations Benchmark v4.0.0"
_V4_VERSION = "v4.0.0"


def _v4(base_cls: type, rule_id: str, section: str) -> type:
    """Return a new class that re-uses *base_cls*.check() under v4 metadata."""
    bm = base_cls.metadata
    meta = RuleMetadata(
        id=rule_id,
        title=bm.title,
        section=section,
        benchmark=_V4_BENCHMARK,
        benchmark_version=_V4_VERSION,
        assessment_status=bm.assessment_status,
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
    cls = type(cls_name, (base_cls,), {"metadata": meta})
    registry.register(cls())
    return cls


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
_v4(CIS_2_1_2, "azure-cis-v4-3.1.2", "3.1 Azure Databricks")
_v4(CIS_2_1_3, "azure-cis-v4-3.1.3", "3.1 Azure Databricks")
_v4(CIS_2_1_4, "azure-cis-v4-3.1.4", "3.1 Azure Databricks")
_v4(CIS_2_1_5, "azure-cis-v4-3.1.5", "3.1 Azure Databricks")
_v4(CIS_2_1_6, "azure-cis-v4-3.1.6", "3.1 Azure Databricks")
_v4(CIS_2_1_7, "azure-cis-v4-3.1.7", "3.1 Azure Databricks")
_v4(CIS_2_1_8, "azure-cis-v4-3.1.8", "3.1 Azure Databricks")
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

# Security Defaults (v6 5.1 → v4 6.1); note: v4 ordering differs slightly
_v4(CIS_5_1_1, "azure-cis-v4-6.1.1", "6.1 Security Defaults (Per-User MFA)")
_v4(CIS_5_1_3, "azure-cis-v4-6.1.2", "6.1 Security Defaults (Per-User MFA)")
_v4(CIS_5_1_4, "azure-cis-v4-6.1.3", "6.1 Security Defaults (Per-User MFA)")

# Periodic Identity Reviews (v6 5.3.1-5.3.4 → v4 6.3.1-6.3.4)
_v4(CIS_5_3_1, "azure-cis-v4-6.3.1", "6.3 Periodic Identity Reviews")
_v4(CIS_5_3_2, "azure-cis-v4-6.3.2", "6.3 Periodic Identity Reviews")
_v4(CIS_5_3_3, "azure-cis-v4-6.3.3", "6.3 Periodic Identity Reviews")
_v4(CIS_5_3_4, "azure-cis-v4-6.3.4", "6.3 Periodic Identity Reviews")
# 5.3.5-5.3.7 are new in v6 and have no v4 equivalent

# Standalone identity rules
_v4(CIS_5_1_2, "azure-cis-v4-6.22", "6 Identity Services")   # require MFA register/join
_v4(CIS_5_4,   "azure-cis-v4-6.23", "6 Identity Services")   # no custom subscription admin
_v4(CIS_5_5,   "azure-cis-v4-6.24", "6 Identity Services")   # custom role for resource locks
_v4(CIS_5_6,   "azure-cis-v4-6.25", "6 Identity Services")   # subscription leaving tenant
# 5.7 (subscription owners) maps to v4 6.26 (global admin count) — different check; skipped

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
_v4(CIS_6_1_1_1, "azure-cis-v4-7.1.1.1", _DIAG)
_v4(CIS_6_1_1_2, "azure-cis-v4-7.1.1.2", _DIAG)
_v4(CIS_6_1_1_3, "azure-cis-v4-7.1.1.3", _DIAG)
_v4(CIS_6_1_1_4, "azure-cis-v4-7.1.1.4", _DIAG)
_v4(CIS_6_1_1_5, "azure-cis-v4-7.1.1.5", _DIAG)
_v4(CIS_6_1_1_6, "azure-cis-v4-7.1.1.6", _DIAG)
_v4(CIS_6_1_1_7, "azure-cis-v4-7.1.1.7", _DIAG)
_v4(CIS_6_1_1_8, "azure-cis-v4-7.1.1.8", _DIAG)
_v4(CIS_6_1_1_9, "azure-cis-v4-7.1.1.9", _DIAG)
# v4 7.1.1.10 (Intune logs) has no v6 codebase equivalent

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
_v4(CIS_8_1_3_2, "azure-cis-v4-9.1.3.2", _DEF_SERVERS)
_v4(CIS_8_1_3_3, "azure-cis-v4-9.1.3.3", _DEF_SERVERS)
_v4(CIS_8_1_3_4, "azure-cis-v4-9.1.3.4", _DEF_SERVERS)
_v4(CIS_8_1_3_5, "azure-cis-v4-9.1.3.5", _DEF_SERVERS)

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
_v4(CIS_9_3_1_1, "azure-cis-v4-10.3.1.1", _SK)
_v4(CIS_9_3_1_2, "azure-cis-v4-10.3.1.2", _SK)
_v4(CIS_9_3_1_3, "azure-cis-v4-10.3.1.3", _SK)

_SNET = "10.3.2 Networking"
_v4(CIS_9_3_2_1, "azure-cis-v4-10.3.2.1", _SNET)
_v4(CIS_9_3_2_2, "azure-cis-v4-10.3.2.2", _SNET)
_v4(CIS_9_3_2_3, "azure-cis-v4-10.3.2.3", _SNET)

_v4(CIS_9_3_3_1, "azure-cis-v4-10.3.3.1", "10.3.3 Identity and Access Management")

_SA = "10.3 Storage Accounts"
_v4(CIS_9_3_4,  "azure-cis-v4-10.3.4",  _SA)
_v4(CIS_9_3_5,  "azure-cis-v4-10.3.5",  _SA)
_v4(CIS_9_3_6,  "azure-cis-v4-10.3.6",  _SA)
_v4(CIS_9_3_7,  "azure-cis-v4-10.3.7",  _SA)
_v4(CIS_9_3_8,  "azure-cis-v4-10.3.8",  _SA)
_v4(CIS_9_3_9,  "azure-cis-v4-10.3.9",  _SA)
_v4(CIS_9_3_10, "azure-cis-v4-10.3.10", _SA)
_v4(CIS_9_3_11, "azure-cis-v4-10.3.11", _SA)
