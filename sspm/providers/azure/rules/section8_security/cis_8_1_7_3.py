"""CIS Azure 8.1.7.3 – Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_7_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.7.3",
        title="Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'",
        section="8.1.7 Defender Plan: Databases",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for Azure SQL (SQL Server Virtual Machines) monitors SQL Server "
            "instances running on Azure VMs and Managed Instances for anomalous activity, "
            "potential SQL injections, and unusual access patterns."
        ),
        rationale=(
            "SQL Server on VMs and Managed Instances hosts business-critical data. Defender "
            "provides database-layer visibility that OS or network monitoring cannot capture."
        ),
        impact="Defender for SQL Server Virtual Machines incurs per-server monthly pricing.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/SqlServerVirtualMachines — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Databases → "
            "SQL servers on machines → toggle to On → Save."
        ),
        default_value="Defender for SQL Server Virtual Machines is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.1", title="Centralize Security Event Alerting", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        plan = next(
            (p for p in pricings if (p.get("name") or "").lower() == "sqlservervirtualmachines"),
            None,
        )
        if plan is None:
            return self._fail("Defender for SQL Server Virtual Machines plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"SqlServerVirtualMachines": tier})]
        if tier == "standard":
            return self._pass("Defender for SQL Server Virtual Machines plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for SQL Server Virtual Machines plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
