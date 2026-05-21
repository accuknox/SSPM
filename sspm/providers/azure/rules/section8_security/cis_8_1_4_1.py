"""CIS Azure 8.1.4.1 – Ensure Microsoft Defender for Containers Is Set To 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_4_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.4.1",
        title="Ensure Microsoft Defender for Containers Is Set To 'On'",
        section="8.1.4 Defender Plan: Containers",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for Containers provides runtime threat protection, vulnerability "
            "assessment for container images, and security hardening recommendations for AKS "
            "clusters and container registries."
        ),
        rationale=(
            "Container workloads are high-value targets for cryptomining and lateral movement. "
            "Without Defender for Containers, threats in running pods go undetected and "
            "vulnerable images reach production unchecked."
        ),
        impact="Defender for Containers incurs per-vCore pricing for AKS nodes.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/Containers — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Containers → "
            "toggle Plan to On → Save."
        ),
        default_value="Defender for Containers is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="7.1", title="Establish and Maintain a Vulnerability Management Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        plan = next(
            (p for p in pricings if (p.get("name") or "").lower() == "containers"),
            None,
        )
        if plan is None:
            return self._fail("Defender for Containers plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"Containers": tier})]
        if tier == "standard":
            return self._pass("Defender for Containers plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for Containers plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
