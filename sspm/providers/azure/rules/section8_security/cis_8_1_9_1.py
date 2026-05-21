"""CIS Azure 8.1.9.1 – Ensure Microsoft Defender for Resource Manager Is Set To 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_9_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.9.1",
        title="Ensure Microsoft Defender for Resource Manager Is Set To 'On'",
        section="8.1.9 Defender Plan: Resource Manager",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for Resource Manager automatically monitors all resource "
            "management operations in the subscription to detect suspicious activity, "
            "such as operations from malicious IP addresses or use of exploitation toolkits."
        ),
        rationale=(
            "Resource Manager is the control plane for all Azure resources. Compromising it "
            "enables an attacker to deploy backdoors, exfiltrate data, or destroy infrastructure. "
            "Defender provides visibility into this critical plane."
        ),
        impact="Defender for Resource Manager incurs per-subscription monthly pricing.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/Arm — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Resource Manager → "
            "toggle Plan to On → Save."
        ),
        default_value="Defender for Resource Manager is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction",
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
            (p for p in pricings if (p.get("name") or "").lower() == "arm"),
            None,
        )
        if plan is None:
            return self._fail("Defender for Resource Manager plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"Arm": tier})]
        if tier == "standard":
            return self._pass("Defender for Resource Manager plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for Resource Manager plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
