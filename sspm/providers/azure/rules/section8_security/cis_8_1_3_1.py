"""CIS Azure 8.1.3.1 – Ensure Microsoft Defender for Servers is Set to 'On' (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_3_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.3.1",
        title="Ensure that Microsoft Defender for Servers is Set to 'On'",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Defender for Servers extends Microsoft Defender for Endpoint to Azure VMs and "
            "Arc-enabled servers, providing EDR, vulnerability assessment, and JIT access."
        ),
        rationale=(
            "VMs run the bulk of sensitive workloads. Without server-side EDR, malware, "
            "crypto-miners, and fileless attacks go undetected."
        ),
        impact="Per-VM hourly charge for the selected sub-plan (P1 or P2).",
        audit_procedure=(
            "ARM: GET /providers/Microsoft.Security/pricings/VirtualMachines — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Servers → Plan On → "
            "select sub-plan → Save."
        ),
        default_value="Defender for Servers is off (Free tier) by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="10.1", title="Deploy and Maintain Anti-Malware Software", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        vm = next(
            (p for p in pricings if (p.get("name") or "").lower() == "virtualmachines"),
            None,
        )
        if vm is None:
            return self._fail("Defender for Servers plan is not configured.")

        tier = (vm.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"VirtualMachines": tier})]
        if tier == "standard":
            return self._pass("Defender for Servers is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for Servers is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
