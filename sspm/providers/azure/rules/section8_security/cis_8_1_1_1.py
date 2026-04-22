"""CIS Azure 8.1.1.1 – Ensure Microsoft Defender for Cloud CSPM Plan is Set to 'On' (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_1_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.1.1",
        title="Ensure that Microsoft Defender for Cloud CSPM Plan is Set to 'On'",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "The Defender Cloud Security Posture Management (CSPM) plan provides agentless "
            "scanning, attack path analysis, and risk prioritisation across Azure resources."
        ),
        rationale=(
            "CSPM surfaces misconfigurations and toxic combinations that simple rule-based "
            "checks miss. Without it, privilege paths and data exposure risks remain invisible."
        ),
        impact="Defender CSPM Standard incurs per-resource pricing.",
        audit_procedure=(
            "ARM: GET /providers/Microsoft.Security/pricings/CloudPosture — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Defender CSPM → "
            "toggle Plan to On."
        ),
        default_value="Defender CSPM is enabled in the Free tier by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="1.1", title="Establish and Maintain Detailed Enterprise Asset Inventory", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        cspm = next(
            (p for p in pricings if (p.get("name") or "").lower() == "cloudposture"),
            None,
        )
        if cspm is None:
            return self._fail("Defender CSPM plan is not configured on this subscription.")

        tier = (cspm.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"CloudPosture": tier})]
        if tier == "standard":
            return self._pass("Defender CSPM plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender CSPM plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
