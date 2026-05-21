"""CIS Azure 8.1.2.1 – Ensure Microsoft Defender for APIs is Set to 'On' (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_2_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.2.1",
        title="Ensure Microsoft Defender for APIs is Set to 'On'",
        section="8.1.2 Defender Plan: APIs",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Defender for APIs provides discovery, threat detection, and security "
            "posture management for APIs published through Azure API Management."
        ),
        rationale=(
            "APIs are a common attack vector for data exfiltration and account takeover. "
            "Defender for APIs surfaces suspicious usage patterns and misconfigurations that "
            "would otherwise go undetected."
        ),
        impact="Defender for APIs incurs per-API-call pricing.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/Apis — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Defender for APIs → "
            "toggle Plan to On."
        ),
        default_value="Defender for APIs is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-apis-introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.10", title="Perform Application Layer Filtering", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        plan = next(
            (p for p in pricings if (p.get("name") or "").lower() == "apis"),
            None,
        )
        if plan is None:
            return self._fail("Defender for APIs plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"Apis": tier})]
        if tier == "standard":
            return self._pass("Defender for APIs plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for APIs plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
