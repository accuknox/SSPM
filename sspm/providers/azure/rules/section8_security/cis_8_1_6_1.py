"""CIS Azure 8.1.6.1 – Ensure Microsoft Defender for App Services Is Set To 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_6_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.6.1",
        title="Ensure Microsoft Defender for App Services Is Set To 'On'",
        section="8.1.6 Defender Plan: App Service",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for App Service monitors Azure App Service environments for "
            "indicators of compromise, web shell attacks, command injection, and other "
            "application-layer threats."
        ),
        rationale=(
            "App Service hosts public-facing web applications that are frequent targets for "
            "exploitation. Defender for App Service leverages Microsoft's cloud scale to "
            "identify attack patterns that perimeter controls miss."
        ),
        impact="Defender for App Service incurs per-vCore hourly pricing.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/AppServices — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → App Service → "
            "toggle Plan to On → Save."
        ),
        default_value="Defender for App Service is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction",
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
            (p for p in pricings if (p.get("name") or "").lower() == "appservices"),
            None,
        )
        if plan is None:
            return self._fail("Defender for App Service plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"AppServices": tier})]
        if tier == "standard":
            return self._pass("Defender for App Service plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for App Service plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
