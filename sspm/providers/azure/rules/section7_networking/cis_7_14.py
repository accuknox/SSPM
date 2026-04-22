"""CIS Azure 7.14 – Ensure Request Body Inspection is Enabled in Azure WAF policy on Azure Application Gateway (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_14(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.14",
        title="Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "WAF request body inspection should be enabled on Application Gateway WAF "
            "configurations to ensure that HTTP request bodies are inspected for malicious "
            "payloads such as SQL injection and XSS attacks embedded in POST data."
        ),
        rationale=(
            "Without request body inspection, WAF rules only inspect request headers and URIs. "
            "Many injection attacks are delivered in the request body (POST/PUT), which would "
            "pass through uninspected and potentially compromise backend applications."
        ),
        impact="Request body inspection adds minor processing overhead; very large request bodies "
               "may need size limit tuning.",
        audit_procedure=(
            "ARM: GET each Application Gateway — check "
            "properties.webApplicationFirewallConfiguration.requestBodyCheck == true OR "
            "properties.webApplicationFirewallConfiguration.requestBodyEnforcement == true."
        ),
        remediation=(
            "Azure portal → Application gateways → select gateway → Web application firewall → "
            "Advanced rule → Request body inspection: Enabled → Save."
        ),
        default_value="Request body inspection is enabled by default on WAF v2 SKUs.",
        references=[
            "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.10", title="Perform Application Layer Filtering", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        app_gateways = data.get("application_gateways")
        if app_gateways is None:
            return self._skip("Application gateways could not be retrieved.")
        if not app_gateways:
            return self._skip("No Application Gateways found in subscription.")

        offenders: list[str] = []
        for gw in app_gateways:
            name = gw.get("name", "?")
            waf_config = gw.get("properties", {}).get("webApplicationFirewallConfiguration") or {}
            request_body_check = waf_config.get("requestBodyCheck", False)
            request_body_enforcement = waf_config.get("requestBodyEnforcement", False)
            # Only evaluate gateways that have WAF config present
            if waf_config and not request_body_check and not request_body_enforcement:
                offenders.append(name)

        evidence = [Evidence(source="arm:applicationGateways", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Application Gateway(s) do not have WAF request body inspection enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(app_gateways)} Application Gateway(s) have WAF request body inspection enabled.",
            evidence=evidence,
        )
