"""CIS Azure 7.10 – Ensure Azure Web Application Firewall (WAF) is Enabled on Azure Application Gateway (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_10(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.10",
        title="Ensure Azure Web Application Firewall (WAF) is Enabled on Azure Application Gateway",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Azure Web Application Firewall (WAF) should be enabled on Application Gateway "
            "to protect web applications from common exploits and vulnerabilities including "
            "OWASP Top 10 threats, SQL injection, and cross-site scripting."
        ),
        rationale=(
            "WAF provides centralized protection for web applications. Without WAF, applications "
            "behind Application Gateway are exposed to Layer 7 attacks that network-layer controls "
            "cannot detect or block."
        ),
        impact="WAF requires WAF SKU for Application Gateway, which has additional cost.",
        audit_procedure=(
            "ARM: GET each Application Gateway — check "
            "properties.webApplicationFirewallConfiguration.enabled == true OR "
            "properties.firewallPolicy is a non-empty object with an id."
        ),
        remediation=(
            "Azure portal → Application gateways → select gateway → Web application firewall → "
            "Enable WAF, or attach a WAF policy → Save."
        ),
        default_value="WAF is not enabled by default on new Application Gateways.",
        references=[
            "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview",
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
            props = gw.get("properties", {})
            waf_config = props.get("webApplicationFirewallConfiguration") or {}
            firewall_policy = props.get("firewallPolicy") or {}
            waf_enabled = waf_config.get("enabled", False)
            policy_attached = bool(firewall_policy.get("id"))
            if not waf_enabled and not policy_attached:
                offenders.append(name)

        evidence = [Evidence(source="arm:applicationGateways", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Application Gateway(s) do not have WAF enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(app_gateways)} Application Gateway(s) have WAF enabled.",
            evidence=evidence,
        )
