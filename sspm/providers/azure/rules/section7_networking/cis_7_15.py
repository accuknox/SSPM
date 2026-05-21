"""CIS Azure 7.15 – Ensure Bot Protection is Enabled in Azure WAF Policy on Azure Application Gateway (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_15(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.15",
        title="Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Bot protection should be enabled on Application Gateway WAF to detect and block "
            "malicious bots using Microsoft threat intelligence feeds. Bot protection requires "
            "a WAF policy (not just inline WAF configuration) to be attached to the gateway."
        ),
        rationale=(
            "Bots are responsible for credential stuffing, scraping, DDoS, and API abuse. "
            "The legacy inline WAF configuration does not support bot protection rules — only "
            "an attached WAF policy enables the bot manager ruleset."
        ),
        impact="Switching to WAF policy mode may require recreation of existing WAF rules.",
        audit_procedure=(
            "ARM: GET each Application Gateway — check that properties.firewallPolicy is a "
            "non-empty object with an id. Gateways with WAF enabled but no attached firewall "
            "policy cannot leverage bot protection."
        ),
        remediation=(
            "Azure portal → Application gateways → select gateway → Web application firewall → "
            "Associate a WAF policy → enable Bot protection ruleset in the policy."
        ),
        default_value="Bot protection is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/bot-protection",
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
            # Flag gateways where WAF is enabled but no WAF policy is attached (no bot protection possible)
            if waf_enabled and not policy_attached:
                offenders.append(f"{name} (WAF enabled but no WAF policy attached)")

        evidence = [Evidence(source="arm:applicationGateways", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Application Gateway(s) have WAF enabled without an attached "
                f"WAF policy (bot protection not available): {', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(app_gateways)} Application Gateway(s) with WAF have an attached WAF policy "
            f"(bot protection can be configured).",
            evidence=evidence,
        )
