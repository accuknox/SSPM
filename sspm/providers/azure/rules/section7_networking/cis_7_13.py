"""CIS Azure 7.13 – Ensure 'HTTP2' is Set to 'Enabled' on Azure Application Gateway (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_13(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.13",
        title="Ensure 'HTTP2' is Set to 'Enabled' on Azure Application Gateway",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "HTTP/2 should be enabled on Azure Application Gateway to take advantage of improved "
            "performance, multiplexing, header compression, and stronger TLS requirements "
            "compared to HTTP/1.1."
        ),
        rationale=(
            "HTTP/2 mandates TLS 1.2+ (in practice), supports multiplexed streams that reduce "
            "connection overhead, and eliminates plaintext protocol options. Enabling it enforces "
            "better security defaults for client-to-gateway communication."
        ),
        impact="Clients that do not support HTTP/2 will fall back to HTTP/1.1 transparently.",
        audit_procedure=(
            "ARM: GET each Application Gateway — properties.enableHttp2 must be true."
        ),
        remediation=(
            "Azure portal → Application gateways → select gateway → Configuration → "
            "HTTP2: Enabled → Save."
        ),
        default_value="HTTP2 is disabled by default on Application Gateways.",
        references=[
            "https://learn.microsoft.com/en-us/azure/application-gateway/configuration-infrastructure#http2-support",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.10", title="Encrypt Sensitive Data in Transit", ig1=False, ig2=True, ig3=True),
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
            if not gw.get("properties", {}).get("enableHttp2", False):
                offenders.append(name)

        evidence = [Evidence(source="arm:applicationGateways", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Application Gateway(s) do not have HTTP/2 enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(app_gateways)} Application Gateway(s) have HTTP/2 enabled.",
            evidence=evidence,
        )
