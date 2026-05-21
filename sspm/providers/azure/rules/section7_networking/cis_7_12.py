"""CIS Azure 7.12 – Ensure the SSL Policy's 'Min protocol version' is Set to 'TLSv1_2' or Higher on Azure Application Gateway (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_12(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.12",
        title="Ensure the SSL Policy's 'Min protocol version' is Set to 'TLSv1_2' or Higher on Azure Application Gateway",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Application Gateway SSL policies should enforce a minimum TLS protocol version of "
            "TLSv1_2. Older protocol versions (TLS 1.0, 1.1) are deprecated and contain known "
            "cryptographic vulnerabilities."
        ),
        rationale=(
            "TLS 1.0 and 1.1 are susceptible to known attacks (POODLE, BEAST, CRIME) and do "
            "not meet modern cryptographic standards. Enforcing TLS 1.2+ prevents downgrade "
            "attacks and meets PCI DSS, HIPAA, and FedRAMP requirements."
        ),
        impact="Legacy clients that do not support TLS 1.2 will be unable to connect.",
        audit_procedure=(
            "ARM: GET each Application Gateway — "
            "properties.sslPolicy.minProtocolVersion must be 'TLSv1_2' or 'TLSv1_3'."
        ),
        remediation=(
            "Azure portal → Application gateways → select gateway → SSL settings → "
            "SSL policy → Custom → Minimum protocol version: TLS 1.2 → Save."
        ),
        default_value="Application Gateway may default to allowing TLS 1.0+.",
        references=[
            "https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview",
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

        _ACCEPTABLE = {"TLSv1_2", "TLSv1_3"}
        offenders: list[str] = []
        for gw in app_gateways:
            name = gw.get("name", "?")
            ssl_policy = gw.get("properties", {}).get("sslPolicy") or {}
            min_version = ssl_policy.get("minProtocolVersion") or ""
            if min_version not in _ACCEPTABLE:
                offenders.append(f"{name} ({min_version or 'not set'})")

        evidence = [Evidence(source="arm:applicationGateways", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Application Gateway(s) do not enforce TLS 1.2+: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(app_gateways)} Application Gateway(s) enforce TLS 1.2 or higher.",
            evidence=evidence,
        )
