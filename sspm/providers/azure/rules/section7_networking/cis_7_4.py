"""CIS Azure 7.4 – Ensure that HTTP(S) Access from the Internet is Evaluated and Restricted (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.azure.rules.section7_networking._helpers import find_offending_nsgs
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.4",
        title="Ensure that HTTP(S) Access from the Internet is Evaluated and Restricted",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Network Security Groups should not allow unrestricted inbound HTTP (TCP/80) or "
            "HTTPS (TCP/443) from the Internet. Web traffic should be routed through a Web "
            "Application Firewall or Application Gateway with appropriate access controls."
        ),
        rationale=(
            "Directly exposing HTTP/HTTPS ports on NSGs to the Internet bypasses WAF protections "
            "and increases exposure to web-based attacks including OWASP Top 10 vulnerabilities."
        ),
        impact="Direct HTTP/HTTPS to VMs will be blocked; route traffic through Application Gateway "
               "or Azure Front Door with WAF enabled.",
        audit_procedure=(
            "List NSG inbound security rules; flag Allow rules whose source is an Internet-equivalent "
            "prefix (``*`` / ``0.0.0.0/0`` / ``Internet``) and port includes 80 or 443."
        ),
        remediation=(
            "Remove or restrict the offending NSG rules; route web traffic through Application "
            "Gateway or Azure Front Door with WAF enabled."
        ),
        default_value="New NSGs do not permit HTTP/HTTPS from the Internet.",
        references=[
            "https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.3", title="Securely Manage Network Infrastructure", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        nsgs = data.get("network_security_groups")
        if nsgs is None:
            return self._skip("Network security groups could not be retrieved.")

        offenders_80 = find_offending_nsgs(nsgs, target_port=80, protocols=("tcp", "*"))
        offenders_443 = find_offending_nsgs(nsgs, target_port=443, protocols=("tcp", "*"))
        # Combine, preserving order, deduplicated
        seen: set[str] = set()
        offenders: list[str] = []
        for name in offenders_80 + offenders_443:
            if name not in seen:
                seen.add(name)
                offenders.append(name)

        evidence = [Evidence(source="arm:networkSecurityGroups", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} NSG(s) expose HTTP/HTTPS (80/443) to the Internet: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass("No NSG exposes HTTP/HTTPS (80/443) to the Internet.", evidence=evidence)
