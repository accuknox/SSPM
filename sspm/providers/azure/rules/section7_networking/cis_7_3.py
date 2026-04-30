"""CIS Azure 7.3 – Ensure that UDP Port Access from the Internet is Evaluated and Restricted (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.3",
        title="Ensure that UDP Port Access from the Internet is Evaluated and Restricted",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Network Security Groups should not allow inbound UDP traffic from the Internet "
            "(source ``*``, ``0.0.0.0/0``, or ``Internet``) on any port. UDP is stateless and "
            "susceptible to amplification attacks and port scanning."
        ),
        rationale=(
            "UDP services exposed to the Internet can be exploited for denial-of-service "
            "amplification attacks (DNS, NTP, SSDP) and reconnaissance. Restricting UDP ingress "
            "limits the attack surface significantly."
        ),
        impact="UDP-based services (DNS, NTP, TFTP, game servers) must be accessed through VPN or "
               "restricted to known source IPs.",
        audit_procedure=(
            "List all NSG inbound security rules. A rule is non-compliant if: access=Allow, "
            "direction=Inbound, protocol in (UDP, *), and source is *, 0.0.0.0/0, Internet, or Any."
        ),
        remediation=(
            "Delete or narrow the offending inbound security rule to restrict source to specific "
            "known IP ranges rather than any Internet source."
        ),
        default_value="New NSGs do not permit UDP from the Internet.",
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

        offenders = []
        for nsg in nsgs:
            name = nsg.get("name") or nsg.get("id", "unknown")
            for rule in nsg.get("properties", {}).get("securityRules", []) or []:
                p = rule.get("properties", rule)
                if (p.get("access", "").lower() != "allow" or p.get("direction", "").lower() != "inbound"):
                    continue
                proto = p.get("protocol", "").lower()
                if proto not in ("udp", "*"):
                    continue
                sources = []
                sources += ([p.get("sourceAddressPrefix")] if p.get("sourceAddressPrefix") else [])
                sources += (p.get("sourceAddressPrefixes") or [])
                if any((s or "").lower() in {"*", "0.0.0.0/0", "internet", "any"} for s in sources):
                    offenders.append(name)
                    break

        evidence = [Evidence(source="arm:networkSecurityGroups", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} NSG(s) expose UDP to the Internet: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass("No NSG exposes UDP to the Internet.", evidence=evidence)
