"""CIS Azure 7.1 – Ensure that RDP Access from the Internet is Evaluated and Restricted (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.azure.rules.section7_networking._helpers import find_offending_nsgs
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.1",
        title="Ensure that RDP Access from the Internet is Evaluated and Restricted",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Network Security Groups should not allow inbound RDP (TCP/3389) from the Internet "
            "(source ``*``, ``0.0.0.0/0``, or ``Internet``). Restrict RDP to VPN, Bastion, or "
            "specific allow-listed IP ranges."
        ),
        rationale=(
            "Exposing RDP to the Internet invites brute-force and credential-stuffing attacks. "
            "Compromised VMs often become footholds for lateral movement."
        ),
        impact="Direct RDP from the Internet will stop working; use Bastion or VPN instead.",
        audit_procedure=(
            "List all NSG inbound security rules. A rule is non-compliant if: access=Allow, "
            "direction=Inbound, protocol in (TCP, *), destination port includes 3389, and "
            "source is *, 0.0.0.0/0, Internet, or Any."
        ),
        remediation="Delete or narrow the offending inbound security rule, or route RDP via Bastion.",
        default_value="New NSGs do not permit RDP from the Internet.",
        references=[
            "https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.4", title="Perform Traffic Filtering Between Network Segments", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        nsgs = data.get("network_security_groups")
        if nsgs is None:
            return self._skip("Network security groups could not be retrieved.")
        offenders = find_offending_nsgs(nsgs, target_port=3389)
        evidence = [Evidence(source="arm:networkSecurityGroups", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} NSG(s) expose RDP (3389) to the Internet: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass("No NSG exposes RDP (3389) to the Internet.", evidence=evidence)
