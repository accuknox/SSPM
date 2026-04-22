"""CIS Azure 7.2 – Ensure that SSH Access from the Internet is Evaluated and Restricted (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.azure.rules.section7_networking._helpers import find_offending_nsgs
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.2",
        title="Ensure that SSH Access from the Internet is Evaluated and Restricted",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Network Security Groups should not allow inbound SSH (TCP/22) from the Internet. "
            "Route SSH through Bastion, VPN, or specific allow-listed IP ranges."
        ),
        rationale=(
            "SSH exposed to the Internet is a frequent target for brute-force and credential "
            "stuffing attacks; compromised hosts are used as launch points for deeper intrusion."
        ),
        impact="Direct SSH from the Internet will stop working; use Bastion or VPN.",
        audit_procedure=(
            "List NSG inbound security rules; flag Allow rules whose source is an Internet-equivalent "
            "prefix (``*`` / ``0.0.0.0/0`` / ``Internet``) and port includes 22."
        ),
        remediation="Remove or restrict the offending rule; prefer Bastion / VPN access.",
        default_value="New NSGs do not permit SSH from the Internet.",
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
        offenders = find_offending_nsgs(nsgs, target_port=22)
        evidence = [Evidence(source="arm:networkSecurityGroups", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} NSG(s) expose SSH (22) to the Internet: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass("No NSG exposes SSH (22) to the Internet.", evidence=evidence)
