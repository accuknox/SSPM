"""CIS Azure 7.7 – Ensure that Public IP Addresses are Evaluated on a Periodic Basis (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.7",
        title="Ensure that Public IP Addresses are Evaluated on a Periodic Basis",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "All public IP addresses in the subscription should be periodically reviewed to "
            "confirm that they are still necessary and associated with legitimate, actively-used "
            "resources."
        ),
        rationale=(
            "Orphaned or forgotten public IP addresses attached to idle or decommissioned "
            "resources expand the attack surface. Regular review ensures only required public "
            "IPs are retained and properly secured."
        ),
        impact="No direct technical impact; purely a governance and review process requirement.",
        audit_procedure=(
            "ARM: list all public IP address resources in the subscription. For each, verify: "
            "it is associated with an active resource (VM, load balancer, VPN gateway, etc.), "
            "the association is documented and approved, and unnecessary public IPs are "
            "deallocated and deleted."
        ),
        remediation=(
            "Azure portal → All resources → filter by type 'Public IP address'. Review each "
            "IP, confirm its business justification, and delete unused addresses. Schedule "
            "periodic (at least quarterly) reviews."
        ),
        default_value="Public IP addresses are not automatically audited or reclaimed.",
        references=[
            "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.3", title="Securely Manage Network Infrastructure", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Evaluating whether public IP addresses are justified and actively used requires "
            "manual review of all public IP address resources in the subscription. Verify each "
            "IP is associated with an active, documented resource and that unused IPs are removed."
        )
