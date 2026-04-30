"""CIS AWS 6.6 – Ensure routing tables for VPC peering are 'least access' (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_6(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.6",
        title="Ensure routing tables for VPC peering are 'least access'",
        section="6 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "VPC peering routing tables should use specific CIDRs for the peered VPC rather "
            "than allowing all traffic (0.0.0.0/0 or ::/0). This ensures that only intended "
            "traffic flows through VPC peering connections."
        ),
        rationale=(
            "Route tables with overly broad CIDRs for peering connections may allow "
            "unintended traffic between VPCs, potentially exposing sensitive resources. "
            "Using specific CIDRs enforces least-access principles for inter-VPC communication."
        ),
        impact=(
            "Restricting routing table CIDRs may require updating routes for each subnet "
            "that uses VPC peering."
        ),
        audit_procedure=(
            "1. List VPC peering connections:\n"
            "aws ec2 describe-vpc-peering-connections\n"
            "2. For each peering connection, review routing tables:\n"
            "aws ec2 describe-route-tables\n"
            "3. Verify routes use specific CIDRs (not 0.0.0.0/0) for peering connections."
        ),
        remediation=(
            "1. Identify the specific CIDR ranges needed for each VPC peering connection.\n"
            "2. Update routing table entries to use specific CIDRs:\n"
            "aws ec2 create-route --route-table-id <rtb-id> "
            "--destination-cidr-block <specific-cidr> --vpc-peering-connection-id <pcx-id>\n"
            "3. Delete the overly broad route."
        ),
        default_value="Route tables do not have peering routes by default.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.4", title="Perform Traffic Filtering Between Network Segments", ig1=False, ig2=True, ig3=True),
            CISControl(version="v7", control_id="9.2", title="Ensure Only Approved Ports, Protocols and Services Are Running", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
