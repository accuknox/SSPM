"""CIS AWS 6.8 – Ensure VPC Endpoints are used for access to AWS Services (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_8(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.8",
        title="Ensure VPC Endpoints are used for access to AWS Services",
        section="6 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "VPC Endpoints allow EC2 instances to communicate with AWS services without "
            "requiring internet gateway, NAT device, VPN connection, or AWS Direct Connect. "
            "Traffic between a VPC and AWS services does not leave the Amazon network."
        ),
        rationale=(
            "Without VPC Endpoints, traffic from VPC resources to AWS services (S3, DynamoDB, "
            "etc.) travels over the public internet, potentially exposing it to interception. "
            "VPC Endpoints keep traffic private within the AWS network and eliminate the need "
            "for internet gateways or NAT for AWS service access."
        ),
        impact=(
            "Creating VPC Endpoints requires network configuration changes and may require "
            "updating security group and bucket policies."
        ),
        audit_procedure=(
            "aws ec2 describe-vpc-endpoints --region <region>\n"
            "Verify that VPC Endpoints exist for commonly used AWS services (S3, DynamoDB, "
            "KMS, SSM, etc.) and are in the 'available' state."
        ),
        remediation=(
            "Create Gateway endpoints for S3 and DynamoDB:\n"
            "aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --service-name com.amazonaws.<region>.s3 "
            "--route-table-ids <rtb-ids>\n"
            "Create Interface endpoints for other services as needed."
        ),
        default_value="No VPC Endpoints are created by default.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that VPC Endpoints are configured for commonly used AWS services "
            "(S3, DynamoDB, KMS, SSM, etc.). Run: aws ec2 describe-vpc-endpoints --region <region> "
            "and verify endpoints exist for all services accessed from within VPCs. "
            "Confirm endpoints are in 'available' state and properly associated with route tables."
        )
