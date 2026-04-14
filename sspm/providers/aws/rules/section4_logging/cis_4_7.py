"""CIS AWS 4.7 – Ensure VPC flow logging is enabled in all VPCs (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_7(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.7",
        title="Ensure VPC flow logging is enabled in all VPCs",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "VPC Flow Logs is a feature that enables you to capture information about the IP "
            "traffic going to and from network interfaces in your VPC. Flow logs can help you "
            "with network troubleshooting and security analysis."
        ),
        rationale=(
            "VPC flow logs capture network traffic metadata, enabling detection of unusual "
            "traffic patterns, data exfiltration attempts, and unauthorized connections. "
            "Without flow logs, network-level security incidents may go undetected."
        ),
        impact="VPC flow logs incur costs based on data volume sent to CloudWatch Logs or S3.",
        audit_procedure=(
            "aws ec2 describe-vpcs --region <region>\n"
            "aws ec2 describe-flow-logs --region <region>\n"
            "For each VPC, verify at least one ACTIVE flow log exists."
        ),
        remediation=(
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> "
            "--traffic-type ALL --log-destination-type cloud-watch-logs "
            "--log-group-name /aws/vpc/flowlogs --deliver-logs-permission-arn <role-arn>"
        ),
        default_value="VPC flow logging is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vpcs = data.get("ec2_vpcs")
        flow_logs = data.get("ec2_flow_logs")
        if vpcs is None:
            return self._skip("Could not retrieve VPC data.")
        if flow_logs is None:
            return self._skip("Could not retrieve VPC flow logs data.")

        # Build set of VPC IDs that have active flow logs
        covered_vpcs: set[str] = set()
        for fl in flow_logs:
            if fl.get("FlowLogStatus") == "ACTIVE":
                resource_id = fl.get("ResourceId", "")
                covered_vpcs.add(resource_id)

        violations = []
        for vpc in vpcs:
            vpc_id = vpc.get("VpcId", "")
            if vpc_id not in covered_vpcs:
                region = vpc.get("Region", "unknown")
                violations.append(f"{vpc_id} ({region})")

        evidence = [Evidence(
            source="ec2:DescribeFlowLogs / ec2:DescribeVpcs",
            data={"vpcs_without_flow_logs": violations, "total_vpcs": len(vpcs)},
            description="VPCs without active VPC flow logs.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} VPC(s) do not have active flow logging: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vpcs)} VPC(s) have active flow logging enabled. Compliant.",
            evidence=evidence,
        )
