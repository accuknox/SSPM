"""CIS AWS 2.16 – Ensure IAM instance roles are used for AWS resource access from instances (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_16(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.16",
        title="Ensure IAM instance roles are used for AWS resource access from instances",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "AWS access from within AWS instances can be done by either encoding AWS keys into "
            "AWS API calls or by assigning an instance role with the necessary permissions. "
            "Running EC2 instances should have IAM instance profiles rather than embedded "
            "credentials to avoid credential exposure."
        ),
        rationale=(
            "IAM instance roles provide temporary credentials that are rotated automatically "
            "and are scoped to the instance. Embedding long-lived credentials in instances "
            "creates a risk of credential exposure through instance metadata APIs or application "
            "vulnerabilities."
        ),
        impact=(
            "Applications relying on embedded credentials must be updated to use the "
            "EC2 instance metadata service to retrieve temporary credentials."
        ),
        audit_procedure=(
            "aws ec2 describe-instances\n"
            "For each running instance, check that IamInstanceProfile is set."
        ),
        remediation=(
            "1. Create an IAM role with appropriate least-privilege permissions.\n"
            "2. Attach the role as an instance profile to the EC2 instance:\n"
            "aws ec2 associate-iam-instance-profile --instance-id <id> "
            "--iam-instance-profile Name=<profile-name>\n"
            "3. Remove any embedded AWS credentials from the instance."
        ),
        default_value="EC2 instances are launched without instance profiles by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
            CISControl(version="v7", control_id="14.1", title="Segment the Network Based on Sensitivity", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        instances = data.get("ec2_instances")
        if instances is None:
            return self._skip("Could not retrieve EC2 instances.")

        violations = []
        for inst in instances:
            state = inst.get("State", {}).get("Name", "")
            if state not in ("running", "stopped"):
                continue
            if not inst.get("IamInstanceProfile"):
                instance_id = inst.get("InstanceId", "unknown")
                region = inst.get("Region", "unknown")
                violations.append(f"{instance_id} ({region}, {state})")

        evidence = [Evidence(
            source="ec2:DescribeInstances",
            data={"instances_without_iam_profile": violations},
            description="Running/stopped EC2 instances without an IAM instance profile.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} EC2 instance(s) have no IAM instance profile: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "All running/stopped EC2 instances have IAM instance profiles. Compliant.",
            evidence=evidence,
        )
