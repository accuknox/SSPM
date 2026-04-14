"""CIS AWS 6.7 – Ensure that EC2 Metadata Service only allows IMDSv2 (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_7(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.7",
        title="Ensure that the EC2 Metadata Service only allows IMDSv2",
        section="6 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "The EC2 Instance Metadata Service (IMDS) provides instance-specific data to "
            "running instances. IMDSv2 uses a session-oriented approach with token-based "
            "authentication, preventing Server-Side Request Forgery (SSRF) attacks that could "
            "exploit IMDSv1 to steal instance credentials."
        ),
        rationale=(
            "IMDSv1 is vulnerable to SSRF attacks: if an application vulnerability allows "
            "an attacker to make requests from the instance to the IMDS endpoint, they can "
            "steal instance credentials. IMDSv2 requires a PUT request to obtain a session "
            "token first, blocking simple SSRF exploitation."
        ),
        impact=(
            "Applications using IMDSv1 must be updated to use the IMDSv2 token-based flow. "
            "Most AWS SDKs support IMDSv2 automatically."
        ),
        audit_procedure=(
            "aws ec2 describe-instances --region <region>\n"
            "For each running instance, check MetadataOptions.HttpTokens == 'required'."
        ),
        remediation=(
            "aws ec2 modify-instance-metadata-options --instance-id <id> "
            "--http-tokens required --http-endpoint enabled"
        ),
        default_value="IMDSv1 is enabled by default (HttpTokens=optional) for older instances.",
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        instances = data.get("ec2_instances")
        if instances is None:
            return self._skip("Could not retrieve EC2 instances.")

        violations = []
        for inst in instances:
            state = inst.get("State", {}).get("Name", "")
            if state != "running":
                continue
            metadata_options = inst.get("MetadataOptions", {})
            http_tokens = metadata_options.get("HttpTokens", "optional")
            if http_tokens != "required":
                instance_id = inst.get("InstanceId", "unknown")
                region = inst.get("Region", "unknown")
                violations.append(f"{instance_id} ({region}, HttpTokens={http_tokens})")

        evidence = [Evidence(
            source="ec2:DescribeInstances",
            data={"imdsv1_instances": violations},
            description="Running EC2 instances not enforcing IMDSv2 (HttpTokens != required).",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} running EC2 instance(s) do not enforce IMDSv2: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "All running EC2 instances enforce IMDSv2 (HttpTokens=required). Compliant.",
            evidence=evidence,
        )
