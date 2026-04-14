"""CIS AWS 4.5 – Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_5(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.5",
        title="Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "AWS CloudTrail is a web service that records AWS API calls for an account and "
            "makes those logs available to users and resources. Configuring CloudTrail to use "
            "SSE-KMS with a customer-managed key provides additional confidentiality controls "
            "over the log data."
        ),
        rationale=(
            "Encrypting CloudTrail logs with KMS customer-managed keys ensures that even users "
            "with S3 access cannot read the log files without KMS permissions. This provides "
            "an additional access control layer for sensitive audit data."
        ),
        impact=(
            "Users reading CloudTrail logs must have permissions on both S3 and the KMS key. "
            "Key management overhead increases."
        ),
        audit_procedure=(
            "aws cloudtrail describe-trails\n"
            "For each trail, check that KMSKeyId is set."
        ),
        remediation=(
            "1. Create or identify a KMS CMK for CloudTrail encryption.\n"
            "2. Update the trail:\n"
            "aws cloudtrail update-trail --name <trail-name> --kms-key-id <key-id>"
        ),
        default_value="CloudTrail logs are encrypted with SSE-S3 by default, not customer-managed keys.",
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        trails = data.get("cloudtrail_trails")
        if trails is None:
            return self._skip("Could not retrieve CloudTrail trails.")

        if not trails:
            return self._fail("No CloudTrail trails found.")

        violations = [
            trail.get("Name", trail.get("TrailARN", "unknown"))
            for trail in trails
            if not trail.get("KMSKeyId")
        ]

        evidence = [Evidence(
            source="cloudtrail:DescribeTrails",
            data={"trails_without_kms": violations, "total": len(trails)},
            description="CloudTrail trails without KMS encryption.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} CloudTrail trail(s) are not encrypted with KMS CMKs: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(trails)} CloudTrail trail(s) are encrypted with KMS CMKs. Compliant.",
            evidence=evidence,
        )
