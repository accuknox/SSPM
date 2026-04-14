"""CIS AWS 3.1.1 – Ensure S3 Bucket Policy is set to deny HTTP requests (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


def _bucket_policy_denies_http(policy: dict) -> bool:
    """Return True if the bucket policy has a Deny on aws:SecureTransport=false."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Deny":
            continue
        condition = stmt.get("Condition", {})
        # Check for aws:SecureTransport = false (denying HTTP)
        bool_conditions = condition.get("Bool", {})
        if str(bool_conditions.get("aws:SecureTransport", "")).lower() == "false":
            return True
    return False


@registry.rule
class CIS_3_1_1(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.1.1",
        title="Ensure S3 Bucket Policy is set to deny HTTP requests",
        section="3.1 Storage – S3",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "At the Amazon S3 bucket level, you can configure permissions through a bucket "
            "policy making the objects accessible only through HTTPS. Bucket policies should "
            "explicitly deny HTTP requests."
        ),
        rationale=(
            "Without HTTPS enforcement, data in transit is susceptible to interception. "
            "A bucket policy that denies non-HTTPS requests ensures all communication is "
            "encrypted in transit."
        ),
        impact=(
            "Applications or scripts using HTTP (not HTTPS) to access S3 will receive "
            "access denied errors."
        ),
        audit_procedure=(
            "aws s3api get-bucket-policy --bucket <bucket-name>\n"
            "Check for a Deny statement with Condition: {Bool: {aws:SecureTransport: false}}."
        ),
        remediation=(
            "Add a bucket policy statement:\n"
            '{"Effect": "Deny", "Principal": "*", "Action": "s3:*", '
            '"Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"], '
            '"Condition": {"Bool": {"aws:SecureTransport": "false"}}}'
        ),
        default_value="S3 bucket policies do not enforce HTTPS by default.",
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        # Try all_bucket_policies first, fall back to cloudtrail bucket policies
        bucket_policies = data.get("s3_all_bucket_policies") or data.get("s3_bucket_policies")
        if bucket_policies is None:
            return self._skip("Could not retrieve S3 bucket policies.")

        violations = []
        compliant = []
        for bucket_name, policy in bucket_policies.items():
            if policy is None:
                violations.append(f"{bucket_name} (no policy)")
                continue
            if _bucket_policy_denies_http(policy):
                compliant.append(bucket_name)
            else:
                violations.append(f"{bucket_name} (policy does not deny HTTP)")

        evidence = [Evidence(
            source="s3:GetBucketPolicy",
            data={"violations": violations, "compliant": len(compliant)},
            description="S3 buckets without HTTP-deny bucket policies.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} S3 bucket(s) do not enforce HTTPS: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(compliant)} S3 bucket(s) have policies denying HTTP requests. Compliant.",
            evidence=evidence,
        )
