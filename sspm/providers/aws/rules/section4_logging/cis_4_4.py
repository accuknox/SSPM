"""CIS AWS 4.4 – Ensure that server access logging is enabled on the CloudTrail S3 bucket (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_4(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.4",
        title="Ensure that server access logging is enabled on the CloudTrail S3 bucket",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "S3 server access logging captures detailed records of requests made to a bucket. "
            "Enabling access logging on the CloudTrail S3 bucket provides a secondary audit "
            "trail of who accessed the CloudTrail logs themselves."
        ),
        rationale=(
            "Server access logs for the CloudTrail bucket help detect unauthorized access "
            "attempts to audit logs. If an attacker tries to view or exfiltrate CloudTrail "
            "logs, server access logging would capture this activity."
        ),
        impact="Server access logging creates additional S3 objects, incurring storage costs.",
        audit_procedure=(
            "For each CloudTrail S3 bucket:\n"
            "aws s3api get-bucket-logging --bucket <bucket-name>\n"
            "Check that LoggingEnabled is set."
        ),
        remediation=(
            "aws s3api put-bucket-logging --bucket <cloudtrail-bucket> "
            "--bucket-logging-status '{\"LoggingEnabled\": {\"TargetBucket\": \"<log-bucket>\", "
            "\"TargetPrefix\": \"cloudtrail-logs/\"}}'"
        ),
        default_value="S3 server access logging is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that server access logging is enabled on the S3 bucket used by CloudTrail. "
            "Run: aws s3api get-bucket-logging --bucket <cloudtrail-bucket-name> and confirm "
            "that LoggingEnabled is present. If not set, enable it by configuring a target "
            "bucket and prefix for the server access logs."
        )
