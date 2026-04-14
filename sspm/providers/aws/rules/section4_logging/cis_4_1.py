"""CIS AWS 4.1 – Ensure CloudTrail is enabled in all regions (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_1(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.1",
        title="Ensure CloudTrail is enabled in all regions",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "AWS CloudTrail is a web service that records AWS API calls for your account and "
            "delivers log files to you. Enabling CloudTrail in all regions ensures a complete "
            "audit trail of all API activity, even in regions not currently in use."
        ),
        rationale=(
            "Enabling CloudTrail across all regions ensures that API activity in any region "
            "is captured. Attackers may operate in regions that are not monitored to avoid "
            "detection."
        ),
        impact="CloudTrail logs are stored in S3 and incur storage costs.",
        audit_procedure=(
            "aws cloudtrail describe-trails --include-shadow-trails\n"
            "Verify at least one trail has IsMultiRegionTrail=true and is actively logging.\n"
            "aws cloudtrail get-trail-status --name <trail-name>\n"
            "Check IsLogging=true."
        ),
        remediation=(
            "1. Create a multi-region trail:\n"
            "aws cloudtrail create-trail --name my-trail --s3-bucket-name <bucket> "
            "--is-multi-region-trail\n"
            "2. Enable logging:\n"
            "aws cloudtrail start-logging --name my-trail"
        ),
        default_value="CloudTrail is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that CloudTrail is enabled in all regions. Run: aws cloudtrail describe-trails "
            "--include-shadow-trails and confirm at least one multi-region trail (IsMultiRegionTrail=true) "
            "is active (IsLogging=true via get-trail-status). Confirm the trail captures management events."
        )
