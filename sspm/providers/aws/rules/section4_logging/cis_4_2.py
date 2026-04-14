"""CIS AWS 4.2 – Ensure CloudTrail log file validation is enabled (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.2",
        title="Ensure CloudTrail log file validation is enabled",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "CloudTrail log file validation creates a digitally signed digest file containing a "
            "hash of each log file that CloudTrail writes to S3. These digest files can be used "
            "to determine whether a log file was modified, deleted, or unchanged after CloudTrail "
            "delivered it."
        ),
        rationale=(
            "Enabling log file validation ensures the integrity of CloudTrail logs. Without "
            "validation, an attacker with access to the S3 bucket could modify or delete log "
            "files to cover their tracks."
        ),
        impact="Log file validation creates additional digest files in the S3 bucket (minimal cost).",
        audit_procedure=(
            "aws cloudtrail describe-trails\n"
            "For each trail, check LogFileValidationEnabled == true."
        ),
        remediation=(
            "aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation"
        ),
        default_value="Log file validation is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
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
            if not trail.get("LogFileValidationEnabled", False)
        ]

        evidence = [Evidence(
            source="cloudtrail:DescribeTrails",
            data={"trails_without_validation": violations, "total": len(trails)},
            description="CloudTrail trails without log file validation enabled.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} CloudTrail trail(s) do not have log file validation enabled: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(trails)} CloudTrail trail(s) have log file validation enabled. Compliant.",
            evidence=evidence,
        )
