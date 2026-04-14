"""CIS AWS 4.8 – Ensure that object-level logging for write events is enabled for S3 buckets (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


def _has_s3_data_logging(trails: list, read_write_type: str) -> bool:
    """
    Check if any trail has S3 data event logging for the given ReadWriteType.
    read_write_type: 'WriteOnly', 'ReadOnly', or 'All'
    """
    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        status = trail.get("_status", {})
        if not status.get("IsLogging"):
            continue
        selectors = trail.get("_event_selectors", [])
        for selector in selectors:
            data_resources = selector.get("DataResources", [])
            for resource in data_resources:
                if resource.get("Type") != "AWS::S3::Object":
                    continue
                values = resource.get("Values", [])
                # Check if it covers all buckets (arn:aws:s3:::*)
                covers_all = any("arn:aws:s3:::" in v for v in values)
                if not covers_all:
                    continue
                rw_type = selector.get("ReadWriteType", "")
                if rw_type == "All" or rw_type == read_write_type:
                    return True
    return False


@registry.rule
class CIS_4_8(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.8",
        title="Ensure that object-level logging for write events is enabled for S3 buckets",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are "
            "called data events. By default, CloudTrail does not log data events. Enabling "
            "S3 write event logging ensures that all write operations on S3 objects are captured."
        ),
        rationale=(
            "Logging S3 write events (PutObject, DeleteObject, etc.) helps detect unauthorized "
            "data modifications or deletions. This is critical for detecting data tampering "
            "and insider threats."
        ),
        impact="S3 data event logging can generate large volumes of log data, increasing costs.",
        audit_procedure=(
            "aws cloudtrail describe-trails && aws cloudtrail get-event-selectors --trail-name <name>\n"
            "Check for DataResources with Type=AWS::S3::Object and ReadWriteType=WriteOnly or All."
        ),
        remediation=(
            "aws cloudtrail put-event-selectors --trail-name <trail-name> "
            "--event-selectors '[{\"ReadWriteType\": \"WriteOnly\", \"IncludeManagementEvents\": true, "
            "\"DataResources\": [{\"Type\": \"AWS::S3::Object\", \"Values\": [\"arn:aws:s3:::\"]}]}]'"
        ),
        default_value="S3 data event logging is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        trails = data.get("cloudtrail_trails")
        if trails is None:
            return self._skip("Could not retrieve CloudTrail trails.")

        has_write_logging = _has_s3_data_logging(trails, "WriteOnly")

        evidence = [Evidence(
            source="cloudtrail:GetEventSelectors",
            data={"s3_write_event_logging_configured": has_write_logging},
            description="Whether S3 object-level write event logging is enabled in CloudTrail.",
        )]

        if has_write_logging:
            return self._pass(
                "CloudTrail is configured with S3 object-level write event logging. Compliant.",
                evidence=evidence,
            )
        return self._fail(
            "No CloudTrail trail has S3 object-level write event logging configured for all buckets.",
            evidence=evidence,
        )
