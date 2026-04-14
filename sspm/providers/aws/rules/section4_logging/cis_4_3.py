"""CIS AWS 4.3 – Ensure AWS Config is enabled in all regions (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_3(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.3",
        title="Ensure AWS Config is enabled in all regions",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "AWS Config is a service that enables you to assess, audit, and evaluate the "
            "configurations of your AWS resources. Config continuously monitors and records "
            "your AWS resource configurations. It should be enabled in all regions."
        ),
        rationale=(
            "AWS Config provides a detailed view of the configuration of AWS resources and "
            "how they change over time. Without Config, configuration drift and unauthorized "
            "changes may go undetected."
        ),
        impact="AWS Config incurs costs based on the number of configuration items recorded.",
        audit_procedure=(
            "aws configservice describe-configuration-recorders\n"
            "aws configservice describe-configuration-recorder-status\n"
            "Verify at least one recorder is recording all resources with lastStatus=SUCCESS."
        ),
        remediation=(
            "1. Create a configuration recorder that records all resource types.\n"
            "2. Create a delivery channel with an S3 bucket.\n"
            "3. Start the configuration recorder:\n"
            "aws configservice start-configuration-recorder --configuration-recorder-name default"
        ),
        default_value="AWS Config is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/config/latest/developerguide/getting-started.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        recorders = data.get("config_recorders") or []
        statuses = data.get("config_recorder_statuses") or []

        if not recorders:
            return self._fail(
                "No AWS Config configuration recorders found. AWS Config is not enabled.",
            )

        # Check that at least one recorder is active and recording all resources
        status_map = {s.get("name"): s for s in statuses}
        compliant_recorders = []
        non_compliant_recorders = []

        for recorder in recorders:
            name = recorder.get("name", "unknown")
            rec_all = recorder.get("recordingGroup", {}).get("allSupported", False)
            status = status_map.get(name, {})
            is_recording = status.get("recording", False)
            last_status = status.get("lastStatus", "")

            if rec_all and is_recording and last_status in ("SUCCESS", ""):
                compliant_recorders.append(name)
            else:
                issues = []
                if not rec_all:
                    issues.append("not recording all resources")
                if not is_recording:
                    issues.append("not recording")
                if last_status and last_status != "SUCCESS":
                    issues.append(f"lastStatus={last_status}")
                non_compliant_recorders.append(f"{name} ({', '.join(issues)})")

        evidence = [Evidence(
            source="config:DescribeConfigurationRecorders / DescribeConfigurationRecorderStatus",
            data={
                "compliant_recorders": compliant_recorders,
                "non_compliant_recorders": non_compliant_recorders,
            },
            description="AWS Config recorder status.",
        )]

        if non_compliant_recorders or not compliant_recorders:
            return self._fail(
                f"AWS Config is not properly configured. Issues: "
                f"{', '.join(non_compliant_recorders) if non_compliant_recorders else 'no active recorders'}",
                evidence=evidence,
            )
        return self._pass(
            f"AWS Config is enabled with {len(compliant_recorders)} active recorder(s). Compliant.",
            evidence=evidence,
        )
