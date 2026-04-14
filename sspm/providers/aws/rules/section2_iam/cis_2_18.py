"""CIS AWS 2.18 – Ensure that IAM Access Analyzer is enabled for all regions (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_18(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.18",
        title="Ensure that IAM Access Analyzer is enabled for all regions",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "AWS IAM Access Analyzer helps you identify the resources in your organization and "
            "accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external "
            "entity. It should be enabled in all regions to provide comprehensive coverage."
        ),
        rationale=(
            "IAM Access Analyzer continuously monitors resource policies and reports any "
            "resources that allow access from outside the AWS account or organization. "
            "Without it, unintended external access may go undetected."
        ),
        impact="Enabling Access Analyzer incurs a small cost per analyzer per region.",
        audit_procedure=(
            "For each enabled region, run:\n"
            "aws accessanalyzer list-analyzers --region <region>\n"
            "Verify at least one ACTIVE analyzer exists per region."
        ),
        remediation=(
            "For each region without an active analyzer:\n"
            "aws accessanalyzer create-analyzer --analyzer-name default "
            "--type ACCOUNT --region <region>"
        ),
        default_value="IAM Access Analyzer is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        analyzers = data.get("access_analyzers")
        if analyzers is None:
            return self._skip(
                "Could not retrieve IAM Access Analyzer data. "
                "Ensure the access_analyzers collector is enabled."
            )

        # analyzers is expected to be {region: [analyzer_dicts]}
        regions_without_analyzer = []
        regions_with_analyzer = []

        if isinstance(analyzers, dict):
            for region, region_analyzers in analyzers.items():
                active = [a for a in region_analyzers if a.get("status") == "ACTIVE"]
                if active:
                    regions_with_analyzer.append(region)
                else:
                    regions_without_analyzer.append(region)
        else:
            return self._skip("Unexpected format for access_analyzers data.")

        evidence = [Evidence(
            source="accessanalyzer:ListAnalyzers",
            data={
                "regions_with_active_analyzer": regions_with_analyzer,
                "regions_without_analyzer": regions_without_analyzer,
            },
            description="IAM Access Analyzer coverage by region.",
        )]

        if regions_without_analyzer:
            return self._fail(
                f"IAM Access Analyzer is not active in {len(regions_without_analyzer)} region(s): "
                f"{', '.join(regions_without_analyzer)}",
                evidence=evidence,
            )
        return self._pass(
            f"IAM Access Analyzer is active in all {len(regions_with_analyzer)} checked region(s). Compliant.",
            evidence=evidence,
        )
