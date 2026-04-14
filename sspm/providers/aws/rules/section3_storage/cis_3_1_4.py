"""CIS AWS 3.1.4 – Ensure that S3 is configured with 'Block Public Access' enabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_1_4(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.1.4",
        title="Ensure that S3 is configured with 'Block Public Access' enabled",
        section="3.1 Storage – S3",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Amazon S3 Block Public Access provides settings to override public access granted "
            "through ACLs or bucket policies. Enabling Block Public Access at the account level "
            "ensures that no S3 bucket in the account can be made publicly accessible."
        ),
        rationale=(
            "Enabling Block Public Access at the account level prevents any user from accidentally "
            "or maliciously configuring S3 buckets for public access. This is the most effective "
            "defense against S3 data exposure."
        ),
        impact=(
            "Any S3 buckets or objects that currently have legitimate public access (e.g., "
            "public static websites) will become inaccessible. Review before enabling."
        ),
        audit_procedure=(
            "aws s3control get-public-access-block --account-id <account-id>\n"
            "All four settings must be true: BlockPublicAcls, IgnorePublicAcls, "
            "BlockPublicPolicy, RestrictPublicBuckets."
        ),
        remediation=(
            "aws s3control put-public-access-block --account-id <account-id> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        default_value="Block Public Access is not enabled by default for new accounts (enabled since April 2023 for new accounts).",
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        block_config = data.get("s3_public_access_block")
        if block_config is None:
            return self._skip(
                "Could not retrieve S3 account-level public access block configuration. "
                "Ensure the s3_public_access_block collector is enabled."
            )

        required_settings = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        missing = [s for s in required_settings if not block_config.get(s, False)]

        evidence = [Evidence(
            source="s3control:GetPublicAccessBlock",
            data=block_config,
            description="Account-level S3 Block Public Access configuration.",
        )]

        if missing:
            return self._fail(
                f"S3 Block Public Access is not fully enabled. Missing settings: {', '.join(missing)}",
                evidence=evidence,
            )
        return self._pass(
            "S3 Block Public Access is fully enabled at the account level. Compliant.",
            evidence=evidence,
        )
