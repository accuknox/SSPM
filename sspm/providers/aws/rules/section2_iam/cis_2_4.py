"""CIS AWS 2.4 – Ensure no 'root' user account access key exists (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_4(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.4",
        title="Ensure no 'root' user account access key exists",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.CRITICAL,
        description=(
            "The root account is the most privileged AWS account. Access keys for the root "
            "account provide programmatic access with unrestricted permissions. Access keys "
            "for the root account should not exist."
        ),
        rationale=(
            "Root access keys are permanent credentials that provide full access to all AWS "
            "services and resources. If compromised, they cannot be scoped or restricted. "
            "All programmatic access should use IAM users or roles with least-privilege policies."
        ),
        impact=(
            "Any automation currently using root access keys must be migrated to use IAM roles "
            "or IAM user credentials with appropriate least-privilege policies."
        ),
        audit_procedure=(
            "aws iam get-account-summary\n"
            "Check: AccountAccessKeysPresent == 0"
        ),
        remediation=(
            "1. Sign in to the AWS Management Console as root.\n"
            "2. Navigate to IAM → Security credentials.\n"
            "3. In the Access keys section, delete any existing access keys.\n"
            "4. Migrate any dependent automation to use IAM roles or IAM user credentials."
        ),
        default_value="Root access keys do not exist by default but can be created.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
            CISControl(version="v7", control_id="4.3", title="Ensure the Use of Dedicated Administrative Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        account_summary = data.get("iam_account_summary")
        if account_summary is None:
            return self._skip("Could not retrieve IAM account summary.")

        keys_present = account_summary.get("AccountAccessKeysPresent", 0)
        evidence = [Evidence(
            source="iam:GetAccountSummary",
            data={"AccountAccessKeysPresent": keys_present},
            description="Number of root account access keys present.",
        )]

        if keys_present == 0:
            return self._pass(
                "No root user access keys exist. Compliant.",
                evidence=evidence,
            )
        return self._fail(
            f"Root user account has {keys_present} access key(s). "
            "Root access keys should be deleted immediately.",
            evidence=evidence,
        )
