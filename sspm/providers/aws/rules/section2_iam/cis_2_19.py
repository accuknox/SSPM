"""CIS AWS 2.19 – Ensure IAM users are managed centrally via identity federation or AWS Organizations (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_19(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.19",
        title="Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "For multi-account environments, use identity federation (SSO/IAM Identity Center) "
            "or AWS Organizations for centralized IAM user management rather than creating "
            "individual IAM users in each account."
        ),
        rationale=(
            "Managing IAM users individually across multiple accounts leads to credential sprawl "
            "and inconsistent access controls. Centralized identity management through federation "
            "or IAM Identity Center simplifies user lifecycle management and enforces consistent "
            "policies."
        ),
        impact=(
            "Migrating from individual IAM users to federated identities requires updating "
            "application authentication and training users on the new login flow."
        ),
        audit_procedure=(
            "1. Check if AWS IAM Identity Center (SSO) is enabled:\n"
            "aws sso-admin list-instances\n"
            "2. Verify SAML or OIDC identity providers are configured:\n"
            "aws iam list-saml-providers\n"
            "aws iam list-open-id-connect-providers\n"
            "3. Confirm that most access is federated rather than through local IAM users."
        ),
        remediation=(
            "1. Enable AWS IAM Identity Center (formerly AWS SSO).\n"
            "2. Connect your identity provider (Active Directory, Okta, etc.).\n"
            "3. Migrate users from IAM users to federated access.\n"
            "4. Remove unnecessary local IAM users."
        ),
        default_value="IAM users are local to each AWS account by default.",
        references=[
            "https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.6", title="Centralize Account Management", ig1=False, ig2=True, ig3=True),
            CISControl(version="v7", control_id="16.2", title="Configure Centralized Point of Authentication", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
