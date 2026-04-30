"""CIS AWS 2.8 – Ensure IAM password policy requires minimum length of 14 or greater (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_8(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.8",
        title="Ensure IAM password policy requires minimum length of 14 or greater",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Password policies are used to enforce password complexity requirements. IAM "
            "password policies can be used to ensure that passwords are at least a given "
            "length. It is recommended that the password policy require a minimum password "
            "length of 14 characters."
        ),
        rationale=(
            "Setting a password complexity policy increases account resiliency against brute "
            "force login attempts. Longer passwords are significantly harder to crack."
        ),
        impact=(
            "Users with existing passwords shorter than 14 characters will be prompted to change "
            "their password at next login."
        ),
        audit_procedure=(
            "aws iam get-account-password-policy\n"
            "Check: MinimumPasswordLength >= 14"
        ),
        remediation=(
            "aws iam update-account-password-policy --minimum-password-length 14\n"
            "Or via IAM Console → Account settings → Password policy."
        ),
        default_value="No password policy is set by default; AWS minimum is 8 characters.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.2", title="Use Unique Passwords", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="16.1", title="Maintain an Inventory of Authentication Systems", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        policy = data.get("password_policy")
        if policy is None:
            return self._fail(
                "No IAM password policy is configured. A password policy with minimum length "
                "of 14 must be set.",
            )

        min_length = policy.get("MinimumPasswordLength", 0)
        evidence = [Evidence(
            source="iam:GetAccountPasswordPolicy",
            data={"MinimumPasswordLength": min_length},
            description="Current minimum password length in the IAM password policy.",
        )]

        if min_length >= 14:
            return self._pass(
                f"IAM password policy requires minimum length of {min_length} characters. Compliant.",
                evidence=evidence,
            )
        return self._fail(
            f"IAM password policy minimum length is {min_length}. Must be 14 or greater.",
            evidence=evidence,
        )
