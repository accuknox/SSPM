"""CIS AWS 2.9 – Ensure IAM password policy prevents password reuse (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_9(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.9",
        title="Ensure IAM password policy prevents password reuse",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "IAM password policies can prevent the reuse of a given password by the same user. "
            "It is recommended that the password policy prevent the reuse of passwords for at "
            "least 24 previous passwords."
        ),
        rationale=(
            "Preventing password reuse increases account resiliency against brute force login "
            "attempts by ensuring that previously compromised passwords cannot be reused."
        ),
        impact="Users cannot reuse any of their last 24 passwords.",
        audit_procedure=(
            "aws iam get-account-password-policy\n"
            "Check: PasswordReusePrevention >= 24"
        ),
        remediation=(
            "aws iam update-account-password-policy --password-reuse-prevention 24\n"
            "Or via IAM Console → Account settings → Password policy."
        ),
        default_value="No password reuse prevention is configured by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.2", title="Use Unique Passwords", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="4.4", title="Use Unique Passwords", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        policy = data.get("password_policy")
        if policy is None:
            return self._fail(
                "No IAM password policy is configured. A password policy preventing reuse of "
                "24 or more passwords must be set.",
            )

        reuse_prevention = policy.get("PasswordReusePrevention", 0)
        evidence = [Evidence(
            source="iam:GetAccountPasswordPolicy",
            data={"PasswordReusePrevention": reuse_prevention},
            description="Number of previous passwords remembered by the IAM password policy.",
        )]

        if reuse_prevention >= 24:
            return self._pass(
                f"IAM password policy prevents reuse of the last {reuse_prevention} passwords. Compliant.",
                evidence=evidence,
            )
        return self._fail(
            f"IAM password policy only prevents reuse of {reuse_prevention} previous password(s). "
            "Must be 24 or greater.",
            evidence=evidence,
        )
