"""CIS AWS 2.10 – Ensure MFA is enabled for all IAM users with a console password (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_10(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.10",
        title="Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Multi-factor authentication (MFA) adds an extra layer of protection on top of a "
            "user name and password. MFA must be enabled for all IAM users that have console "
            "access (i.e., a console password set)."
        ),
        rationale=(
            "Enabling MFA for console access users provides additional protection against "
            "compromised passwords. Without MFA, a stolen password is sufficient for an attacker "
            "to gain console access."
        ),
        impact=(
            "Users without MFA will need to enroll an MFA device before they can access the "
            "console if policies are enforced."
        ),
        audit_procedure=(
            "aws iam generate-credential-report && aws iam get-credential-report\n"
            "For each user where password_enabled=true, check mfa_active=true."
        ),
        remediation=(
            "1. For each non-compliant user, navigate to IAM → Users → <username> → Security credentials.\n"
            "2. In the Multi-factor authentication (MFA) section, assign an MFA device.\n"
            "3. Consider enforcing MFA via an IAM policy that denies all actions except "
            "MFA enrollment unless MFA is present."
        ),
        default_value="MFA is not enabled for IAM users by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.5", title="Require MFA for Administrative Access", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="4.5", title="Use Multifactor Authentication for All Administrative Access", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        report = data.get("credential_report")
        if report is None:
            return self._skip("Could not retrieve IAM credential report.")

        violations = []
        for row in report:
            user = row.get("user", "")
            if user == "<root_account>":
                continue
            password_enabled = str(row.get("password_enabled", "false")).lower()
            if password_enabled != "true":
                continue
            mfa_active = str(row.get("mfa_active", "false")).lower()
            if mfa_active != "true":
                violations.append(user)

        evidence = [Evidence(
            source="iam:GetCredentialReport",
            data={"users_without_mfa": violations},
            description="IAM users with console password but no MFA enabled.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} IAM user(s) have console access without MFA: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "All IAM users with console passwords have MFA enabled. Compliant.",
            evidence=evidence,
        )
