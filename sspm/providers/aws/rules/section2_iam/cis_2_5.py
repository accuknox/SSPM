"""CIS AWS 2.5 – Ensure MFA is enabled for the 'root' user account (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_5(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.5",
        title="Ensure MFA is enabled for the 'root' user account",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.CRITICAL,
        description=(
            "The root account is the most privileged AWS account. Multi-factor authentication "
            "(MFA) adds an extra layer of protection on top of a user name and password. "
            "MFA must be enabled for the root account."
        ),
        rationale=(
            "Enabling MFA for the root account ensures that even if root credentials are "
            "compromised, an attacker cannot gain access without the second factor. "
            "This significantly reduces the risk of unauthorized root access."
        ),
        impact=(
            "Root account login will require an MFA device. Ensure the MFA device is stored "
            "securely and recovery procedures are in place."
        ),
        audit_procedure=(
            "aws iam get-account-summary\n"
            "Check: AccountMFAEnabled == 1"
        ),
        remediation=(
            "1. Sign in to the AWS Management Console as root.\n"
            "2. Navigate to IAM → Security credentials.\n"
            "3. In the Multi-factor authentication (MFA) section, click 'Assign MFA device'.\n"
            "4. Follow the wizard to configure a hardware or virtual MFA device.\n"
            "Note: Hardware MFA is recommended for the root account (see CIS 2.6)."
        ),
        default_value="MFA is not enabled for the root account by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.5", title="Require MFA for Administrative Access", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="4.5", title="Use Multifactor Authentication for All Administrative Access", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        account_summary = data.get("iam_account_summary")
        if account_summary is None:
            return self._skip("Could not retrieve IAM account summary.")

        mfa_enabled = account_summary.get("AccountMFAEnabled", 0)
        evidence = [Evidence(
            source="iam:GetAccountSummary",
            data={"AccountMFAEnabled": mfa_enabled},
            description="Whether MFA is enabled for the root account (1=enabled, 0=disabled).",
        )]

        if mfa_enabled == 1:
            return self._pass(
                "MFA is enabled for the root account. Compliant.",
                evidence=evidence,
            )
        return self._fail(
            "MFA is NOT enabled for the root account. Enable MFA immediately.",
            evidence=evidence,
        )
