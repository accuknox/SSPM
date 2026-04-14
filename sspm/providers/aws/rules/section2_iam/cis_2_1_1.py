"""CIS AWS 2.1.1 – Ensure centralized root access in AWS Organizations (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_1(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.1.1",
        title="Ensure centralized root access in AWS Organizations",
        section="2.1 Identity and Access Management – AWS Organizations",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "Ensure centralized root access management is enabled to manage and secure root user "
            "credentials for member accounts in AWS Organizations."
        ),
        rationale=(
            "Root credentials in each member account create privileged credential sprawl. "
            "Centralized management lets security teams remove or avoid creating root credentials "
            "and perform root-only tasks via short-term sessions."
        ),
        impact=(
            "Changing centralized root access changes how root user access is obtained but does "
            "not automatically remove existing root credentials."
        ),
        audit_procedure=(
            "1. Sign in to AWS Management Console.\n"
            "2. Navigate to AWS Organizations and check that Root access management is enabled.\n"
            "3. Navigate to IAM → Root access management and verify root credentials management "
            "is turned on for member accounts."
        ),
        remediation=(
            "1. In the AWS Organizations console, enable trusted access for IAM.\n"
            "2. In the IAM console, enable Root access management to centrally manage root "
            "credentials for all member accounts in the organization."
        ),
        default_value="Centralized root access management is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="5.6", title="Centralize Account Management", ig1=False, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.7", title="Centralize Access Control", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify in the AWS Management Console: Organizations → Root access management is "
            "enabled, and IAM → Root access management shows root credentials management is "
            "turned on for all member accounts."
        )
