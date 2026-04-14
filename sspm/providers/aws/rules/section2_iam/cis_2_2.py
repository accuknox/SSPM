"""CIS AWS 2.2 – Maintain current AWS account contact details (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.2",
        title="Maintain current AWS account contact details",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Ensure AWS account contact details (name, email, phone number, and address) are "
            "accurate and current. Stale contact details result in delayed notification of "
            "security events and billing issues."
        ),
        rationale=(
            "AWS uses account contact information to notify of security findings, billing events, "
            "and service notices. Stale contact details lead to missed notifications, which can "
            "delay incident response and compliance activities."
        ),
        impact="No operational impact — purely a contact information update.",
        audit_procedure=(
            "1. Sign in to the AWS Management Console.\n"
            "2. Click on your account name at the top right corner.\n"
            "3. Select 'Account' from the drop-down menu.\n"
            "4. Review the Contact Information section and verify the name, email address, "
            "phone number, and address are current and accurate."
        ),
        remediation=(
            "1. Sign in to the AWS Management Console.\n"
            "2. Click on your account name → Account.\n"
            "3. Under Contact Information, click 'Edit'.\n"
            "4. Update the name, email, phone number, and address with current information.\n"
            "5. Click 'Update'."
        ),
        default_value="Contact details are provided during account creation but may become stale.",
        references=[
            "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that the AWS account contact details are current and accurate via the "
            "AWS Management Console: Account → Contact Information. Ensure the name, email, "
            "phone number, and address are up to date."
        )
