"""CIS AWS 2.3 – Ensure security contact information is registered (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_3(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.3",
        title="Ensure security contact information is registered",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Specify the contact information for the account's security team so AWS security "
            "advisories reach the right people. Consider specifying an email distribution list "
            "to ensure emails are monitored by more than one individual."
        ),
        rationale=(
            "AWS sends security advisories (e.g., vulnerability notifications, abuse reports) "
            "to the registered security contact. Without this information, security notifications "
            "may go unnoticed or reach the wrong team."
        ),
        impact="No operational impact — purely a contact registration.",
        audit_procedure=(
            "1. Sign in to the AWS Management Console.\n"
            "2. Click on your account name at the top right corner.\n"
            "3. Select 'Account' from the drop-down menu.\n"
            "4. Scroll down to the Alternate Contacts section.\n"
            "5. Verify that contact information is specified in the Security section."
        ),
        remediation=(
            "1. Click on your account name at the top right corner of the console.\n"
            "2. Select 'Account' from the drop-down menu.\n"
            "3. Scroll down to the Alternate Contacts section.\n"
            "4. Click 'Edit' in the Security section.\n"
            "5. Enter the security contact name, email, and phone number.\n"
            "Note: Use an internal email distribution list so multiple people receive advisories."
        ),
        default_value="No security contact is registered by default.",
        references=[
            "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Security contact information can only be verified via the AWS Management Console "
            "(Account → Alternate Contacts → Security section). Confirm that a name, email, "
            "and phone number are entered for the Security contact, ideally pointing to a team "
            "distribution list."
        )
