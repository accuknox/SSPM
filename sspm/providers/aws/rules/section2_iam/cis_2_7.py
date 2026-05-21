"""CIS AWS 2.7 – Eliminate use of the 'root' user for administrative and daily tasks (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_7(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.7",
        title="Eliminate use of the 'root' user for administrative and daily tasks",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "With the creation of an AWS account, a root user is created. Daily administrative "
            "tasks should use IAM users or roles, not the root user. The root user should only "
            "be used for tasks that specifically require root privileges."
        ),
        rationale=(
            "The root user has unrestricted access to all AWS resources and cannot be restricted "
            "by IAM policies. Using IAM identities with least-privilege policies for daily tasks "
            "limits the blast radius of compromised credentials."
        ),
        impact=(
            "Tasks currently performed as root must be identified and delegated to appropriate "
            "IAM identities with least-privilege permissions."
        ),
        audit_procedure=(
            "1. Run: aws iam generate-credential-report && aws iam get-credential-report\n"
            "2. Decode the Base64 credential report.\n"
            "3. Find the row for <root_account>.\n"
            "4. Check the password_last_used field. If it was used recently (within 90 days), "
            "investigate and eliminate root usage."
        ),
        remediation=(
            "1. Create IAM identities (users/roles) with appropriate least-privilege policies "
            "for all administrative tasks.\n"
            "2. Avoid using the root account for daily operations.\n"
            "3. Enable CloudWatch alarms for root account activity (see CIS 5.3).\n"
            "4. Store root credentials securely (e.g., in a vault) and limit access."
        ),
        default_value="The root account is active and can be used for all operations.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="4.3", title="Ensure the Use of Dedicated Administrative Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
