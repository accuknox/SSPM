"""CIS AWS 2.1.6 – Ensure delegated admins manage AWS Organizations-integrated services (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_6(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.1.6",
        title="Ensure delegated admins manage AWS Organizations-integrated services",
        section="2.1 Identity and Access Management – AWS Organizations",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "Ensure AWS services that integrate with AWS Organizations (e.g., Security Hub, "
            "GuardDuty, Config, Macie) are managed through delegated administrator member "
            "accounts instead of directly from the management account."
        ),
        rationale=(
            "Managing integrated services from the management account increases its exposure "
            "and usage. Delegated administration allows security tooling to be managed from "
            "a dedicated security account while limiting access to the management account."
        ),
        impact=(
            "Migrating service administration to delegated admin accounts requires re-enrollment "
            "of member accounts in each service."
        ),
        audit_procedure=(
            "For each AWS service that supports delegated administration, run:\n"
            "aws organizations list-delegated-administrators --service-principal <service-principal>\n"
            "Common service principals: securityhub.amazonaws.com, guardduty.amazonaws.com, "
            "config.amazonaws.com, macie.amazonaws.com"
        ),
        remediation=(
            "1. For each Organizations-integrated service, designate a dedicated security account "
            "as delegated administrator.\n"
            "2. From the management account, register the delegated admin:\n"
            "aws organizations register-delegated-administrator "
            "--account-id <ACCOUNT_ID> --service-principal <service-principal>\n"
            "3. Configure the service from the delegated admin account."
        ),
        default_value="No delegated administrators are configured by default for integrated services.",
        references=[
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
