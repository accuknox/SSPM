"""CIS AWS 2.13 – Ensure IAM users receive permissions only through groups (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_13(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.13",
        title="Ensure IAM users receive permissions only through groups",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "IAM users should not have directly attached policies. Instead, users should "
            "receive permissions through group membership. This simplifies permission management "
            "and ensures consistent policy application."
        ),
        rationale=(
            "Managing permissions through groups makes it easier to revoke permissions from "
            "multiple users simultaneously and reduces the risk of permission drift. "
            "Direct user policies are harder to audit and maintain."
        ),
        impact=(
            "Permissions currently attached directly to users must be migrated to IAM groups "
            "before removing direct policy attachments."
        ),
        audit_procedure=(
            "aws iam list-users | iterate users\n"
            "aws iam list-attached-user-policies --user-name <username>\n"
            "aws iam list-user-policies --user-name <username>\n"
            "Any user with attached or inline policies is non-compliant."
        ),
        remediation=(
            "1. Create appropriate IAM groups with the required policies.\n"
            "2. Add users to the appropriate groups.\n"
            "3. Remove directly attached policies from users.\n"
            "IAM → Users → <username> → Permissions → remove directly attached policies."
        ),
        default_value="IAM allows policies to be attached directly to users.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
            CISControl(version="v7", control_id="16.1", title="Maintain an Inventory of Authentication Systems", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        users = data.get("iam_users")
        if users is None:
            return self._skip("Could not retrieve IAM users.")

        violations = []
        for user in users:
            name = user.get("UserName", "")
            attached = user.get("_attached_policies", [])
            inline = user.get("_inline_policies", [])
            if attached or inline:
                violations.append(
                    f"{name} ({len(attached)} attached, {len(inline)} inline)"
                )

        evidence = [Evidence(
            source="iam:ListAttachedUserPolicies / iam:ListUserPolicies",
            data={"users_with_direct_policies": violations},
            description="IAM users with policies attached directly (not via groups).",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} IAM user(s) have directly attached policies: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "All IAM users receive permissions only through groups. Compliant.",
            evidence=evidence,
        )
