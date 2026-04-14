"""CIS AWS 2.14 – Ensure IAM policies that allow full '*:*' administrative privileges are not attached (Automated, L1)"""
from __future__ import annotations

import json

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


def _policy_has_full_admin(document: dict) -> bool:
    """Return True if the policy document grants full admin (Effect=Allow, Action=*, Resource=*)."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


@registry.rule
class CIS_2_14(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.14",
        title="Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.CRITICAL,
        description=(
            "IAM policies are the means by which privileges are granted to users, groups, or "
            "roles. It is recommended that IAM policies that grant full administrative privileges "
            "(Action=*, Resource=*) should not be attached to any IAM identity."
        ),
        rationale=(
            "Policies granting full admin access (*:*) violate the principle of least privilege. "
            "If such a policy is attached to a compromised identity, an attacker gains unrestricted "
            "access to all AWS resources."
        ),
        impact=(
            "Users or roles relying on full admin policies must be assigned more specific, "
            "least-privilege policies for their actual tasks."
        ),
        audit_procedure=(
            "aws iam list-policies --scope Local\n"
            "For each policy, get the policy document and check for Effect=Allow, Action=*, Resource=*.\n"
            "Also check: aws iam list-users | for each user: list-attached-user-policies for "
            "AdministratorAccess."
        ),
        remediation=(
            "1. Identify all IAM identities (users, groups, roles) with full admin policies attached.\n"
            "2. Determine the actual permissions needed for each identity.\n"
            "3. Create or assign appropriate least-privilege policies.\n"
            "4. Detach or delete the full admin policies."
        ),
        default_value="No policies are created or attached by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        policies = data.get("iam_policies") or []
        users = data.get("iam_users") or []

        violations = []

        # Check customer-managed policies for *:* grants
        for policy in policies:
            doc = policy.get("_document", {})
            if _policy_has_full_admin(doc):
                violations.append(f"Policy: {policy.get('PolicyName')} ({policy.get('Arn')})")

        # Check for AWS-managed AdministratorAccess attached to users
        for user in users:
            name = user.get("UserName", "")
            attached = user.get("_attached_policies", [])
            for p in attached:
                if p.get("PolicyName") == "AdministratorAccess":
                    violations.append(f"User {name} has AdministratorAccess attached")

        evidence = [Evidence(
            source="iam:ListPolicies / iam:GetPolicyVersion / iam:ListAttachedUserPolicies",
            data={"full_admin_violations": violations},
            description="Policies or users with full administrative (*:*) privileges.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} IAM policy/attachment(s) grant full administrative privileges: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "No IAM policies granting full '*:*' administrative privileges found. Compliant.",
            evidence=evidence,
        )
