"""
CIS MS365 5.2.2.10 (L2) – Ensure managed device is required to register
security info (Automated)

Profile Applicability: E3 Level 2, E5 Level 2
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    Evidence,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.base import MS365Rule

# The "Microsoft Authentication Registration" app ID
_MFA_REGISTRATION_APP_ID = "0000000c-0000-0000-c000-000000000000"


@registry.rule
class CIS_5_2_2_10(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.10",
        title="Ensure managed device is required to register security info",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Users should only be able to register MFA security information "
            "(phone numbers, authenticator apps) from managed, compliant devices. "
            "This prevents attackers who compromise credentials from registering "
            "new MFA methods."
        ),
        rationale=(
            "If users can register MFA methods from any device, an attacker with "
            "stolen credentials can register their own MFA method and gain full "
            "account access. Requiring a managed device for registration prevents this."
        ),
        impact=(
            "Users must use a compliant device to register or update MFA methods. "
            "IT must assist users who need to register from a new device."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy that:\n"
            "  • targets the MFA registration app (or uses userActions "
            "registerSecurityInfo)\n"
            "  • requires compliantDevice or domainJoinedDevice"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Users: All users\n"
            "  2. Target resources: User actions > Register security information\n"
            "  3. Grant: Require device to be marked as compliant\n"
            "  4. Enable the policy"
        ),
        default_value="No device requirement for security info registration by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-registration",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.3",
                title="Require MFA for Externally-Exposed Applications",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "mfa-registration", "device-compliance"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        registration_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            # Check if it targets security info registration
            conditions = policy.get("conditions") or {}
            apps_cond = conditions.get("applications") or {}
            user_actions = apps_cond.get("includeUserActions") or []
            include_apps = apps_cond.get("includeApplications") or []

            targets_registration = (
                "urn:user:registersecurityinfo" in [a.lower() for a in user_actions]
                or _MFA_REGISTRATION_APP_ID in include_apps
            )

            if not targets_registration:
                continue

            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []

            if "compliantDevice" in built_in or "domainJoinedDevice" in built_in:
                registration_policy = policy
                break

        if registration_policy:
            return self._pass(
                f"Policy '{registration_policy.get('displayName')}' requires managed "
                "device for security info registration.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": registration_policy.get("id"),
                            "displayName": registration_policy.get("displayName"),
                        },
                        description="CA policy requiring managed device for MFA registration.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy requiring managed device for security info registration found. "
            f"Reviewed {len(policies)} policies.",
        )
