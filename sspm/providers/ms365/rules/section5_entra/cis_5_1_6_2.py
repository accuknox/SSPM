"""
CIS MS365 5.1.6.2 (L1) – Ensure guest user access is restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1
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

# Role IDs for guest access levels
# 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Restricted Guest User (most restrictive)
# bf6e4e74-7941-46e8-9c5a-fef2b3e9d6dd = Guest User (default)
# None/missing = same as member (most permissive)
_RESTRICTED_GUEST_ROLE_ID = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
_GUEST_USER_ROLE_ID = "bf6e4e74-7941-46e8-9c5a-fef2b3e9d6dd"


@registry.rule
class CIS_5_1_6_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.6.2",
        title="Ensure guest user access is restricted",
        section="5.1.6 Guest Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Guest user access should be restricted to 'Restricted Guest User' "
            "permissions to minimize the amount of directory information guest "
            "users can access and enumerate."
        ),
        rationale=(
            "By default, guest users have the same permissions as regular users to "
            "enumerate directory objects. Restricting guest access prevents guests "
            "from enumerating all users, groups, and other directory objects."
        ),
        impact=(
            "Guest users will have limited access to the directory and may not be "
            "able to enumerate other users or groups. Some integration scenarios "
            "may need to be adjusted."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check guestUserRoleId:\n"
            "  • 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Restricted Guest (compliant)\n"
            "  • bf6e4e74-7941-46e8-9c5a-fef2b3e9d6dd = Guest User (partially compliant)\n"
            "  • Other/null = Member-like access (non-compliant)"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > External identities > "
            "External collaboration settings.\n"
            "Set 'Guest user access' to 'Guest users have limited access to properties "
            "and memberships of directory objects' (most restrictive)."
        ),
        default_value="Guest user access is set to Guest User level by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "guests", "external-collaboration", "b2b"],
    )

    async def check(self, data: CollectedData):
        auth_policy = data.get("authorization_policy")
        if auth_policy is None:
            return self._skip(
                "Could not retrieve authorization policy. "
                "Requires Policy.Read.All permission."
            )

        if isinstance(auth_policy, list):
            auth_policy = auth_policy[0] if auth_policy else {}

        guest_role_id = auth_policy.get("guestUserRoleId")

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"guestUserRoleId": guest_role_id},
                description="Authorization policy guest user role setting.",
            )
        ]

        if guest_role_id == _RESTRICTED_GUEST_ROLE_ID:
            return self._pass(
                "Guest user access is set to Restricted Guest (most restrictive). "
                f"guestUserRoleId = {guest_role_id}",
                evidence=evidence,
            )

        role_names = {
            _GUEST_USER_ROLE_ID: "Guest User (limited directory access)",
            None: "Member (full directory access)",
        }
        role_name = role_names.get(guest_role_id, f"Unknown role: {guest_role_id}")

        return self._fail(
            f"Guest user access is not set to the most restrictive level. "
            f"Current setting: {role_name}. "
            f"Should be Restricted Guest (role ID: {_RESTRICTED_GUEST_ROLE_ID}).",
            evidence=evidence,
        )
