"""
CIS MS365 5.1.6.3 (L1) – Ensure guest invitations are limited to the Guest
Inviter role (Automated)

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


@registry.rule
class CIS_5_1_6_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.6.3",
        title="Ensure guest invitations are limited to the Guest Inviter role",
        section="5.1.6 Guest Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Only users with the Guest Inviter role or administrators should be "
            "allowed to invite external users. This prevents any user from "
            "inviting external guests without proper approval."
        ),
        rationale=(
            "Allowing all users to invite guests can result in uncontrolled guest "
            "access to organizational resources. Restricting invitations ensures "
            "that guest access is properly governed and tracked."
        ),
        impact=(
            "Regular users will not be able to invite external guests. Only users "
            "with the Guest Inviter role or admin roles can send invitations."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check allowInvitesFrom:\n"
            "  • 'adminsAndGuestInviters' = compliant\n"
            "  • 'admins' = compliant (most restrictive)\n"
            "  • 'none' = compliant (no invitations allowed)\n"
            "  • 'everyone' = non-compliant"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > External identities > "
            "External collaboration settings.\n"
            "Set 'Guest invite settings' to 'Only users assigned to specific admin "
            "roles can invite guest users'."
        ),
        default_value="Members can invite guest users by default.",
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
        tags=["identity", "guests", "invitations", "external-collaboration"],
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

        allow_invites_from = auth_policy.get("allowInvitesFrom")

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"allowInvitesFrom": allow_invites_from},
                description="Authorization policy guest invitation setting.",
            )
        ]

        compliant_values = ("adminsAndGuestInviters", "admins", "none")
        if allow_invites_from in compliant_values:
            return self._pass(
                f"Guest invitations are restricted (allowInvitesFrom = {allow_invites_from}).",
                evidence=evidence,
            )

        return self._fail(
            f"Guest invitations are not properly restricted "
            f"(allowInvitesFrom = {allow_invites_from}). "
            "Should be 'adminsAndGuestInviters' or more restrictive.",
            evidence=evidence,
        )
