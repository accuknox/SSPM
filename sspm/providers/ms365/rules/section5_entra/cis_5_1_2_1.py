"""
CIS MS365 5.1.2.1 (L1) – Ensure 'Per-user MFA' is disabled (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Per-user MFA (the legacy portal at aka.ms/mfasetup) is a deprecated method.
All MFA should be enforced via Conditional Access policies or Security
Defaults.  Mixing per-user MFA with Conditional Access causes unpredictable
authentication behaviour.
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
class CIS_5_1_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.2.1",
        title="Ensure 'Per-user MFA' is disabled",
        section="5.1.2 Users",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Per-user MFA is a legacy method of enforcing MFA that should be replaced "
            "by Conditional Access or Security Defaults.  When Conditional Access is "
            "in use, per-user MFA settings are ignored and can create confusion."
        ),
        rationale=(
            "Mixing per-user MFA with Conditional Access can result in users being "
            "prompted for MFA unexpectedly or bypassing intended security controls. "
            "Centralising MFA enforcement in Conditional Access provides consistent "
            "policy application."
        ),
        impact=(
            "Disabling per-user MFA requires that MFA is enforced via Conditional "
            "Access or Security Defaults.  Ensure CA policies are in place before "
            "disabling."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /users?$select=id,userPrincipalName,strongAuthenticationRequirements\n"
            "  (beta endpoint required)\n"
            "  Check: no user should have strongAuthenticationRequirements.state = "
            "'enabled' or 'enforced'.\n\n"
            "Alternatively via portal:\n"
            "  Azure portal → Microsoft Entra ID → Security > MFA > Per-user MFA.\n"
            "  Confirm no users have MFA Status of 'Enabled' or 'Enforced'."
        ),
        remediation=(
            "1. Ensure Conditional Access MFA policies are in place.\n"
            "2. Navigate to Microsoft Entra admin center → Users > All Users > "
            "Per-user MFA.\n"
            "3. Select all users and disable per-user MFA.\n"
            "Note: Do not disable per-user MFA until CA policies enforcing MFA are "
            "confirmed to be active."
        ),
        default_value="Disabled (per-user MFA is off by default in new tenants with CA).",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates",
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview",
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
            CISControl(
                version="v8",
                control_id="6.5",
                title="Require MFA for Administrative Access",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "mfa", "conditional-access", "authentication"],
    )

    async def check(self, data: CollectedData):
        users = data.get("users")
        if users is None:
            return self._skip("Could not retrieve users data.")

        # The strongAuthenticationRequirements field is only available in beta.
        # We check if any user has it set (Graph beta returns it when populated).
        per_user_mfa_enabled = [
            u
            for u in users
            if u.get("strongAuthenticationRequirements")
            and any(
                req.get("state") in ("enabled", "enforced")
                for req in u.get("strongAuthenticationRequirements", [])
            )
        ]

        if not per_user_mfa_enabled:
            return self._pass(
                "Per-user MFA is not enabled for any user. "
                "MFA should be enforced via Conditional Access policies.",
                evidence=[
                    Evidence(
                        source="graph/users",
                        data={"users_checked": len(users)},
                        description="No per-user MFA enabled/enforced states found.",
                    )
                ],
            )

        upns = [u.get("userPrincipalName", u["id"]) for u in per_user_mfa_enabled]
        return self._fail(
            f"{len(per_user_mfa_enabled)} user(s) have per-user MFA enabled/enforced: "
            + ", ".join(upns[:10])
            + ("…" if len(upns) > 10 else ""),
            evidence=[
                Evidence(
                    source="graph/users",
                    data=[
                        {
                            "userPrincipalName": u.get("userPrincipalName"),
                            "strongAuthenticationRequirements": u.get(
                                "strongAuthenticationRequirements"
                            ),
                        }
                        for u in per_user_mfa_enabled
                    ],
                    description="Users with legacy per-user MFA configured.",
                )
            ],
        )
