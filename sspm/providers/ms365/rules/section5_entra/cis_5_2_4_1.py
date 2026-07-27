"""
CIS MS365 5.2.4.1 (L1) – Ensure 'Self service password reset enabled' is set to
'All' (Manual)

Profile Applicability: E3 Level 1, E5 Level 1

Per the official CIS Microsoft 365 Foundations Benchmark v6.0.1, this control's
audit procedure is UI-only (Microsoft Entra admin center > Password reset >
Properties > 'Self service password reset enabled' = 'All') with no published
Microsoft Graph or PowerShell method. CIS therefore classifies it as Manual.
Note: the Graph `authorizationPolicy.allowedToUseSSPR` flag only reflects
whether SSPR is enabled at all (any/none), not whether it is scoped to 'All'
users specifically, so it cannot be used to assert a pass/fail verdict here.
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_5_2_4_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.4.1",
        title="Ensure 'Self service password reset enabled' is set to 'All'",
        section="5.2.4 Password Reset",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Self-service password reset (SSPR) should be enabled for all users "
            "to allow them to reset their own passwords without contacting IT "
            "helpdesk, reducing support burden and enabling faster password recovery."
        ),
        rationale=(
            "SSPR reduces helpdesk ticket volume for password resets and allows "
            "users to quickly regain access to their accounts. SSPR can be "
            "configured to require MFA verification for identity verification."
        ),
        impact=(
            "Users will be able to reset their own passwords using registered "
            "authentication methods. Requires users to register SSPR methods."
        ),
        audit_procedure=(
            "Microsoft Entra admin center → Entra ID > Password reset > Properties.\n"
            "Ensure 'Self service password reset enabled' is set to 'All'."
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Password reset > Properties.\n"
            "Set 'Self-service password reset enabled' to 'All'.\n"
            "Configure methods and require 2 methods for strong verification."
        ),
        default_value="SSPR is disabled by default or set to 'None'.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment",
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
        tags=["identity", "sspr", "password-reset", "self-service"],
    )

    async def check(self, data: CollectedData):
        auth_policy = data.get("authorization_policy")
        hint = ""
        if auth_policy is not None and auth_policy.get("allowedToUseSSPR") is False:
            hint = (
                " Note: tenant-wide SSPR (allowedToUseSSPR) is currently disabled, "
                "which already fails this control."
            )

        return self._manual(
            message=(
                "CIS classifies this control as Manual: verify in the Microsoft "
                "Entra admin center under Entra ID > Password reset > Properties "
                "that 'Self service password reset enabled' is set to 'All'."
                + hint
            )
        )
