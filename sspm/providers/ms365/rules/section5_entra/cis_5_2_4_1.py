"""
CIS MS365 5.2.4.1 (L1) – Ensure self-service password reset is enabled for all
users (Automated)

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
class CIS_5_2_4_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.4.1",
        title="Ensure self-service password reset is enabled for all users",
        section="5.2.4 Password Reset",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Microsoft Entra admin center → Protection > Password reset > Properties.\n"
            "Verify 'Self-service password reset enabled' is set to 'All'.\n\n"
            "Also verify the required number of authentication methods is set to 2."
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
        if auth_policy is None:
            return self._skip(
                "Could not retrieve authorization policy. "
                "Requires Policy.Read.All permission."
            )

        sspr_enabled = auth_policy.get("allowedToUseSSPR")
        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"allowedToUseSSPR": sspr_enabled},
                description="Tenant-wide SSPR enablement flag.",
            )
        ]

        if sspr_enabled is True:
            return self._pass(
                "Self-service password reset is enabled for all users "
                "(allowedToUseSSPR = true).",
                evidence=evidence,
            )
        if sspr_enabled is False:
            return self._fail(
                "Self-service password reset is disabled "
                "(allowedToUseSSPR = false).",
                evidence=evidence,
            )

        # Field absent — fall back to manual guidance
        return self._manual(
            "The allowedToUseSSPR flag was not present in the authorization policy. "
            "Verify SSPR manually:\n"
            "  Microsoft Entra admin center → Protection > Password reset > Properties\n"
            "  Ensure 'Self-service password reset enabled' is set to 'All'."
        )
