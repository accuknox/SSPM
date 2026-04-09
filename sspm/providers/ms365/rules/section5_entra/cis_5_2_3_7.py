"""
CIS MS365 5.2.3.7 (L1) – Ensure email-based OTP is disabled (Automated)

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
class CIS_5_2_3_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.7",
        title="Ensure email-based OTP is disabled",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Email one-time passcode (OTP) should be disabled as an authentication "
            "method. Email OTP is a weaker authentication method that can be "
            "compromised if the user's email is compromised."
        ),
        rationale=(
            "Email OTP relies on the security of the email account. If a user's "
            "email is compromised, attackers can intercept OTPs and bypass MFA. "
            "Stronger methods should be used instead."
        ),
        impact=(
            "External users (B2B guests) who rely on email OTP for authentication "
            "will need to use alternative authentication methods."
        ),
        audit_procedure=(
            "GET /policies/authenticationMethodsPolicy\n"
            "In authenticationMethodConfigurations:\n"
            "  Find email method (id = 'email') - state should be 'disabled'"
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Authentication methods.\n"
            "Disable 'Email OTP' authentication method."
        ),
        default_value="Email OTP may be enabled for guest users by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods",
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
        tags=["identity", "mfa", "authentication-methods", "email-otp"],
    )

    async def check(self, data: CollectedData):
        auth_methods_policy = data.get("authentication_methods_policy")
        if auth_methods_policy is None:
            return self._skip(
                "Could not retrieve authentication methods policy. "
                "Requires Policy.Read.All permission."
            )

        auth_method_configs = auth_methods_policy.get("authenticationMethodConfigurations") or []

        email_config = None
        for config in auth_method_configs:
            if config.get("id", "").lower() == "email":
                email_config = config
                break

        if email_config is None:
            # Email OTP not found; might mean it's controlled differently
            return self._manual(
                "Email OTP method configuration not found in authentication methods policy. "
                "Verify manually in Microsoft Entra admin center:\n"
                "  Protection > Authentication methods > Email OTP"
            )

        state = email_config.get("state", "").lower()

        evidence = [
            Evidence(
                source="graph/policies/authenticationMethodsPolicy",
                data={"emailOTP.state": state},
                description="Email OTP authentication method state.",
            )
        ]

        if state == "disabled":
            return self._pass(
                "Email OTP authentication method is disabled.",
                evidence=evidence,
            )

        return self._fail(
            f"Email OTP authentication method is not disabled (state = '{state}'). "
            "Disable email OTP in favor of stronger authentication methods.",
            evidence=evidence,
        )
