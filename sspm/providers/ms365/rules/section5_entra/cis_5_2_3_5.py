"""
CIS MS365 5.2.3.5 (L1) – Ensure weak authentication methods are disabled
(Automated)

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
class CIS_5_2_3_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.5",
        title="Ensure weak authentication methods are disabled",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Weak authentication methods such as SMS OTP and voice call should "
            "be disabled in favor of stronger methods like Microsoft Authenticator "
            "and FIDO2. SMS and voice calls are susceptible to SIM swapping and "
            "social engineering attacks."
        ),
        rationale=(
            "SMS and voice call OTP are vulnerable to SIM swapping, phone number "
            "porting, and social engineering attacks. Disabling these methods "
            "forces users to adopt more secure authentication options."
        ),
        impact=(
            "Users currently using SMS or voice call for MFA must register a "
            "stronger method before the weak methods are disabled."
        ),
        audit_procedure=(
            "GET /policies/authenticationMethodsPolicy\n"
            "In authenticationMethodConfigurations:\n"
            "  Find SMS method (id = 'sms') - state should be 'disabled'\n"
            "  Find Voice method (id = 'voice') - state should be 'disabled'"
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Authentication methods.\n"
            "Disable SMS and Voice call methods.\n"
            "Ensure users have stronger methods registered before disabling."
        ),
        default_value="SMS and Voice authentication methods may be enabled.",
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
        tags=["identity", "mfa", "authentication-methods", "sms", "voice"],
    )

    async def check(self, data: CollectedData):
        auth_methods_policy = data.get("authentication_methods_policy")
        if auth_methods_policy is None:
            return self._skip(
                "Could not retrieve authentication methods policy. "
                "Requires Policy.Read.All permission."
            )

        auth_method_configs = auth_methods_policy.get("authenticationMethodConfigurations") or []

        # Find SMS and Voice configurations
        weak_methods_enabled = []
        for config in auth_method_configs:
            method_id = config.get("id", "").lower()
            state = config.get("state", "").lower()
            if method_id in ("sms", "voice") and state == "enabled":
                weak_methods_enabled.append(method_id)

        evidence = [
            Evidence(
                source="graph/policies/authenticationMethodsPolicy",
                data={
                    "weakMethodsEnabled": weak_methods_enabled,
                    "methodsChecked": ["sms", "voice"],
                },
                description="Authentication method states for weak methods.",
            )
        ]

        if not weak_methods_enabled:
            return self._pass(
                "Weak authentication methods (SMS, Voice) are disabled.",
                evidence=evidence,
            )

        return self._fail(
            f"Weak authentication method(s) are still enabled: {', '.join(weak_methods_enabled)}. "
            "These should be disabled in favor of stronger methods.",
            evidence=evidence,
        )
