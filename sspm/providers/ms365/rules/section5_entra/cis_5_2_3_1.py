"""
CIS MS365 5.2.3.1 (L1) – Ensure Microsoft Authenticator MFA fatigue
protections are enabled (Automated)

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
class CIS_5_2_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.1",
        title="Ensure Microsoft Authenticator MFA fatigue protections are enabled",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Authenticator should be configured with MFA fatigue "
            "protections: number matching (shows a number the user must match) "
            "and additional context (shows application name and location). "
            "These features prevent MFA push bombing attacks."
        ),
        rationale=(
            "MFA fatigue attacks flood users with push notifications until they "
            "accidentally approve one. Number matching and additional context "
            "require users to actively verify the sign-in request, defeating "
            "these attacks."
        ),
        impact=(
            "Users will need to look at a number on the sign-in screen and enter "
            "it in the Authenticator app, adding a small amount of friction to MFA."
        ),
        audit_procedure=(
            "GET /policies/authenticationMethodsPolicy\n"
            "In authenticationMethodConfigurations:\n"
            "  Find microsoftAuthenticator method\n"
            "  Check featureSettings.numberMatchingRequiredState.state = 'enabled'\n"
            "  Check featureSettings.displayAppInformationRequiredState.state = 'enabled'"
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Microsoft Authenticator.\n"
            "Enable 'Require number matching' and 'Show additional context in notifications'.\n\n"
            "PATCH /policies/authenticationMethodsPolicy\n"
            "  Update microsoftAuthenticator configuration with "
            "numberMatchingRequiredState = enabled"
        ),
        default_value="Number matching may be enabled but additional context may not be.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match",
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
        tags=["identity", "mfa", "authenticator", "mfa-fatigue", "number-matching"],
    )

    async def check(self, data: CollectedData):
        auth_methods_policy = data.get("authentication_methods_policy")
        if auth_methods_policy is None:
            return self._skip(
                "Could not retrieve authentication methods policy. "
                "Requires Policy.Read.All permission."
            )

        # Find Microsoft Authenticator configuration
        auth_method_configs = auth_methods_policy.get("authenticationMethodConfigurations") or []
        ms_auth_config = None
        for config in auth_method_configs:
            if config.get("@odata.type", "").lower().endswith("microsoftauthenticatorauthenticationmethodconfiguration"):
                ms_auth_config = config
                break
            if config.get("id", "").lower() == "microsoftauthenticator":
                ms_auth_config = config
                break

        if ms_auth_config is None:
            return self._skip("Microsoft Authenticator method configuration not found.")

        feature_settings = ms_auth_config.get("featureSettings") or {}
        number_match = feature_settings.get("numberMatchingRequiredState") or {}
        display_app_info = feature_settings.get("displayAppInformationRequiredState") or {}

        number_match_state = number_match.get("state", "").lower()
        display_app_info_state = display_app_info.get("state", "").lower()

        is_enabled = ms_auth_config.get("state", "").lower() == "enabled"

        issues = []
        if not is_enabled:
            issues.append("Microsoft Authenticator is not enabled")
        if number_match_state not in ("enabled", "microsoftenabled"):
            issues.append(f"Number matching state = '{number_match_state}' (should be 'enabled')")
        if display_app_info_state not in ("enabled", "microsoftenabled"):
            issues.append(f"Additional context (displayAppInfo) state = '{display_app_info_state}' (should be 'enabled')")

        evidence = [
            Evidence(
                source="graph/policies/authenticationMethodsPolicy",
                data={
                    "state": ms_auth_config.get("state"),
                    "numberMatchingRequiredState": number_match_state,
                    "displayAppInformationRequiredState": display_app_info_state,
                },
                description="Microsoft Authenticator method configuration.",
            )
        ]

        if not issues:
            return self._pass(
                "Microsoft Authenticator MFA fatigue protections are enabled "
                "(number matching + additional context).",
                evidence=evidence,
            )

        return self._fail(
            "Microsoft Authenticator MFA fatigue protections are not fully enabled: "
            + "; ".join(issues),
            evidence=evidence,
        )
