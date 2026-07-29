"""
CIS MS365 5.2.3.6 (L1) – Ensure system-preferred MFA is enabled (Automated)

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
class CIS_5_2_3_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.6",
        title="Ensure system-preferred MFA is enabled",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "System-preferred MFA (credential preferences) should be enabled to "
            "ensure users are prompted to use the most secure MFA method they have "
            "registered, rather than a weaker method they may prefer."
        ),
        rationale=(
            "Users may have both weak (SMS) and strong (Authenticator) MFA methods "
            "registered. System-preferred MFA ensures the system prompts for the "
            "strongest available method rather than deferring to user preference."
        ),
        impact=(
            "Users may be prompted for a different MFA method than they are "
            "accustomed to using."
        ),
        audit_procedure=(
            "GET /beta/policies/authenticationMethodsPolicy\n"
            "(Invoke-MgGraphRequest ...).systemCredentialPreferences\n"
            "Ensure includeTargets contains 'all_users' and state is 'enabled'."
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Authentication methods policy.\n"
            "Enable 'System-preferred multifactor authentication'."
        ),
        default_value="System-preferred MFA state may vary by tenant.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-preferred-multifactor-authentication",
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
        tags=["identity", "mfa", "system-preferred", "authentication-methods"],
    )

    async def check(self, data: CollectedData):
        auth_methods_policy = data.get("authentication_methods_policy")
        if auth_methods_policy is None:
            return self._skip(
                "Could not retrieve authentication methods policy. "
                "Requires Policy.Read.All permission."
            )

        sys_cred_prefs = auth_methods_policy.get("systemCredentialPreferences") or {}
        state = (sys_cred_prefs.get("state") or "").lower()
        include_targets = sys_cred_prefs.get("includeTargets") or []
        includes_all_users = any(
            t.get("id") == "all_users" for t in include_targets
        )

        evidence = [
            Evidence(
                source="graph/beta/policies/authenticationMethodsPolicy",
                data={
                    "systemCredentialPreferences.state": state,
                    "includeTargets": include_targets,
                },
                description="System credential preferences configuration.",
            )
        ]

        if state == "enabled" and includes_all_users:
            return self._pass(
                "System-preferred MFA is enabled for all users.",
                evidence=evidence,
            )

        if state == "disabled":
            return self._fail(
                "System-preferred MFA is disabled. Users may be prompted for weaker MFA methods.",
                evidence=evidence,
            )

        if state == "enabled" and not includes_all_users:
            return self._fail(
                "System-preferred MFA is enabled but not scoped to all users "
                "(includeTargets does not contain 'all_users').",
                evidence=evidence,
            )

        if state == "default":
            # "default" means "Microsoft managed" — the tenant admin has never
            # explicitly turned this on. CIS's audit procedure requires state
            # to literally be 'enabled', so an unconfigured/Microsoft-managed
            # state does not satisfy that, regardless of what Microsoft's
            # current rollout default happens to resolve to internally.
            return self._fail(
                "System-preferred MFA state is 'default' (Microsoft managed) — "
                "it has not been explicitly enabled by the tenant admin, so "
                "this control is not satisfied.",
                evidence=evidence,
            )

        return self._skip(
            f"System-preferred MFA state is '{state}'."
        )
