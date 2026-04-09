"""
CIS MS365 5.2.2.4 (L2) – Ensure sign-in frequency and no persistent browser
sessions for admins (Automated)

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


@registry.rule
class CIS_5_2_2_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.4",
        title="Ensure sign-in frequency and persistent browser session for admins is configured",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Administrative accounts should have a sign-in frequency policy that "
            "requires re-authentication after a set period (e.g., every hour) and "
            "should not allow persistent browser sessions."
        ),
        rationale=(
            "Limiting session lifetime for admins reduces the risk of session "
            "hijacking. Short sign-in frequency ensures admins frequently "
            "re-authenticate, reducing the window of opportunity for attackers."
        ),
        impact=(
            "Administrative users will be required to re-authenticate more "
            "frequently and browser sessions will not persist, requiring "
            "re-authentication when reopening the browser."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy targeting admin roles with:\n"
            "  • sessionControls.signInFrequency.isEnabled = true\n"
            "  • sessionControls.persistentBrowser.isEnabled = true (and mode = never)"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Target: Admin directory roles\n"
            "  2. Session: Sign-in frequency = every 1 hour\n"
            "  3. Session: Persistent browser session = never persistent\n"
            "  4. Enable the policy"
        ),
        default_value="No session frequency restriction on admin sessions by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.3",
                title="Configure Automatic Session Locking on Enterprise Assets",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "session", "admin", "sign-in-frequency"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        session_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            session_controls = policy.get("sessionControls") or {}
            sign_in_freq = session_controls.get("signInFrequency") or {}

            if not sign_in_freq.get("isEnabled"):
                continue

            # Check if it targets admin roles
            conditions = policy.get("conditions") or {}
            users_cond = conditions.get("users") or {}
            include_roles = users_cond.get("includeRoles") or []
            include_users = users_cond.get("includeUsers") or []

            targets_admins = len(include_roles) > 0 or "All" in include_users

            if targets_admins:
                session_policy = policy
                break

        if session_policy:
            session_controls = session_policy.get("sessionControls") or {}
            return self._pass(
                f"Conditional Access policy '{session_policy.get('displayName')}' "
                "configures sign-in frequency for admin sessions.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": session_policy.get("id"),
                            "displayName": session_policy.get("displayName"),
                            "sessionControls": session_controls,
                        },
                        description="CA policy with session controls for admins.",
                    )
                ],
            )

        return self._fail(
            "No enabled Conditional Access policy with sign-in frequency configured "
            f"for admin roles found. Reviewed {len(policies)} policies.",
        )
