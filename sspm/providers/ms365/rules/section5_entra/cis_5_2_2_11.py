"""
CIS MS365 5.2.2.11 (L2) – Ensure sign-in frequency for Intune Enrollment is
set to every time (Automated)

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

# Microsoft Intune Enrollment app ID
_INTUNE_ENROLLMENT_APP_ID = "d4ebce55-015a-49b5-a083-c84d1797ae8c"


@registry.rule
class CIS_5_2_2_11(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.11",
        title="Ensure sign-in frequency for Intune Enrollment is set to every time",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "A Conditional Access policy should require re-authentication every "
            "time for Microsoft Intune Enrollment to prevent device enrollment "
            "from cached credentials."
        ),
        rationale=(
            "Requiring authentication at every Intune enrollment prevents enrollment "
            "using cached or stolen credentials, ensuring only the legitimate device "
            "owner can enroll their device."
        ),
        impact=(
            "Users must authenticate each time they enroll a device in Intune. "
            "This prevents bulk enrollment without active user consent."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy that:\n"
            "  • targets Intune Enrollment app (d4ebce55-015a-49b5-a083-c84d1797ae8c)\n"
            "  • sessionControls.signInFrequency.type = 'everyTime'"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Target resources: Select apps > Microsoft Intune Enrollment\n"
            "  2. Session: Sign-in frequency = Every time\n"
            "  3. Enable the policy"
        ),
        default_value="No sign-in frequency for Intune enrollment by default.",
        references=[
            "https://learn.microsoft.com/en-us/intune/intune-service/enrollment/multi-factor-authentication",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.1",
                title="Establish and Maintain a Secure Configuration Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "intune", "enrollment", "sign-in-frequency"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        intune_freq_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            conditions = policy.get("conditions") or {}
            apps_cond = conditions.get("applications") or {}
            include_apps = apps_cond.get("includeApplications") or []

            if _INTUNE_ENROLLMENT_APP_ID not in include_apps and "All" not in include_apps:
                continue

            session_controls = policy.get("sessionControls") or {}
            sign_in_freq = session_controls.get("signInFrequency") or {}
            freq_type = sign_in_freq.get("type", "")
            freq_enabled = sign_in_freq.get("isEnabled", False)

            if freq_enabled and freq_type.lower() in ("everytime", "every_time"):
                intune_freq_policy = policy
                break

        if intune_freq_policy:
            return self._pass(
                f"Policy '{intune_freq_policy.get('displayName')}' requires "
                "re-authentication every time for Intune enrollment.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": intune_freq_policy.get("id"),
                            "displayName": intune_freq_policy.get("displayName"),
                        },
                        description="CA policy with everyTime sign-in frequency for Intune.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy with 'every time' sign-in frequency for Intune enrollment found. "
            f"Reviewed {len(policies)} policies.",
        )
