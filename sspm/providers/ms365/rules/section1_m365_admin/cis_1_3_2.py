"""
CIS MS365 1.3.2 (L2) – Ensure idle session timeout for unmanaged devices is
set to 3 hours or less (Automated)

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

_MAX_TIMEOUT_SECONDS = 3 * 60 * 60  # 3 hours in seconds


@registry.rule
class CIS_1_3_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.2",
        title="Ensure idle session timeout for unmanaged devices is set to 3 hours or less",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Configuring an idle session timeout for unmanaged devices ensures "
            "that browser sessions on shared or unmanaged devices are automatically "
            "signed out after a period of inactivity, reducing the risk of "
            "unauthorized access."
        ),
        rationale=(
            "Unmanaged devices may be used in shared environments (kiosks, shared "
            "PCs). Idle session timeouts ensure active sessions are terminated "
            "after inactivity, preventing unauthorized access to M365 services."
        ),
        impact=(
            "Users on unmanaged devices will be signed out after the configured "
            "idle period, requiring re-authentication."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/activityBasedTimeoutPolicies\n"
            "  Review each policy's definition property for web session timeout.\n"
            "  The timeout should be ≤ PT3H (3 hours) for web sessions."
        ),
        remediation=(
            "Microsoft 365 admin center → Security & privacy → Idle session timeout.\n"
            "Enable idle session timeout and set to 3 hours or less for unmanaged devices.\n\n"
            "Or via Microsoft Entra admin center → Identity > Overview > Properties > "
            "Manage security defaults or Conditional Access."
        ),
        default_value="No idle session timeout configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/idle-session-timeout-web-apps",
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
        tags=["session", "timeout", "unmanaged-devices", "identity"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("activity_based_timeout_policies")
        if policies is None:
            return self._skip(
                "Could not retrieve activity-based timeout policies. "
                "Requires Policy.Read.All permission."
            )

        if not policies:
            return self._fail(
                "No activity-based timeout policies found. Idle session timeout "
                "for unmanaged devices is not configured.",
                evidence=[
                    Evidence(
                        source="graph/policies/activityBasedTimeoutPolicies",
                        data=[],
                        description="No timeout policies found.",
                    )
                ],
            )

        # Check if any enabled policy has a web session timeout <= 3h
        compliant_policy = None
        for policy in policies:
            if not policy.get("isOrganizationDefault", False) and not policy.get("id"):
                continue
            definitions = policy.get("definition") or []
            for defn in definitions:
                if isinstance(defn, str):
                    import json
                    try:
                        defn = json.loads(defn)
                    except Exception:
                        continue
                timeout_str = (
                    defn.get("ActivityBasedAuthenticationTimeoutPolicy", {})
                    .get("WebSessionIdleTimeout", "")
                )
                # Parse ISO 8601 duration (e.g. PT1H, PT3H)
                if timeout_str:
                    hours = 0
                    minutes = 0
                    import re
                    h_match = re.search(r"(\d+)H", timeout_str)
                    m_match = re.search(r"(\d+)M", timeout_str)
                    if h_match:
                        hours = int(h_match.group(1))
                    if m_match:
                        minutes = int(m_match.group(1))
                    total_seconds = hours * 3600 + minutes * 60
                    if 0 < total_seconds <= _MAX_TIMEOUT_SECONDS:
                        compliant_policy = {
                            "displayName": policy.get("displayName"),
                            "timeout": timeout_str,
                        }
                        break
            if compliant_policy:
                break

        if compliant_policy:
            return self._pass(
                f"Activity-based timeout policy '{compliant_policy['displayName']}' "
                f"sets idle session timeout to {compliant_policy['timeout']} (≤3h).",
                evidence=[
                    Evidence(
                        source="graph/policies/activityBasedTimeoutPolicies",
                        data=compliant_policy,
                        description="Compliant idle session timeout policy found.",
                    )
                ],
            )

        return self._fail(
            "No activity-based timeout policy with a web session timeout ≤ 3 hours found.",
            evidence=[
                Evidence(
                    source="graph/policies/activityBasedTimeoutPolicies",
                    data=policies,
                    description="Existing timeout policies (none meet the 3-hour requirement).",
                )
            ],
        )
