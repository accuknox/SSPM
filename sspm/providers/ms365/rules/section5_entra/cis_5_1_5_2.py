"""
CIS MS365 5.1.5.2 (L1) – Ensure the admin consent workflow is enabled
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
class CIS_5_1_5_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.5.2",
        title="Ensure the admin consent workflow is enabled",
        section="5.1.5 Applications",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The admin consent workflow should be enabled to allow users to request "
            "admin approval for applications they need. Without this workflow, users "
            "may try to work around consent restrictions."
        ),
        rationale=(
            "When user consent is disabled, users still need to use applications. "
            "The admin consent workflow provides a formal process for users to "
            "request access, maintaining security while avoiding friction."
        ),
        impact=(
            "Users will be able to submit requests for application consent to "
            "administrators. Admins will need to review and approve or deny requests."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/adminConsentRequestPolicy\n"
            "  Check: isEnabled = true"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Enterprise applications > "
            "Consent and permissions > Admin consent settings.\n"
            "Enable 'Users can request admin consent to apps they are unable to "
            "consent to' and configure reviewers."
        ),
        default_value="Admin consent workflow is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow",
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
        tags=["identity", "apps", "consent", "admin-workflow"],
    )

    async def check(self, data: CollectedData):
        admin_consent_policy = data.get("admin_consent_request_policy")
        if admin_consent_policy is None:
            return self._skip(
                "Could not retrieve admin consent request policy. "
                "Requires Policy.Read.All permission (beta)."
            )

        is_enabled = admin_consent_policy.get("isEnabled")

        evidence = [
            Evidence(
                source="graph/beta/policies/adminConsentRequestPolicy",
                data={"isEnabled": is_enabled},
                description="Admin consent request policy status.",
            )
        ]

        if is_enabled is True:
            return self._pass(
                "Admin consent workflow is enabled (isEnabled = true).",
                evidence=evidence,
            )

        return self._fail(
            "Admin consent workflow is disabled (isEnabled = false). "
            "Users cannot request admin approval for applications.",
            evidence=evidence,
        )
