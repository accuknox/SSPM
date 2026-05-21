"""CIS Azure 5.1.1 – Ensure 'security defaults' is Enabled in Microsoft Entra ID (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_1_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.1.1",
        title="Ensure that 'security defaults' is Enabled in Microsoft Entra ID",
        section="5.1 Security Defaults (Per-User MFA)",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Security defaults in Microsoft Entra ID make it easier to be secure and help "
            "protect your organization with preconfigured security settings for common attacks."
        ),
        rationale=(
            "Security defaults require all users and admins to register for MFA, challenge users "
            "with MFA based on risk factors, and disable legacy authentication. Tenants on the "
            "free Entra ID tier (no Conditional Access) rely on this baseline to prevent common "
            "identity attacks."
        ),
        impact=(
            "Tenants licensed for Microsoft Entra ID P1/P2 should bypass this and use Conditional "
            "Access instead. Enabling security defaults may impact legacy auth workflows."
        ),
        audit_procedure=(
            "Microsoft Graph: GET /policies/identitySecurityDefaultsEnforcementPolicy\n"
            "Verify that ``isEnabled`` is ``true``."
        ),
        remediation=(
            "Entra admin center → Identity → Overview → Properties → Manage security defaults → "
            "Security defaults = Enabled (recommended) → Save."
        ),
        default_value="Tenants created on or after 22 Oct 2019 have security defaults enabled.",
        references=[
            "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.3", title="Require MFA for Externally-Exposed Applications", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.5", title="Require MFA for Administrative Access", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        policy = data.get("security_defaults")
        if policy is None:
            return self._skip("Security defaults policy could not be retrieved from Graph.")

        enabled = bool(policy.get("isEnabled"))
        evidence = [Evidence(
            source="graph:/policies/identitySecurityDefaultsEnforcementPolicy",
            data={"isEnabled": enabled},
        )]
        if enabled:
            return self._pass("Security defaults are enabled.", evidence=evidence)
        return self._fail(
            "Security defaults are disabled. Enable them (or configure equivalent Conditional "
            "Access policies if licensed for Entra ID P1/P2).",
            evidence=evidence,
        )
