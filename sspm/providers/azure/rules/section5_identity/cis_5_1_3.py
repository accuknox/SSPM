"""CIS Azure 5.1.3 – Ensure 'multifactor authentication' is 'enabled' For All Users (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_1_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.1.3",
        title="Ensure that 'multifactor authentication' is 'enabled' for all users",
        section="5.1 Security Defaults (Per-User MFA)",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Enable per-user multifactor authentication for all users. Since 2024 Azure is rolling "
            "out mandatory multifactor authentication for sign-ins to Azure portal, CLI, and "
            "PowerShell."
        ),
        rationale=(
            "MFA requires an individual to present a minimum of two separate forms of "
            "authentication. An attacker compromising a password must also compromise a second "
            "factor, sharply increasing the cost of account takeover."
        ),
        impact="Users and admins need a second factor; plan device enrollment before enforcement.",
        audit_procedure=(
            "Entra admin center → Users → Per-user MFA: verify Status is 'enabled' for all users."
        ),
        remediation=(
            "Enable per-user MFA for every user, or (preferred) enforce MFA via a Conditional "
            "Access policy targeting all users."
        ),
        default_value="Per-user MFA is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.3", title="Require MFA for Externally-Exposed Applications", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        # Direct per-user MFA state requires AuditLog.Read.All which is not available under
        # application permissions. Use Security Defaults as an authoritative proxy: when enabled,
        # Microsoft enforces MFA for all users on the tenant.
        security_defaults = data.get("security_defaults")
        if security_defaults is None:
            return self._skip("Security defaults policy could not be retrieved.")

        sd_enabled = security_defaults.get("isEnabled", False)
        evidence = [Evidence(
            source="graph:identitySecurityDefaultsEnforcementPolicy",
            data={"security_defaults_enabled": sd_enabled},
        )]

        if sd_enabled:
            return self._pass(
                "Security Defaults is enabled — MFA is enforced for all users by Microsoft.",
                evidence=evidence,
            )

        return self._skip(
            "Security Defaults is disabled and per-user MFA state requires AuditLog.Read.All "
            "to enumerate directly. Verify via Entra admin center → Users → Per-user MFA, "
            "or ensure a Conditional Access policy enforces MFA for all users.",
        )
