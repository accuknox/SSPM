"""CIS Azure 5.1.3 – Ensure 'multifactor authentication' is 'enabled' For All Users (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
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
        assessment_status=AssessmentStatus.MANUAL,
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
        # Per-user MFA state is only accessible via legacy MSOnline / Graph beta endpoints that
        # require DelegatedAuthentication.ReadWrite.All and an admin user context.
        return self._manual(
            "Per-user MFA state is not exposed through Graph application permissions; "
            "verify manually via Entra admin center → Users → Per-user MFA."
        )
