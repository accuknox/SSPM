"""CIS Azure 5.1.4 – Ensure that 'Allow users to remember multifactor authentication on devices they trust' is Disabled (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_1_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.1.4",
        title="Ensure that 'Allow users to remember multifactor authentication on devices they trust' is Disabled",
        section="5.1 Security Defaults (Per-User MFA)",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "The 'remember MFA' feature allows users to bypass MFA challenges for a configurable "
            "number of days on devices they mark as trusted. Disabling this feature ensures MFA "
            "is enforced on every sign-in."
        ),
        rationale=(
            "When MFA is remembered on a trusted device, a stolen device can be used without "
            "re-authenticating with a second factor for the duration of the trust period, "
            "undermining the protection that MFA provides."
        ),
        impact=(
            "Users must complete MFA on every sign-in. This may increase friction but ensures "
            "consistent enforcement of multi-factor authentication."
        ),
        audit_procedure=(
            "Entra admin center → Users → Per-user MFA → Service settings → "
            "Allow users to remember multifactor authentication on devices they trust: "
            "verify the option is unchecked/disabled."
        ),
        remediation=(
            "Entra admin center → Users → Per-user MFA → Service settings → "
            "uncheck 'Allow users to remember multifactor authentication on devices they trust' → Save."
        ),
        default_value="Disabled by default; some tenants may have enabled it as a convenience measure.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.3", title="Require MFA for Externally-Exposed Applications", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "The 'remember MFA on trusted devices' setting is not accessible via Graph application "
            "permissions; verify manually via Entra admin center → Users → Per-user MFA → "
            "Service settings."
        )
