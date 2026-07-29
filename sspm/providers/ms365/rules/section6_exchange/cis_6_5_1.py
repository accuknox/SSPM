"""
CIS MS365 6.5.1 (L1) – Ensure modern authentication for Exchange Online is
enabled (Automated)

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
class CIS_6_5_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.5.1",
        title="Ensure modern authentication for Exchange Online is enabled",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Modern authentication (OAuth 2.0) for Exchange Online should be "
            "enabled to allow MFA and Conditional Access policies to apply to "
            "email clients. Without modern auth, older clients use Basic Authentication "
            "which cannot enforce MFA."
        ),
        rationale=(
            "Modern authentication enables MFA, Conditional Access, and other "
            "advanced security features for Exchange Online connections. Basic "
            "Authentication bypasses these controls."
        ),
        impact="Older email clients that only support Basic Auth will not be able to connect.",
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /admin/exchange/settings\n"
            "  Check: isModernAuthentication = true\n\n"
            "Or Exchange Online PowerShell:\n"
            "  Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-OrganizationConfig -OAuth2ClientProfileEnabled $true"
        ),
        default_value="Modern authentication is enabled by default in Exchange Online.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online",
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
        tags=["exchange", "modern-auth", "oauth", "mfa"],
    )

    async def check(self, data: CollectedData):
        # Get-OrganizationConfig has no Microsoft Graph equivalent; it is only
        # reachable via Exchange Online Remote PowerShell.
        if "organization_config" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange organization configuration: "
                f"{data.errors.get('organization_config')}"
            )

        org_config = data.get("organization_config")
        if org_config is None:
            return self._skip(
                "OAuth2ClientProfileEnabled requires the Exchange Online "
                "PowerShell bridge (Connect-ExchangeOnline with certificate "
                "or access-token app-only auth), which is not configured "
                "for this scan. Verify manually: Get-OrganizationConfig | "
                "Select-Object OAuth2ClientProfileEnabled - must be True."
            )

        modern_auth_enabled = org_config.get("OAuth2ClientProfileEnabled")
        evidence = [
            Evidence(
                source="Get-OrganizationConfig",
                data={"OAuth2ClientProfileEnabled": modern_auth_enabled},
                description="Whether modern authentication (OAuth 2.0) is enabled for Exchange Online.",
            )
        ]

        if modern_auth_enabled:
            return self._pass(
                "OAuth2ClientProfileEnabled is True; modern authentication "
                "for Exchange Online is enabled.",
                evidence=evidence,
            )

        return self._fail(
            "OAuth2ClientProfileEnabled is False; modern authentication for "
            "Exchange Online is disabled, allowing Basic Authentication "
            "which bypasses MFA and Conditional Access.",
            evidence=evidence,
        )
