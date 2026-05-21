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
        # Try to get Exchange settings via Graph API
        org = data.get("organization")
        if org:
            # The organization object doesn't directly expose OAuth settings
            # but we can note this
            pass

        # We'll check via a manual approach since the exchange settings
        # endpoint requires specific permissions
        return self._manual()
