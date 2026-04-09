"""
CIS MS365 2.1.9 (L1) – Ensure that DKIM is enabled for all Exchange Online
Domains (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

DKIM (DomainKeys Identified Mail) adds a digital signature to outbound email,
allowing receiving servers to verify the email originated from an authorised
sender.  Without DKIM, spoofed email appears more legitimate.
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
class CIS_2_1_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.9",
        title="Ensure that DKIM is enabled for all Exchange Online Domains",
        section="2.1 Email & collaboration",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "DomainKeys Identified Mail (DKIM) should be enabled for all Exchange "
            "Online domains to digitally sign outbound mail and prevent spoofing. "
            "DKIM is a critical component of an email authentication stack alongside "
            "SPF and DMARC."
        ),
        rationale=(
            "Without DKIM, attackers can more easily spoof your domain to send "
            "fraudulent emails that appear legitimate to recipients.  DKIM signing "
            "also provides non-repudiation for outbound messages."
        ),
        impact=(
            "Minimal operational impact.  Some third-party email services that send on "
            "behalf of your domain may need DKIM key updates."
        ),
        audit_procedure=(
            "Using Microsoft Graph domains API:\n"
            "  GET /domains\n"
            "  For each verified domain, check the DKIM signing status via:\n"
            "  Exchange Online PowerShell: Get-DkimSigningConfig | "
            "Select-Object Domain, Enabled\n"
            "  All domains should have Enabled = True.\n\n"
            "Note: The Graph API does not expose DKIM configuration directly. "
            "Full automated verification requires Exchange Online PowerShell or "
            "the Exchange Online REST API."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Enable-DkimSigning -DomainName <domain>\n\n"
            "Or via Defender portal:\n"
            "  Microsoft Defender portal → Email & collaboration > Policies & rules > "
            "Threat policies > Email authentication settings > DKIM.\n"
            "  Enable signing for each domain."
        ),
        default_value="DKIM is enabled by default for .onmicrosoft.com but not custom domains.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/enable-dkimsigning",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.5",
                title="Implement DMARC",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["email", "dkim", "anti-spoofing", "defender"],
    )

    async def check(self, data: CollectedData):
        domains = data.get("domains")
        if domains is None:
            return self._skip("Could not retrieve domain data.")

        verified_custom = [
            d for d in domains
            if d.get("isVerified") and not d.get("id", "").endswith(".onmicrosoft.com")
        ]

        if not verified_custom:
            return self._pass(
                "No custom verified domains found. "
                "DKIM is enabled by default for .onmicrosoft.com domains."
            )

        # DKIM config is not available via Graph v1.0; we flag for manual follow-up
        # with available domain inventory.
        return self._manual(
            message=(
                f"Found {len(verified_custom)} custom domain(s): "
                + ", ".join(d.get("id", "") for d in verified_custom)
                + ". DKIM signing status must be verified via Exchange Online "
                "PowerShell: Get-DkimSigningConfig | Select-Object Domain, Enabled"
            ),
        )
