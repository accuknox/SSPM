"""
CIS MS365 2.1.8 (L1) – Ensure that SPF records are published for all Exchange
Domains (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

An SPF record must be published for each verified domain used by Exchange Online.
"""

from __future__ import annotations

import httpx

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
class CIS_2_1_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.8",
        title="Ensure that SPF records are published for all Exchange Domains",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Sender Policy Framework (SPF) records specify which mail servers are "
            "authorized to send email on behalf of a domain. SPF records should be "
            "published for all Exchange Online verified domains."
        ),
        rationale=(
            "Without an SPF record, attackers can spoof the organization's domain "
            "in phishing emails. SPF records allow receiving mail servers to verify "
            "that email claiming to come from the domain was sent from an authorized server."
        ),
        impact=(
            "Incorrect SPF records can cause legitimate emails to be rejected. "
            "Ensure the SPF record includes all authorized sending sources before "
            "publishing."
        ),
        audit_procedure=(
            "For each verified domain:\n"
            "  1. Query DNS TXT records for the domain\n"
            "  2. Look for a record starting with 'v=spf1'\n"
            "  3. Verify it includes 'include:spf.protection.outlook.com'\n\n"
            "Using DNS-over-HTTPS:\n"
            "  GET https://dns.google/resolve?name={domain}&type=TXT"
        ),
        remediation=(
            "For each Exchange domain without an SPF record:\n"
            "  Add a DNS TXT record:\n"
            "  v=spf1 include:spf.protection.outlook.com -all\n\n"
            "This should be done through your domain registrar's DNS management."
        ),
        default_value="No SPF record is published by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure",
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
        tags=["dns", "spf", "email-authentication", "anti-spoofing"],
    )

    async def _check_spf(self, domain: str) -> dict:
        """Check SPF record for a domain via DNS-over-HTTPS."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": "TXT"},
                )
                resp.raise_for_status()
                data = resp.json()
                answers = data.get("Answer") or []
                for answer in answers:
                    txt = answer.get("data", "")
                    if "v=spf1" in txt:
                        return {
                            "domain": domain,
                            "has_spf": True,
                            "record": txt,
                            "has_outlook": "spf.protection.outlook.com" in txt,
                        }
                return {"domain": domain, "has_spf": False, "record": None}
        except Exception as exc:
            return {"domain": domain, "has_spf": False, "error": str(exc)}

    async def check(self, data: CollectedData):
        domains = data.get("domains")
        if not domains:
            return self._skip("Could not retrieve domains data.")

        # Only check verified domains (not onmicrosoft.com)
        exchange_domains = [
            d for d in domains
            if d.get("isVerified")
            and not d.get("name", "").endswith(".onmicrosoft.com")
        ]

        if not exchange_domains:
            return self._skip("No verified custom domains found to check SPF records.")

        results = []
        for domain_obj in exchange_domains:
            domain_name = domain_obj.get("name", "")
            spf_result = await self._check_spf(domain_name)
            results.append(spf_result)

        missing_spf = [r for r in results if not r.get("has_spf")]
        has_spf = [r for r in results if r.get("has_spf")]

        if not missing_spf:
            return self._pass(
                f"All {len(results)} verified domain(s) have SPF records published.",
                evidence=[
                    Evidence(
                        source="DNS TXT records (dns.google/resolve)",
                        data=has_spf,
                        description="SPF records found for all verified domains.",
                    )
                ],
            )

        return self._fail(
            f"{len(missing_spf)} domain(s) are missing SPF records: "
            + ", ".join(r["domain"] for r in missing_spf),
            evidence=[
                Evidence(
                    source="DNS TXT records (dns.google/resolve)",
                    data=results,
                    description="SPF check results per domain.",
                )
            ],
        )
