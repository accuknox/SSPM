"""
CIS MS365 2.1.10 (L1) – Ensure DMARC Records for all Exchange Online Domains
are Published (Automated)

Profile Applicability: E3 Level 1, E5 Level 1
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
class CIS_2_1_10(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.10",
        title="Ensure DMARC Records for all Exchange Online Domains are Published",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Domain-based Message Authentication, Reporting, and Conformance (DMARC) "
            "records should be published for all Exchange Online verified domains. "
            "DMARC builds on SPF and DKIM to give email receivers instructions on "
            "how to handle emails that fail authentication."
        ),
        rationale=(
            "DMARC prevents domain spoofing by telling receiving mail servers what "
            "to do with email that fails SPF and DKIM checks. A DMARC policy of "
            "'reject' or 'quarantine' prevents spoofed emails from reaching recipients."
        ),
        impact=(
            "Incorrect DMARC policies can cause legitimate emails to be rejected. "
            "Start with 'p=none' for monitoring before moving to 'p=quarantine' "
            "or 'p=reject'."
        ),
        audit_procedure=(
            "For each verified domain:\n"
            "  1. Query DNS TXT records for _dmarc.{domain}\n"
            "  2. Look for a record starting with 'v=DMARC1'\n"
            "  3. Check the policy (p=) value\n\n"
            "Using DNS-over-HTTPS:\n"
            "  GET https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
        ),
        remediation=(
            "For each domain without a DMARC record:\n"
            "  Add a DNS TXT record for _dmarc.{domain}:\n"
            "  v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com\n\n"
            "Start with p=none for monitoring, then move to p=quarantine, then p=reject."
        ),
        default_value="No DMARC record is published by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure",
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
        tags=["dns", "dmarc", "email-authentication", "anti-spoofing"],
    )

    async def _check_dmarc(self, domain: str) -> dict:
        """Check DMARC record for a domain via DNS-over-HTTPS."""
        dmarc_domain = f"_dmarc.{domain}"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://dns.google/resolve",
                    params={"name": dmarc_domain, "type": "TXT"},
                )
                resp.raise_for_status()
                data = resp.json()
                answers = data.get("Answer") or []
                for answer in answers:
                    txt = answer.get("data", "")
                    if "v=DMARC1" in txt:
                        # Extract policy value
                        policy = "none"
                        for part in txt.split(";"):
                            part = part.strip()
                            if part.startswith("p="):
                                policy = part[2:]
                        return {
                            "domain": domain,
                            "has_dmarc": True,
                            "record": txt,
                            "policy": policy,
                            "is_enforced": policy in ("quarantine", "reject"),
                        }
                return {"domain": domain, "has_dmarc": False, "record": None}
        except Exception as exc:
            return {"domain": domain, "has_dmarc": False, "error": str(exc)}

    async def check(self, data: CollectedData):
        domains = data.get("domains")
        if not domains:
            return self._skip("Could not retrieve domains data.")

        exchange_domains = [
            d for d in domains
            if d.get("isVerified")
            and not d.get("name", "").endswith(".onmicrosoft.com")
        ]

        if not exchange_domains:
            return self._skip("No verified custom domains found to check DMARC records.")

        results = []
        for domain_obj in exchange_domains:
            domain_name = domain_obj.get("name", "")
            dmarc_result = await self._check_dmarc(domain_name)
            results.append(dmarc_result)

        missing_dmarc = [r for r in results if not r.get("has_dmarc")]
        not_enforced = [
            r for r in results if r.get("has_dmarc") and not r.get("is_enforced")
        ]

        if not missing_dmarc and not not_enforced:
            return self._pass(
                f"All {len(results)} verified domain(s) have enforced DMARC records.",
                evidence=[
                    Evidence(
                        source="DNS TXT records (dns.google/resolve)",
                        data=results,
                        description="DMARC records found and enforced for all domains.",
                    )
                ],
            )

        issues = []
        if missing_dmarc:
            issues.append(
                f"{len(missing_dmarc)} domain(s) missing DMARC: "
                + ", ".join(r["domain"] for r in missing_dmarc)
            )
        if not_enforced:
            issues.append(
                f"{len(not_enforced)} domain(s) have DMARC policy=none (not enforced): "
                + ", ".join(r["domain"] for r in not_enforced)
            )

        return self._fail(
            "DMARC issues found: " + "; ".join(issues),
            evidence=[
                Evidence(
                    source="DNS TXT records (dns.google/resolve)",
                    data=results,
                    description="DMARC check results per domain.",
                )
            ],
        )
