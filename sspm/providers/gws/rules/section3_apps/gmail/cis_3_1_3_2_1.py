"""
CIS GWS 3.1.3.2.1 (L1) – Ensure that DKIM is enabled for all mail
enabled domains (Automated)

Profile Applicability: Enterprise Level 1

Note: CIS marks this as Manual, but the DKIM public key can be verified
automatically via DNS TXT record lookup (google._domainkey.<domain>).
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
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_3_1_3_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.2.1",
        title="Ensure that DKIM is enabled for all mail enabled domains",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "DKIM adds an encrypted signature to the header of all outgoing messages. "
            "Email servers that get signed messages use DKIM to decrypt the message "
            "header, and verify the message was not changed after it was sent.  DKIM "
            "should be configured for all Google Workspace domains."
        ),
        rationale=(
            "Spoofing is a common unauthorised use of email, so some email servers "
            "require DKIM to prevent email spoofing.  DKIM is a critical component "
            "alongside SPF and DMARC."
        ),
        impact=(
            "There should be no impact of setting up DKIM; however, organisations "
            "should ensure appropriate setup to ensure continuous mail-flow."
        ),
        audit_procedure=(
            "Check the DKIM TXT record in DNS for each domain:\n"
            "  dig TXT google._domainkey.<domain>\n\n"
            "A valid Google DKIM record starts with 'v=DKIM1' and contains a "
            "public key prefixed with 'p='.\n\n"
            "Also verify DKIM signing is enabled in Admin Console:\n"
            "  Apps → Google Workspace → Gmail → Authenticate email → DKIM"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Navigate to Apps → Google Workspace → Gmail\n"
            "  2. Select 'Authenticate email'\n"
            "  3. For each domain, click 'Generate new record'\n"
            "  4. Under Select DKIM key bit length, select the appropriate key "
            "bit length (2048 is recommended if supported)\n"
            "  5. Under Prefix selector (optional), enter the appropriate prefix "
            "selector\n"
            "  6. Use the text at TXT record value to update the DNS record at "
            "your domain host\n"
            "  7. Click 'Start Authentication'\n\n"
            "DNS changes may take up to 48 hours to propagate."
        ),
        default_value="DKIM is not configured by default — requires explicit setup.",
        references=[
            "https://support.google.com/a/answer/174124",
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
        tags=["gmail", "dkim", "email-security", "anti-spoofing", "dns"],
    )

    async def check(self, data: CollectedData):
        dkim_data = data.get("dns_dkim")
        if dkim_data is None:
            return self._skip("DKIM DNS data was not collected.")

        if not dkim_data:
            return self._skip("No domains found to check DKIM records.")

        missing = [domain for domain, record in dkim_data.items() if not record]
        present = {domain: record for domain, record in dkim_data.items() if record}

        evidence = [
            Evidence(
                source="dns.google/resolve (TXT) — google._domainkey.<domain>",
                data={"dkim_records": {d: bool(r) for d, r in dkim_data.items()}},
                description="DKIM TXT records (google._domainkey) for all verified domains.",
            )
        ]

        if missing:
            return self._fail(
                f"{len(missing)} domain(s) are missing Google DKIM records "
                f"(google._domainkey): {', '.join(missing)}.",
                evidence=evidence,
            )

        return self._pass(
            f"All {len(present)} domain(s) have DKIM records configured.",
            evidence=evidence,
        )
