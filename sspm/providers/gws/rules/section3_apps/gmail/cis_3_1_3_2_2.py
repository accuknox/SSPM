"""
CIS GWS 3.1.3.2.2 (L1) – Ensure the SPF record is configured for all
mail enabled domains (Automated)

Profile Applicability: Enterprise Level 1

Note: CIS marks this as Manual, but SPF records can be verified
automatically via DNS TXT record lookup.
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
class CIS_3_1_3_2_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.2.2",
        title="Ensure the SPF record is configured for all mail enabled domains",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "For all the email domains configured in Google Workspace, a corresponding "
            "Sender Policy Framework (SPF) record should be created.  SPF records "
            "allow Gmail and other mail systems to know where messages from your "
            "domains are allowed to originate."
        ),
        rationale=(
            "Without an SPF record, receiving mail servers cannot verify that email "
            "claiming to be from your domain actually originated from an authorised "
            "mail server.  This makes it easier for attackers to spoof your domain "
            "in phishing campaigns."
        ),
        impact=(
            "Minimal operational impact.  However, organisations should ensure proper "
            "SPF record setup as email could be flagged as spam if SPF is not set up "
            "appropriately."
        ),
        audit_procedure=(
            "Check the DNS TXT record for each domain:\n"
            "  dig TXT <domain>\n"
            "  or: nslookup -type=TXT <domain>\n\n"
            "A valid Google Workspace SPF record should include 'include:_spf.google.com':\n"
            "  v=spf1 include:_spf.google.com ~all"
        ),
        remediation=(
            "Add an SPF TXT record to the domain's DNS configuration:\n"
            "  v=spf1 include:_spf.google.com ~all\n\n"
            "If the domain also sends email via other services, add their SPF "
            "includes before the 'all' qualifier.  Use '~all' (softfail) initially "
            "and change to '-all' (hardfail) once confirmed working."
        ),
        default_value="SPF records are not automatically configured — must be added manually in DNS.",
        references=[
            "https://support.google.com/a/answer/33786",
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
        tags=["gmail", "spf", "email-security", "anti-spoofing", "dns"],
    )

    async def check(self, data: CollectedData):
        spf_data = data.get("dns_spf")
        if spf_data is None:
            return self._skip("SPF DNS data was not collected.")

        if not spf_data:
            return self._skip("No domains found to check SPF records.")

        missing = [domain for domain, record in spf_data.items() if not record]
        present = {domain: record for domain, record in spf_data.items() if record}

        evidence = [
            Evidence(
                source="dns.google/resolve (TXT)",
                data={"spf_records": spf_data},
                description="SPF TXT records for all verified domains.",
            )
        ]

        if missing:
            return self._fail(
                f"{len(missing)} domain(s) are missing SPF records: {', '.join(missing)}.",
                evidence=evidence,
            )

        return self._pass(
            f"All {len(present)} domain(s) have SPF records configured.",
            evidence=evidence,
        )
