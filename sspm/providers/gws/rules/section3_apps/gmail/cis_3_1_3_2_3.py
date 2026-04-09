"""
CIS GWS 3.1.3.2.3 (L1) – Ensure the DMARC record is configured for all
mail enabled domains (Automated)

Profile Applicability: Enterprise Level 1

Note: CIS marks this as Manual, but DMARC records and policy strength
can be verified automatically via DNS TXT record lookup.
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
class CIS_3_1_3_2_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.2.3",
        title="Ensure the DMARC record is configured for all mail enabled domains",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "For all email domains configured in Google Workspace, a corresponding "
            "Domain-Based Message Authentication, Reporting and Conformance (DMARC) "
            "record should be created.  DMARC works with SPF and DKIM to authenticate "
            "mail senders and ensure that destination email systems trust messages "
            "sent from your domain."
        ),
        rationale=(
            "DMARC tells receiving mail servers what to do when they get a message "
            "that appears to be from your organisation but doesn't pass authentication "
            "checks.  Spammers can spoof your domain to send fake messages that "
            "impersonate your organisation.  A p=reject or p=quarantine policy "
            "protects against this."
        ),
        impact=(
            "Minimal impact when starting with p=none (monitor only).  Organisations "
            "should ensure proper DMARC record setup as email could be flagged as "
            "spam if DMARC is not set up appropriately.  At minimum, configure DMARC "
            "to receive RUA reports."
        ),
        audit_procedure=(
            "Check the DNS TXT record for _dmarc.<domain>:\n"
            "  dig TXT _dmarc.<domain>\n\n"
            "A valid DMARC record should start with 'v=DMARC1' and contain a "
            "policy (p=none/quarantine/reject).\n"
            "Example: v=DMARC1; p=none; rua=mailto:<report@domain.com>"
        ),
        remediation=(
            "Add a DMARC TXT record to the domain's DNS configuration:\n"
            "  v=DMARC1; p=none; rua=mailto:<report@domain.com>\n\n"
            "Start with p=none to monitor email flow, then progress to "
            "p=quarantine and finally p=reject once mail flow is confirmed.\n"
            "Note: This will likely need to be configured at your domain registrar."
        ),
        default_value="DMARC records are not automatically configured — must be added manually in DNS.",
        references=[
            "https://support.google.com/a/answer/2466580",
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
        tags=["gmail", "dmarc", "email-security", "anti-spoofing", "dns"],
    )

    async def check(self, data: CollectedData):
        dmarc_data = data.get("dns_dmarc")
        if dmarc_data is None:
            return self._skip("DMARC DNS data was not collected.")

        if not dmarc_data:
            return self._skip("No domains found to check DMARC records.")

        missing = []
        weak_policy = []
        present = {}

        for domain, record in dmarc_data.items():
            if not record:
                missing.append(domain)
            else:
                present[domain] = record
                # Check if policy is p=none (weakest)
                if "p=none" in record.lower() and "p=quarantine" not in record.lower() and "p=reject" not in record.lower():
                    weak_policy.append(domain)

        evidence = [
            Evidence(
                source="dns.google/resolve (TXT) — _dmarc.<domain>",
                data={"dmarc_records": dmarc_data},
                description="DMARC TXT records for all verified domains.",
            )
        ]

        if missing:
            return self._fail(
                f"{len(missing)} domain(s) are missing DMARC records: {', '.join(missing)}.",
                evidence=evidence,
            )

        if weak_policy:
            return self._fail(
                f"{len(weak_policy)} domain(s) have DMARC set to p=none (monitor-only); "
                f"upgrade to p=quarantine or p=reject: {', '.join(weak_policy)}.",
                evidence=evidence,
            )

        return self._pass(
            f"All {len(present)} domain(s) have DMARC records with enforcing policy.",
            evidence=evidence,
        )
