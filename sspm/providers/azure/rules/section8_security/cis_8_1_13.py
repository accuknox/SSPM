"""CIS Azure 8.1.13 – Ensure 'Additional email addresses' is Configured with a Security Contact Email (Automated, L1)"""
from __future__ import annotations

import re

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@registry.rule
class CIS_8_1_13(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.13",
        title="Ensure 'Additional email addresses' is Configured with a Security Contact Email",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "A security contact email must be configured so that Microsoft can notify the "
            "right people when Defender for Cloud detects a high-severity alert."
        ),
        rationale=(
            "Without a dedicated security contact, critical alerts reach only subscription "
            "owners — who may not route them to the SOC or incident response team in time."
        ),
        impact="None.",
        audit_procedure=(
            "ARM: GET /providers/Microsoft.Security/securityContacts — at least one contact "
            "must have a non-empty emails field."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Email notifications → "
            "add a security-ops email address → Save."
        ),
        default_value="No security contact email is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="17.2", title="Establish and Maintain Contact Information for Reporting Security Incidents", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        contacts = data.get("security_contacts")
        if contacts is None:
            return self._skip("Security contacts could not be retrieved.")

        all_emails: list[str] = []
        for c in contacts:
            raw = c.get("properties", {}).get("emails") or c.get("properties", {}).get("email") or ""
            for e in re.split(r"[;,\s]+", str(raw)):
                e = e.strip()
                if e and _EMAIL_RE.match(e):
                    all_emails.append(e)

        evidence = [Evidence(source="arm:securityContacts", data={"emails": all_emails})]
        if all_emails:
            return self._pass(
                f"{len(all_emails)} security contact email(s) configured.",
                evidence=evidence,
            )
        return self._fail("No security contact email is configured.", evidence=evidence)
