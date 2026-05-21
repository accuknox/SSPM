"""CIS Azure 8.1.14 – Ensure that 'Notify about alerts with the following severity (or higher)' is Enabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_14(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.14",
        title="Ensure that 'Notify about alerts with the following severity (or higher)' is Enabled",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Defender for Cloud security contact alert notifications should be enabled with a "
            "minimum severity threshold so that security contacts receive email alerts when "
            "threats of at least that severity are detected."
        ),
        rationale=(
            "Without alert notifications, security incidents may go unnoticed by the contact "
            "team. A severity threshold ensures that meaningful threats trigger immediate "
            "notification without alert fatigue from low-severity informational events."
        ),
        impact="None.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/securityContacts — "
            "at least one contact must have properties.alertNotifications.state == 'On' "
            "and properties.alertNotifications.minimalSeverity set to a non-empty value."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Email notifications → "
            "Notify about alerts with the following severity → select High/Medium/Low → Save."
        ),
        default_value="Alert notifications are off by default.",
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

        compliant = False
        found_severity: str = ""
        for c in contacts:
            an = c.get("properties", {}).get("alertNotifications", {})
            state = (an.get("state") or "").lower()
            min_sev = (an.get("minimalSeverity") or "").strip()
            if state == "on" and min_sev:
                compliant = True
                found_severity = min_sev
                break

        evidence = [Evidence(
            source="arm:securityContacts",
            data={"alert_notifications_on": compliant, "minimal_severity": found_severity},
        )]
        if compliant:
            return self._pass(
                f"Alert notifications are enabled with minimal severity '{found_severity}'.",
                evidence=evidence,
            )
        return self._fail(
            "No security contact has alert severity notifications configured and enabled.",
            evidence=evidence,
        )
