"""CIS Azure 8.1.12 – Ensure That 'All users with the following roles' is Set to 'Owner' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_12(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.12",
        title="Ensure That 'All users with the following roles' is Set to 'Owner'",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Defender for Cloud security contact notifications should be configured to send "
            "alerts to all subscription Owners so that the people accountable for the resource "
            "are notified when a high-severity threat is detected."
        ),
        rationale=(
            "Owners have the broadest control over a subscription. Ensuring they receive "
            "security alerts means the right people can authorize remediation actions "
            "without delay."
        ),
        impact="None.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/securityContacts — "
            "at least one contact must have properties.notificationsByRole.state == 'On' "
            "and properties.notificationsByRole.roles containing 'Owner'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Email notifications → "
            "All users with the following roles → select Owner → Save."
        ),
        default_value="Role-based notifications are off by default.",
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
        for c in contacts:
            nbr = c.get("properties", {}).get("notificationsByRole", {})
            state = (nbr.get("state") or "").lower()
            roles = [r.lower() for r in (nbr.get("roles") or [])]
            if state == "on" and "owner" in roles:
                compliant = True
                break

        evidence = [Evidence(
            source="arm:securityContacts",
            data={"owner_role_notification_enabled": compliant},
        )]
        if compliant:
            return self._pass(
                "Security contact notifications are enabled for subscription Owners.",
                evidence=evidence,
            )
        return self._fail(
            "No security contact has role-based notifications enabled for 'Owner'.",
            evidence=evidence,
        )
