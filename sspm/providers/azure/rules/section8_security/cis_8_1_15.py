"""CIS Azure 8.1.15 – Ensure that 'Notify about attack paths with the following risk level (or higher)' is Enabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_15(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.15",
        title="Ensure that 'Notify about attack paths with the following risk level (or higher)' is Enabled",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Defender for Cloud can notify security contacts when new attack paths are "
            "discovered above a configured risk level. Enabling this notification ensures "
            "that toxic combinations of misconfigurations are surfaced promptly."
        ),
        rationale=(
            "Attack paths represent chains of misconfigurations that an attacker could exploit "
            "end-to-end. Without notifications, newly discovered paths may sit unaddressed "
            "until the next manual review cycle."
        ),
        impact="None.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/securityContacts — "
            "at least one contact must have a notificationsSources entry with "
            "sourceType == 'AttackPath' and state == 'On'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Email notifications → "
            "Notify about attack paths → enable and select risk level → Save."
        ),
        default_value="Attack path notifications are off by default.",
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

        # Check if any contact has notificationsSources
        any_has_sources = any(
            "notificationsSources" in c.get("properties", {})
            for c in contacts
        )
        if not any_has_sources:
            return self._skip("Security contact notification sources could not be verified.")

        compliant = False
        for c in contacts:
            sources = c.get("properties", {}).get("notificationsSources") or []
            for src in sources:
                src_type = (src.get("sourceType") or src.get("type") or "").lower()
                state = (src.get("state") or "").lower()
                if src_type == "attackpath" and state == "on":
                    compliant = True
                    break
            if compliant:
                break

        evidence = [Evidence(
            source="arm:securityContacts",
            data={"attack_path_notifications_on": compliant},
        )]
        if compliant:
            return self._pass(
                "Attack path notifications are enabled in security contact settings.",
                evidence=evidence,
            )
        return self._fail(
            "No security contact has attack path notifications enabled.",
            evidence=evidence,
        )
