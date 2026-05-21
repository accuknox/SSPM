"""CIS Azure 8.1.3.3 – Ensure that 'Endpoint protection' Component Status is set to 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_3_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.3.3",
        title="Ensure that 'Endpoint protection' Component Status is set to 'On'",
        section="8.1.3 Defender Plan: Servers",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "The Endpoint protection component in Defender for Servers automatically provisions "
            "the monitoring agent on Azure VMs to enable threat detection and anti-malware "
            "capabilities across the fleet."
        ),
        rationale=(
            "Without auto-provisioning, new VMs are deployed without an endpoint protection "
            "agent, creating blind spots for malware and living-off-the-land attacks."
        ),
        impact="Agent deployment adds a small overhead to VM startup time.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/autoProvisioningSettings — "
            "at least one setting must have properties.autoProvision equal to 'On'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Auto provisioning → "
            "set Microsoft Monitoring Agent (or Azure Monitor Agent) to On → Save."
        ),
        default_value="Auto-provisioning is off by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="10.1", title="Deploy and Maintain Anti-Malware Software", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        settings = data.get("auto_provisioning_settings")
        if settings is None:
            return self._skip("Auto-provisioning settings could not be retrieved.")

        mma_on = any(
            s.get("properties", {}).get("autoProvision", "").lower() == "on"
            for s in settings
        )
        on_names = [
            s.get("name", "?")
            for s in settings
            if s.get("properties", {}).get("autoProvision", "").lower() == "on"
        ]
        evidence = [Evidence(source="arm:autoProvisioningSettings", data={"agents_on": on_names})]
        if mma_on:
            return self._pass(
                f"Auto-provisioning is On for agent(s): {', '.join(on_names)}.",
                evidence=evidence,
            )
        return self._fail(
            "No auto-provisioning setting is set to 'On'; endpoint protection is not deployed automatically.",
            evidence=evidence,
        )
