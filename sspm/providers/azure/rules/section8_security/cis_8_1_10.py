"""CIS Azure 8.1.10 – Ensure that Microsoft Defender for Cloud is Configured to Check VM Operating Systems for Updates (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_10(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.10",
        title="Ensure that Microsoft Defender for Cloud is Configured to Check VM Operating Systems for Updates",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Defender for Cloud auto-provisioning of the monitoring agent ensures that "
            "Azure VMs are continuously assessed for missing OS updates, allowing Defender to "
            "surface patch compliance recommendations."
        ),
        rationale=(
            "Unpatched operating systems are the most common initial access vector. Automatic "
            "agent provisioning ensures that update status is continuously visible without "
            "manual agent installation on each VM."
        ),
        impact="Agent deployment adds a small overhead to VM startup and consumes Log Analytics workspace capacity.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/autoProvisioningSettings — "
            "at least one setting must have properties.autoProvision equal to 'On'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Auto provisioning → "
            "set Log Analytics agent / Azure Monitor Agent to On → Save."
        ),
        default_value="Auto-provisioning is off by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="7.3", title="Perform Automated Operating System Patch Management", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        settings = data.get("auto_provisioning_settings")
        if settings is None:
            return self._skip("Auto-provisioning settings could not be retrieved.")

        # Check for MMA/AMA agent provisioning first, then fall back to any agent that is On
        mma_setting = next(
            (
                s for s in settings
                if any(
                    kw in (s.get("name") or "").lower()
                    for kw in ("mma-agent", "microsoftmonitoringagent", "mmaagent", "azuremonitor")
                )
            ),
            None,
        )
        if mma_setting:
            provision = (mma_setting.get("properties", {}).get("autoProvision") or "").lower()
            evidence = [Evidence(
                source="arm:autoProvisioningSettings",
                data={"agent": mma_setting.get("name"), "autoProvision": provision},
            )]
            if provision == "on":
                return self._pass(
                    f"Auto-provisioning is On for agent '{mma_setting.get('name', '?')}'.",
                    evidence=evidence,
                )
            return self._fail(
                f"Auto-provisioning for agent '{mma_setting.get('name', '?')}' is '{provision or 'Off'}'.",
                evidence=evidence,
            )

        # Fall back: any setting that is On
        any_on = next(
            (s for s in settings if (s.get("properties", {}).get("autoProvision") or "").lower() == "on"),
            None,
        )
        on_names = [
            s.get("name", "?")
            for s in settings
            if (s.get("properties", {}).get("autoProvision") or "").lower() == "on"
        ]
        evidence = [Evidence(source="arm:autoProvisioningSettings", data={"agents_on": on_names})]
        if any_on:
            return self._pass(
                f"Auto-provisioning is On for agent(s): {', '.join(on_names)}.",
                evidence=evidence,
            )
        return self._fail(
            "No auto-provisioning setting is set to 'On'; VM OS update checks are not configured.",
            evidence=evidence,
        )
