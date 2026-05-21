"""CIS Azure 8.1.7.2 – Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_7_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.7.2",
        title="Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'",
        section="8.1.7 Defender Plan: Databases",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for Open-Source Relational Databases covers Azure Database for "
            "PostgreSQL, MySQL, and MariaDB, detecting brute-force attacks, anomalous access "
            "patterns, and potential SQL injection attempts."
        ),
        rationale=(
            "Open-source databases are widely used and frequently targeted. Defender provides "
            "the behavioral analytics and threat intelligence needed to detect database-level "
            "attacks that network controls cannot block."
        ),
        impact="Defender for open-source databases incurs per-server monthly pricing.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Security/pricings/OpenSourceRelationalDatabases — "
            "properties.pricingTier must equal 'Standard'."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Databases → "
            "Open-source relational databases → toggle to On → Save."
        ),
        default_value="Defender for Open-Source Relational Databases is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.1", title="Centralize Security Event Alerting", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        pricings = data.get("defender_pricings")
        if pricings is None:
            return self._skip("Defender pricings could not be retrieved.")

        plan = next(
            (p for p in pricings if (p.get("name") or "").lower() == "opensource relational databases".replace(" ", "")),
            None,
        )
        if plan is None:
            # Try alternate casing
            plan = next(
                (p for p in pricings if "opensource" in (p.get("name") or "").lower() and "relation" in (p.get("name") or "").lower()),
                None,
            )
        if plan is None:
            return self._fail("Defender for Open-Source Relational Databases plan is not configured on this subscription.")

        tier = (plan.get("properties", {}).get("pricingTier") or "").lower()
        evidence = [Evidence(source="arm:Microsoft.Security/pricings", data={"OpenSourceRelationalDatabases": tier})]
        if tier == "standard":
            return self._pass("Defender for Open-Source Relational Databases plan is set to Standard (On).", evidence=evidence)
        return self._fail(
            f"Defender for Open-Source Relational Databases plan is '{tier or 'unset'}', expected 'Standard'.",
            evidence=evidence,
        )
