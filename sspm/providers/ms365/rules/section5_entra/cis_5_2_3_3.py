"""
CIS MS365 5.2.3.3 (L1) – Ensure password protection is enabled for on-prem
Active Directory (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Entra Password Protection settings are exposed via the tenant-wide "Password
Rule Settings" directory setting (GET /groupSettings, templateId
5cf42378-d67d-4f36-ba46-e8b86229381d), so this control is genuinely
automatable via Microsoft Graph.
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_5_2_3_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.3",
        title="Ensure password protection is enabled for on-prem Active Directory",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "For hybrid environments, Microsoft Entra Password Protection agents "
            "should be installed on on-premises Active Directory domain controllers "
            "to enforce the same banned password policies on-premises."
        ),
        rationale=(
            "Without on-premises password protection, users can set weak passwords "
            "in on-premises AD that may be synced to Entra ID, bypassing cloud "
            "password protection policies."
        ),
        impact=(
            "Requires installation of the Microsoft Entra Password Protection proxy "
            "service and DC agent on on-premises infrastructure."
        ),
        audit_procedure=(
            "Microsoft Graph:\n"
            "  GET /groupSettings, filter templateId == "
            "5cf42378-d67d-4f36-ba46-e8b86229381d (Password Rule Settings)\n"
            "  Ensure EnableBannedPasswordCheckOnPremises is True and "
            "BannedPasswordCheckOnPremisesMode is 'Enforce'.\n\n"
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Password protection.\n"
            "  Ensure 'Enable password protection on Windows Server Active "
            "Directory' is Yes and Mode is Enforced.\n\n"
            "Note: This recommendation applies to hybrid deployments only and "
            "has no impact without on-premises Active Directory."
        ),
        remediation=(
            "1. Download the Microsoft Entra Password Protection proxy installer\n"
            "2. Install on a domain-joined server with connectivity to Entra ID\n"
            "3. Install DC agents on all domain controllers\n"
            "4. Configure enforcement mode in Entra admin center"
        ),
        default_value="On-premises password protection is not installed by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "passwords", "on-premises", "ad", "hybrid"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("password_protection_settings")
        if settings is None:
            if "password_protection_settings" in (data.errors or {}):
                return self._skip(
                    "Could not retrieve Password Protection settings: "
                    f"{data.errors.get('password_protection_settings')}"
                )
            # No "Password Rule Settings" groupSetting object exists for this
            # tenant at all. Per CIS's own default-value note, on-premises
            # password protection is "not installed by default" — this is a
            # deterministic non-compliant state, not an unknown one. Note:
            # this control only has real impact for hybrid tenants with
            # on-premises Active Directory.
            return self._fail(
                "On-premises Active Directory password protection is not "
                "configured for this tenant (Password Rule Settings group "
                "setting does not exist). Note: this control only applies "
                "to hybrid tenants with on-premises AD."
            )

        on_prem_enabled = str(
            settings.get("EnableBannedPasswordCheckOnPremises", "False")
        ).lower() == "true"
        mode = settings.get("BannedPasswordCheckOnPremisesMode", "")
        evidence = [
            Evidence(
                source="graph/groupSettings (Password Rule Settings)",
                data={
                    "EnableBannedPasswordCheckOnPremises": settings.get(
                        "EnableBannedPasswordCheckOnPremises"
                    ),
                    "BannedPasswordCheckOnPremisesMode": mode,
                },
                description="Entra Password Protection on-premises AD proxy mode.",
            )
        ]

        if on_prem_enabled and mode == "Enforce":
            return self._pass(
                "On-premises Active Directory password protection is enabled "
                "and enforced.",
                evidence=evidence,
            )
        return self._fail(
            "On-premises Active Directory password protection is not enabled "
            f"and enforced (enabled={on_prem_enabled}, mode={mode!r}). Note: "
            "this only applies to hybrid tenants with on-premises AD.",
            evidence=evidence,
        )
