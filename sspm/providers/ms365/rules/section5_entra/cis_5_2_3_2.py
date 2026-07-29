"""
CIS MS365 5.2.3.2 (L1) – Ensure custom banned passwords lists are used
(Automated)

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
class CIS_5_2_3_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.2",
        title="Ensure custom banned passwords lists are used",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Entra Password Protection should be configured with a "
            "custom banned password list specific to the organization. This "
            "prevents users from using company-specific weak passwords."
        ),
        rationale=(
            "Default banned password lists may not include organization-specific "
            "terms (company name, product names, locations) that attackers commonly "
            "use in password spray attacks. Custom lists enhance protection."
        ),
        impact=(
            "Users attempting to set passwords that match custom banned terms will "
            "be rejected and must choose a different password."
        ),
        audit_procedure=(
            "Microsoft Graph:\n"
            "  GET /groupSettings, filter templateId == "
            "5cf42378-d67d-4f36-ba46-e8b86229381d (Password Rule Settings)\n"
            "  Ensure EnableBannedPasswordCheck is True and BannedPasswordList "
            "is populated.\n\n"
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Password protection.\n"
            "Verify:\n"
            "  • 'Enforce custom list' is set to 'Yes'\n"
            "  • Custom banned password list contains organization-relevant terms"
        ),
        remediation=(
            "Microsoft Entra admin center → Protection > Authentication methods > "
            "Password protection.\n"
            "Enable 'Enforce custom list' and add organization-specific terms:\n"
            "  • Company name and abbreviations\n"
            "  • Product names\n"
            "  • Office locations\n"
            "  • Common patterns used by your organization"
        ),
        default_value="Custom banned passwords are not configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad",
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
        tags=["identity", "passwords", "password-protection", "banned-passwords"],
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
            # tenant at all. Per CIS's own default-value note, custom banned
            # passwords are "not configured by default" — this is a
            # deterministic non-compliant state, not an unknown one.
            return self._fail(
                "No custom banned password list is configured for this "
                "tenant (Password Rule Settings group setting does not "
                "exist)."
            )

        enforce_custom_list = str(
            settings.get("EnableBannedPasswordCheck", "False")
        ).lower() == "true"
        banned_list = settings.get("BannedPasswordList") or ""
        evidence = [
            Evidence(
                source="graph/groupSettings (Password Rule Settings)",
                data={
                    "EnableBannedPasswordCheck": settings.get(
                        "EnableBannedPasswordCheck"
                    ),
                    "BannedPasswordList": banned_list,
                },
                description="Entra Password Protection custom banned password list.",
            )
        ]

        if enforce_custom_list and banned_list.strip():
            return self._pass(
                "Custom banned password list is enforced and populated.",
                evidence=evidence,
            )
        return self._fail(
            "Custom banned password list is not enforced or is empty "
            f"(EnableBannedPasswordCheck={enforce_custom_list}, "
            f"list_populated={bool(banned_list.strip())}).",
            evidence=evidence,
        )
