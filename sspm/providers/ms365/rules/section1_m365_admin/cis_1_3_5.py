"""
CIS MS365 1.3.5 (L1) – Ensure internal phishing protection for Microsoft Forms
is enabled (Manual)

Profile Applicability: E3 Level 1, E5 Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_1_3_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.5",
        title="Ensure internal phishing protection for Microsoft Forms is enabled",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Forms has a built-in phishing detection capability that "
            "blocks forms containing phishing attempts from being shared. This "
            "protection should be enabled to prevent Microsoft Forms from being "
            "used as a phishing vector."
        ),
        rationale=(
            "Attackers can use Microsoft Forms to create credential harvesting pages "
            "that appear legitimate due to the Microsoft branding. Internal phishing "
            "protection helps detect and block these forms."
        ),
        impact=(
            "Legitimate forms that happen to match phishing patterns may be "
            "incorrectly blocked. Administrators can review and unblock flagged forms."
        ),
        audit_procedure=(
            "Microsoft 365 admin center → Settings > Org settings > Forms.\n"
            "Verify that 'Internal phishing protection' is enabled.\n\n"
            "There is no Microsoft Graph API for Microsoft Forms settings."
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Forms.\n"
            "Enable the 'Internal phishing protection' option."
        ),
        default_value="Internal phishing protection for Forms is enabled by default.",
        references=[
            "https://support.microsoft.com/en-us/office/phishing-protection-in-microsoft-forms",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.6",
                title="Block Unnecessary File Types",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["forms", "phishing", "anti-phishing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
