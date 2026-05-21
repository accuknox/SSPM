"""
CIS GWS 4.2.1.3 (L1) – Ensure internal apps can access Google Workspace APIs
(Manual)

Profile Applicability: Enterprise Level 1
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
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_4_2_1_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.1.3",
        title="Ensure internal apps can access Google Workspace APIs",
        section="4.2.1 API Controls",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Confirms that domain-owned (internal) applications developed "
            "by the organisation are configured and permitted to access "
            "Google Workspace APIs.  Internal apps should be trusted and "
            "managed through the Admin Console to ensure proper oversight."
        ),
        rationale=(
            "When API access controls are tightened to restrict third-party "
            "apps, it is important to ensure that legitimate internal "
            "applications are not inadvertently blocked.  Internal apps "
            "should be explicitly marked as trusted so they can continue "
            "to function while the organisation restricts external app "
            "access."
        ),
        impact=(
            "Internal applications that are not properly registered or "
            "trusted in the Admin Console may lose access to Google Workspace "
            "APIs when restrictions are applied.  All internal apps should "
            "be inventoried and configured before enabling API restrictions."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → App access control\n"
            "  3. Verify that 'Trust domain-owned apps' is enabled\n"
            "  4. Review the list of internal apps to confirm they are "
            "correctly registered and trusted"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → App access control\n"
            "  3. Enable 'Trust domain-owned apps' or add internal apps to "
            "the trusted apps list individually\n"
            "  4. Click Save"
        ),
        default_value=(
            "Domain-owned app trust settings depend on the overall API "
            "access configuration; verify current state in Admin Console."
        ),
        references=[
            "https://support.google.com/a/answer/7281227",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["api", "internal-apps"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
