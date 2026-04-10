"""
CIS GWS 3.1.6.1 (L1) – Ensure that accessing groups from outside this
organization is set to Private (Automated)

Profile Applicability: Enterprise Level 1
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
from sspm.providers.gws.rules.base import GWSRule

# Groups Settings API values that allow outsiders to view a group
_EXTERNAL_VISIBLE = {"ANYONE_CAN_VIEW"}


@registry.rule
class CIS_3_1_6_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.6.1",
        title="Ensure that accessing groups from outside this organization is set to Private",
        section="3.1.6 Groups for Business",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Ensures that Google Groups are not visible to users outside the "
            "organisation.  When groups are publicly accessible, their "
            "membership lists, content, and existence can be enumerated by "
            "anyone on the internet, facilitating social engineering and "
            "targeted phishing."
        ),
        rationale=(
            "Group membership and conversation history may contain sensitive "
            "organisational information.  Restricting visibility to members "
            "only (Private) limits information exposure to external parties."
        ),
        impact=(
            "People outside the organisation will not be able to discover, "
            "view membership of, or read messages in any group."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Groups for Business\n"
            "  3. Select Sharing options\n"
            "  4. Ensure 'Accessing groups from outside this organization' "
            "is set to Private\n\n"
            "Automated check: queries the Groups Settings API for every group "
            "and verifies whoCanViewGroup is not ANYONE_CAN_VIEW and "
            "allowExternalMembers is false (requires apps.groups.settings scope)."
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Groups for Business\n"
            "  3. Select Sharing options\n"
            "  4. Set 'Accessing groups from outside this organization' to Private\n"
            "  5. Click Save\n\n"
            "For any non-compliant groups, also update per-group settings to "
            "restrict whoCanViewGroup to ALL_MEMBERS_CAN_VIEW or more restrictive."
        ),
        default_value=(
            "Accessing groups from outside this organization is Private by "
            "default (already compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/167097",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["groups", "external-access", "privacy", "information-disclosure"],
    )

    async def check(self, data: CollectedData):
        group_settings: dict | None = data.get("group_settings")

        if group_settings is None:
            return self._manual(
                "Group settings could not be collected.  "
                "Ensure the 'apps.groups.settings' scope is authorised in "
                "Domain-wide Delegation, then re-run the scan.\n\n"
                "Manual verification:\n"
                "  1. Log in to https://admin.google.com\n"
                "  2. Select Apps → Google Workspace → Groups for Business\n"
                "  3. Select Sharing options\n"
                "  4. Ensure 'Accessing groups from outside this organization' "
                "is set to Private"
            )

        violations: list[tuple[str, str]] = []  # (group_email, reason)

        for group_email, settings in group_settings.items():
            who_can_view = settings.get("whoCanViewGroup", "")
            allow_external = str(settings.get("allowExternalMembers", "false")).lower()

            if who_can_view in _EXTERNAL_VISIBLE:
                violations.append((
                    group_email,
                    f"whoCanViewGroup={who_can_view}",
                ))
            elif allow_external == "true":
                violations.append((
                    group_email,
                    "allowExternalMembers=true",
                ))

        if not violations:
            total = len(group_settings)
            return self._pass(
                f"All {total} group(s) have external access restricted "
                "(whoCanViewGroup is not public, allowExternalMembers is false)."
            )

        evidence = [
            Evidence(
                source="Groups Settings API",
                data={"group": email, "issue": reason},
                description=f"{email}: {reason}",
            )
            for email, reason in violations
        ]

        sample = ", ".join(e for e, _ in violations[:5])
        return self._fail(
            f"{len(violations)} group(s) are accessible from outside the organisation: "
            f"{sample}" + (" …" if len(violations) > 5 else ""),
            evidence=evidence,
        )
