"""
CIS GWS 3.1.2.2.1 (L1) – Ensure offline access to documents is disabled
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
class CIS_3_1_2_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.2.1",
        title="Ensure offline access to documents is disabled",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Prevent documents from being locally accessible on an unconnected "
            "device.  Offline access should be controlled via device policies rather "
            "than allowing unrestricted offline caching."
        ),
        rationale=(
            "This setting prevents an organisation's files from being stored locally, "
            "thus limiting data loss issues if the device is lost or stolen."
        ),
        impact=(
            "Copies of recent files are only synced and saved on devices if you've "
            "defined a managed policy to do so.  All users will lose access to "
            "offline documents on all devices if managed device policies are not set."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Offline\n"
            "  4. Ensure 'Control offline access using device policies' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Offline\n"
            "  4. Set 'Control offline access using device policies' to checked\n"
            "  5. Click Save"
        ),
        default_value="Control offline access using device policies is unchecked.",
        references=[
            "https://support.google.com/a/answer/1639498",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.8",
                title="Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["drive", "offline", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify offline document access is controlled by device policies:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Select Features and Applications → Offline\n"
            "  4. Ensure 'Control offline access using device policies' is checked"
        )
