"""CIS AWS 2.6 – Ensure hardware MFA is enabled for the 'root' user account (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_6(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.6",
        title="Ensure hardware MFA is enabled for the 'root' user account",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "The root account should be protected with a hardware MFA device rather than a "
            "virtual MFA application. Hardware MFA provides stronger assurance since the "
            "physical device must be present to authenticate."
        ),
        rationale=(
            "Virtual MFA devices are software-based and their seed keys could be extracted from "
            "a compromised device. Hardware MFA devices cannot be cloned or remotely extracted, "
            "providing a stronger second factor for the most privileged account."
        ),
        impact=(
            "Switching from virtual to hardware MFA requires a hardware token device and must "
            "be done while logged in as root with the current MFA device."
        ),
        audit_procedure=(
            "1. Run: aws iam get-account-summary → check AccountMFAEnabled == 1\n"
            "2. Run: aws iam list-virtual-mfa-devices --assignment-status Assigned\n"
            "3. If root account appears in the virtual MFA list, it is using virtual MFA (non-compliant).\n"
            "4. If root is not in the virtual MFA list but MFA is enabled, it is using hardware MFA (compliant)."
        ),
        remediation=(
            "1. Obtain a hardware MFA device (FIDO2 key or TOTP hardware token).\n"
            "2. Sign in to the AWS Management Console as root with current MFA.\n"
            "3. Navigate to IAM → Security credentials.\n"
            "4. Deactivate the virtual MFA device.\n"
            "5. Assign the hardware MFA device."
        ),
        default_value="No MFA is configured by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.5", title="Require MFA for Administrative Access", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="4.5", title="Use Multifactor Authentication for All Administrative Access", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        account_summary = data.get("iam_account_summary") or {}
        mfa_enabled = account_summary.get("AccountMFAEnabled", 0) == 1

        if not mfa_enabled:
            return self._fail(
                "Root account does not have MFA enabled at all. Enable hardware MFA immediately.",
                evidence=[Evidence(
                    source="iam:GetAccountSummary",
                    data={"AccountMFAEnabled": 0},
                )],
            )

        # Check if root is using a virtual MFA device
        virtual_devices = data.get("iam_virtual_mfa_devices") or []
        root_has_virtual = any(
            d.get("User", {}).get("Arn", "").endswith(":root")
            for d in virtual_devices
        )

        evidence = [Evidence(
            source="iam:ListVirtualMFADevices",
            data={
                "root_uses_virtual_mfa": root_has_virtual,
                "total_virtual_devices": len(virtual_devices),
            },
            description="Whether the root account is assigned a virtual MFA device.",
        )]

        if root_has_virtual:
            return self._fail(
                "Root account uses a virtual MFA device. Hardware MFA is required for Level 2 compliance.",
                evidence=evidence,
            )
        return self._pass(
            "Root account MFA appears to be hardware-based (not found in virtual MFA device list).",
            evidence=evidence,
        )
