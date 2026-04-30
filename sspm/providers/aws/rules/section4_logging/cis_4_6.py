"""CIS AWS 4.6 – Ensure rotation for customer-created symmetric CMKs is enabled (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_6(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.6",
        title="Ensure rotation for customer-created symmetric CMKs is enabled",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "AWS Key Management Service (KMS) allows customers to rotate the backing key "
            "material of their customer-managed keys. Key rotation minimizes the blast radius "
            "of a compromised key by ensuring new data is encrypted with new key material."
        ),
        rationale=(
            "Rotating encryption keys reduces the amount of data encrypted under any single key "
            "version and limits the impact of key compromise. AWS KMS retains old key material "
            "to allow decryption of data encrypted before the rotation."
        ),
        impact="Key rotation happens automatically once per year with no downtime.",
        audit_procedure=(
            "aws kms list-keys\n"
            "For each customer-managed symmetric key:\n"
            "aws kms get-key-rotation-status --key-id <key-id>\n"
            "Check KeyRotationEnabled == true."
        ),
        remediation=(
            "aws kms enable-key-rotation --key-id <key-id>"
        ),
        default_value="Key rotation is not enabled by default for customer-managed keys.",
        references=[
            "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.11", title="Encrypt Sensitive Data at Rest", ig1=False, ig2=True, ig3=True),
            CISControl(version="v7", control_id="14.8", title="Encrypt Sensitive Information at Rest", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        keys = data.get("kms_keys")
        if keys is None:
            return self._skip("Could not retrieve KMS keys.")

        # Filter to customer-managed symmetric keys only
        violations = []
        checked = 0
        for key in keys:
            detail = key.get("_detail", {})
            # Skip AWS-managed keys, asymmetric keys, and HMAC keys
            if detail.get("KeyManager") == "AWS":
                continue
            if detail.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            if detail.get("KeyState") not in ("Enabled", None, ""):
                continue
            checked += 1
            rotation = key.get("_rotation", False)
            if not rotation:
                kid = key.get("KeyId", "unknown")
                alias = detail.get("Description", kid)
                violations.append(f"{kid} ({alias[:30]})")

        evidence = [Evidence(
            source="kms:GetKeyRotationStatus",
            data={"keys_without_rotation": violations, "customer_managed_keys_checked": checked},
            description="Customer-managed symmetric CMKs without rotation enabled.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} customer-managed symmetric CMK(s) do not have rotation enabled: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {checked} customer-managed symmetric CMK(s) have rotation enabled. Compliant.",
            evidence=evidence,
        )
