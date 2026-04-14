"""CIS AWS 6.1.2 – Ensure CIFS access is restricted to trusted networks (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.1.2",
        title="Ensure CIFS access is restricted to trusted networks to prevent unauthorized access",
        section="6.1 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "CIFS (Common Internet File System) uses port 445. Access to this port should "
            "be restricted to trusted network ranges to prevent unauthorized access to "
            "file shares and to mitigate ransomware propagation risks."
        ),
        rationale=(
            "Unrestricted access to port 445 (CIFS/SMB) exposes systems to ransomware, "
            "worm propagation (WannaCry, NotPetya), and unauthorized file system access. "
            "This port should only be accessible from trusted internal networks."
        ),
        impact=(
            "Restricting port 445 may break legitimate file sharing workflows. Review "
            "all legitimate CIFS consumers before restricting access."
        ),
        audit_procedure=(
            "aws ec2 describe-security-groups\n"
            "For each security group, check IpPermissions for port 445 ingress from "
            "0.0.0.0/0 or ::/0. Any such rule is a violation."
        ),
        remediation=(
            "EC2 Console → Security Groups → Inbound rules → Remove or restrict rules "
            "allowing port 445 from 0.0.0.0/0 or ::/0. Replace with specific trusted CIDR ranges."
        ),
        default_value="Security groups are not created by default.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Review security groups for ingress rules allowing port 445 (CIFS/SMB) from "
            "0.0.0.0/0 or ::/0. Run: aws ec2 describe-security-groups and check IpPermissions "
            "for port 445. Any unrestricted access to CIFS should be restricted to trusted "
            "network ranges only."
        )
