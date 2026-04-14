"""CIS AWS 6.5 – Ensure the default security group of every VPC restricts all traffic (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_5(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.5",
        title="Ensure the default security group of every VPC restricts all traffic",
        section="6 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "A VPC comes with a default security group whose initial settings deny all inbound "
            "traffic, allow all outbound traffic, and allow all traffic between instances "
            "assigned to the security group. The default security group should be configured "
            "to restrict all traffic."
        ),
        rationale=(
            "Configuring default security groups to restrict all traffic ensures that "
            "resources inadvertently launched into the default SG are not exposed. "
            "Resources should use explicitly configured, least-privilege security groups."
        ),
        impact=(
            "Resources currently using the default security group must be assigned a "
            "purpose-built security group before restricting the default SG."
        ),
        audit_procedure=(
            "aws ec2 describe-security-groups --filters Name=group-name,Values=default\n"
            "For each default SG, verify IpPermissions and IpPermissionsEgress are empty."
        ),
        remediation=(
            "For each default SG:\n"
            "1. Remove all inbound rules:\n"
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions <...>\n"
            "2. Remove all outbound rules:\n"
            "aws ec2 revoke-security-group-egress --group-id <sg-id> --ip-permissions <...>"
        ),
        default_value="Default SG allows all traffic between instances in the same SG by default.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.3", title="Configure Data Access Control Lists", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="4.5", title="Implement and Manage a Firewall on End-User Devices", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="9.4", title="Apply Host-Based Firewalls or Port-Filtering", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="14.6", title="Protect Information through Access Control Lists", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        sgs = data.get("ec2_security_groups")
        if sgs is None:
            return self._skip("Could not retrieve EC2 security groups.")

        violations = []
        default_sgs_checked = 0
        for sg in sgs:
            if sg.get("GroupName") != "default":
                continue
            default_sgs_checked += 1
            sg_id = sg.get("GroupId", "unknown")
            region = sg.get("Region", "unknown")
            has_ingress = bool(sg.get("IpPermissions"))
            has_egress = bool(sg.get("IpPermissionsEgress"))
            if has_ingress or has_egress:
                issues = []
                if has_ingress:
                    issues.append(f"{len(sg.get('IpPermissions', []))} inbound rule(s)")
                if has_egress:
                    issues.append(f"{len(sg.get('IpPermissionsEgress', []))} outbound rule(s)")
                violations.append(f"{sg_id} ({region}): {', '.join(issues)}")

        evidence = [Evidence(
            source="ec2:DescribeSecurityGroups",
            data={"default_sgs_with_rules": violations, "total_default_sgs": default_sgs_checked},
            description="Default VPC security groups with non-empty ingress or egress rules.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} default VPC security group(s) have ingress/egress rules: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {default_sgs_checked} default VPC security group(s) restrict all traffic. Compliant.",
            evidence=evidence,
        )
