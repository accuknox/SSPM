"""CIS AWS 6.4 – Ensure no security groups allow ingress from ::/0 to remote server administration ports (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_ADMIN_PORTS = {22, 3389}


def _sg_allows_unrestricted_ipv6(sg: dict, port: int) -> bool:
    """Return True if the SG allows IPv6 ingress from ::/0 on the given port."""
    for perm in sg.get("IpPermissions", []):
        ip_protocol = perm.get("IpProtocol", "")
        if ip_protocol == "-1":
            if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
                return True
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if from_port is None or to_port is None:
            continue
        if from_port <= port <= to_port:
            if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
                return True
    return False


@registry.rule
class CIS_6_4(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.4",
        title="Ensure no security groups allow ingress from ::/0 to remote server administration ports",
        section="6 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Security groups should not allow unrestricted IPv6 ingress access to remote "
            "server administration ports (SSH port 22 and RDP port 3389). This extends the "
            "protection of CIS 6.3 to IPv6 traffic."
        ),
        rationale=(
            "As IPv6 adoption increases, security groups must also restrict IPv6 access to "
            "administration ports. An SG that blocks IPv4 but allows IPv6 from ::/0 still "
            "exposes instances to internet-based attacks."
        ),
        impact=(
            "Administrators using IPv6 connectivity for SSH/RDP must use a VPN, bastion host, "
            "or AWS Systems Manager Session Manager instead."
        ),
        audit_procedure=(
            "aws ec2 describe-security-groups\n"
            "For each SG, check IpPermissions for ports 22 or 3389 with CidrIpv6=::/0."
        ),
        remediation=(
            "EC2 Console → Security Groups → Inbound rules → Remove rules allowing "
            "ports 22 or 3389 from ::/0."
        ),
        default_value="Security groups are not created by default.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        sgs = data.get("ec2_security_groups")
        if sgs is None:
            return self._skip("Could not retrieve EC2 security groups.")

        violations = []
        for sg in sgs:
            sg_id = sg.get("GroupId", "unknown")
            name = sg.get("GroupName", "")
            region = sg.get("Region", "unknown")
            for port in _ADMIN_PORTS:
                if _sg_allows_unrestricted_ipv6(sg, port):
                    violations.append(f"{sg_id} ({name}, port {port}, {region})")

        evidence = [Evidence(
            source="ec2:DescribeSecurityGroups",
            data={"violations": violations},
            description="Security groups allowing unrestricted IPv6 ingress to SSH/RDP.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} security group(s) allow unrestricted IPv6 ingress to "
                f"administration ports: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "No security groups allow unrestricted IPv6 ingress to SSH or RDP ports. Compliant.",
            evidence=evidence,
        )
