"""CIS AWS 6.2 – Ensure no NACLs allow ingress from 0.0.0.0/0 to remote server administration ports (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_ADMIN_PORTS = {22, 3389}


def _nacl_allows_unrestricted_ingress(nacl: dict, port: int) -> bool:
    """Return True if any NACL entry allows ingress from 0.0.0.0/0 on the given port."""
    for entry in nacl.get("Entries", []):
        # Only check ingress (Egress=False)
        if entry.get("Egress", True):
            continue
        # Only Allow rules
        if entry.get("RuleAction", "").lower() != "allow":
            continue
        cidr = entry.get("CidrBlock", "")
        cidr_v6 = entry.get("Ipv6CidrBlock", "")
        if cidr not in ("0.0.0.0/0",) and cidr_v6 not in ("::/0",):
            continue
        # Check protocol and port range
        protocol = str(entry.get("Protocol", "-1"))
        if protocol == "-1":  # All traffic
            return True
        if protocol not in ("6", "tcp", "17", "udp"):
            continue
        port_range = entry.get("PortRange", {})
        from_port = port_range.get("From", 0)
        to_port = port_range.get("To", 65535)
        if from_port <= port <= to_port:
            return True
    return False


@registry.rule
class CIS_6_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.2",
        title="Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
        section="6 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Network ACLs (NACLs) provide subnet-level network access control. No NACL should "
            "allow unrestricted ingress access to remote server administration ports such as "
            "SSH (port 22) and RDP (port 3389)."
        ),
        rationale=(
            "Unrestricted access to SSH and RDP ports at the NACL level exposes all instances "
            "in the subnet to internet-based attacks. Even if security groups are restrictive, "
            "defense-in-depth requires NACLs to also restrict admin port access."
        ),
        impact=(
            "Administrators relying on unrestricted NACL rules for SSH/RDP must use VPN, "
            "bastion hosts, or AWS Systems Manager Session Manager."
        ),
        audit_procedure=(
            "aws ec2 describe-network-acls --region <region>\n"
            "For each NACL, check Entries for ingress Allow rules on ports 22 or 3389 "
            "from 0.0.0.0/0 or ::/0."
        ),
        remediation=(
            "EC2 Console → Network ACLs → Inbound rules → Remove or restrict entries "
            "allowing ports 22 or 3389 from 0.0.0.0/0 or ::/0."
        ),
        default_value="Default NACLs allow all inbound and outbound traffic.",
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        nacls = data.get("ec2_nacls")
        if nacls is None:
            return self._skip(
                "Could not retrieve Network ACLs. "
                "Ensure the ec2_nacls collector is enabled."
            )

        violations = []
        for nacl in nacls:
            nacl_id = nacl.get("NetworkAclId", "unknown")
            region = nacl.get("Region", "unknown")
            for port in _ADMIN_PORTS:
                if _nacl_allows_unrestricted_ingress(nacl, port):
                    violations.append(f"{nacl_id} (port {port}, {region})")

        evidence = [Evidence(
            source="ec2:DescribeNetworkAcls",
            data={"violations": violations, "total_nacls": len(nacls)},
            description="NACLs allowing unrestricted ingress to admin ports (22, 3389).",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} NACL(s) allow unrestricted ingress to administration ports: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"No NACLs allow unrestricted ingress to SSH/RDP ports ({len(nacls)} total). Compliant.",
            evidence=evidence,
        )
