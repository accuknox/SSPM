"""CIS AWS 6.1.2 – Ensure CIFS access is restricted to trusted networks (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_CIFS_PORT = 445


def _sg_allows_unrestricted_cifs(sg: dict) -> bool:
    """Return True if the SG allows ingress from 0.0.0.0/0 or ::/0 on port 445."""
    for perm in sg.get("IpPermissions", []):
        ip_protocol = perm.get("IpProtocol", "")
        # All-traffic rule
        if ip_protocol == "-1":
            if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
                return True
            if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
                return True
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if from_port is None or to_port is None:
            continue
        if from_port <= _CIFS_PORT <= to_port:
            if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
                return True
            if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
                return True
    return False


@registry.rule
class CIS_6_1_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.1.2",
        title="Ensure CIFS access is restricted to trusted networks to prevent unauthorized access",
        section="6.1 Networking",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Common Internet File System (CIFS) is a network file-sharing protocol that allows "
            "systems to share files over a network. Unrestricted CIFS access on port 445 can "
            "expose data to unauthorized users. CIFS access should be restricted to only trusted "
            "networks to prevent unauthorized access and data breaches."
        ),
        rationale=(
            "Allowing unrestricted CIFS access can lead to significant security vulnerabilities, "
            "as it may allow unauthorized users to access sensitive files and data. Restricting "
            "CIFS access to known and trusted networks minimizes the risk of unauthorized access "
            "and protects sensitive data from exposure to potential attackers, including ransomware "
            "propagation (WannaCry, NotPetya)."
        ),
        impact=(
            "Restricting port 445 may break legitimate file sharing workflows. Review "
            "all legitimate CIFS consumers before restricting access."
        ),
        audit_procedure=(
            "aws ec2 describe-security-groups --region <region>\n"
            "For each security group, check IpPermissions for ingress rules on port 445 "
            "from 0.0.0.0/0 or ::/0. Any such rule is a violation."
        ),
        remediation=(
            "EC2 Console → Security Groups → Inbound rules → Remove or restrict rules "
            "allowing port 445 from 0.0.0.0/0 or ::/0. Replace with specific trusted CIDR ranges.\n\n"
            "CLI: aws ec2 revoke-security-group-ingress --region <region> --group-id <sg-id> "
            "--protocol tcp --port 445 --cidr 0.0.0.0/0"
        ),
        default_value=(
            "By default, security groups can allow unrestricted CIFS access (port 445) if "
            "configured, including 0.0.0.0/0 or ::/0. AWS does not automatically restrict this."
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="4.5", title="Implement and Manage a Firewall on End-User Devices", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="9.4", title="Apply Host-Based Firewalls or Port-Filtering", ig1=True, ig2=True, ig3=True),
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
            if _sg_allows_unrestricted_cifs(sg):
                violations.append(f"{sg_id} ({name}, {region})")

        evidence = [Evidence(
            source="ec2:DescribeSecurityGroups",
            data={"violations": violations, "total_sgs": len(sgs)},
            description="Security groups allowing unrestricted ingress to CIFS port 445.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} security group(s) allow unrestricted ingress to CIFS "
                f"port 445: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"No security groups allow unrestricted ingress to CIFS port 445 "
            f"({len(sgs)} groups checked). Compliant.",
            evidence=evidence,
        )
