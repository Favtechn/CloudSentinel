import boto3


DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
}


def scan_security_groups():
    ec2 = boto3.client("ec2")
    response = ec2.describe_security_groups()

    findings = {}

    for security_group in response["SecurityGroups"]:

        for rule in security_group["IpPermissions"]:

            protocol = rule.get("IpProtocol")
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            for ip_range in rule.get("IpRanges", []):

                cidr = ip_range.get("CidrIp")

                # Only check rules open to the entire Internet
                if cidr != "0.0.0.0/0":
                    continue

                # All traffic
                if protocol == "-1":
                    service = "All Traffic"
                    severity = "CRITICAL"
                    port = "ALL"

                # Known dangerous ports
                elif from_port in DANGEROUS_PORTS:
                    service = DANGEROUS_PORTS[from_port]
                    severity = "HIGH"
                    port = from_port

                else:
                    continue

                # This identifies the actual security rule.
                # Identical rules will be counted together.
                finding_key = (
                    service,
                    protocol,
                    from_port,
                    to_port,
                    cidr
                )

                if finding_key not in findings:
                    findings[finding_key] = {
                        "service": service,
                        "severity": severity,
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "port": port,
                        "source": cidr,
                        "count": 0
                    }

                findings[finding_key]["count"] += 1

    return list(findings.values())







