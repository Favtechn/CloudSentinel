import boto3

from security_groups import scan_security_groups
from s3 import scan_s3_buckets
from iam import scan_iam
from cloudtrail import scan_cloudtrail
from ebs import scan_ebs
from rds import scan_rds
from scoring import calculate_score, count_severities


def main():

    print("AWS Security Scanner")
    print("--------------------")

    # --------------------------------------------------
    # AWS ACCOUNT INFORMATION
    # --------------------------------------------------

    sts = boto3.client("sts")
    identity = sts.get_caller_identity()

    print(f"Account: {identity['Account']}")
    print(f"ARN:     {identity['Arn']}")
    print(f"User ID: {identity['UserId']}")

    # This stores ALL findings from every scanner
    all_findings = []

    # --------------------------------------------------
    # SECURITY GROUPS
    # --------------------------------------------------

    print("\nScanning Security Groups...")
    print("---------------------------")

    security_findings = scan_security_groups()

    all_findings.extend(security_findings)

    if not security_findings:
        print("No Security Group findings found.")
    else:

        print("\nSecurity Findings")
        print("-----------------")

        for finding in security_findings:

            print("\n" + "=" * 50)

            print(
                f"[{finding['severity']}] "
                f"{finding['service']} exposed to the Internet"
            )

            print("=" * 50)

            print(f"Port:        {finding['port']}")
            print(f"Protocol:    {finding['protocol']}")
            print(f"Source:      {finding['source']}")
            print(f"Occurrences: {finding['count']}")

            print(
                f"\nRisk: {finding['service']} "
                "is accessible from the public Internet."
            )

            print(
                "Recommendation: Restrict access to trusted "
                "IP addresses or private networks."
            )

    # --------------------------------------------------
    # S3
    # --------------------------------------------------

    print("\nScanning S3 buckets...")
    print("----------------------")

    s3_findings = scan_s3_buckets()

    all_findings.extend(s3_findings)

    if not s3_findings:
        print("No S3 security findings found.")
    else:

        for finding in s3_findings:

            print("\n" + "=" * 50)
            print(f"[{finding['severity']}] {finding['service']}")
            print("=" * 50)

            print(f"Issue:    {finding['issue']}")
            print(f"Resource: {finding['resource']}")

    # --------------------------------------------------
    # IAM
    # --------------------------------------------------

    print("\nScanning IAM policies...")
    print("------------------------")

    iam_result = scan_iam()

    iam_findings = iam_result["findings"]

    all_findings.extend(iam_findings)

    print(f"Policies discovered: {iam_result['discovered']}")
    print(f"Policies analyzed:   {iam_result['analyzed']}")
    print(f"Policies skipped:    {iam_result['skipped']}")

    if iam_result["skipped"] > 0:

        print("\n[INFO] IAM analysis is incomplete.")
        print("AWS denied access to some policy documents.")

    if not iam_findings:

      if iam_result["skipped"] > 0:

        print(
            "\nNo IAM policy findings could be confirmed "
            "because some policy documents were inaccessible."
        )

      else:

        print("\nNo IAM policy findings detected.")

    else:

        for finding in iam_findings:

            print("\n" + "=" * 50)
            print(f"[{finding['severity']}] IAM")
            print("=" * 50)

            print(f"Issue:    {finding['issue']}")
            print(f"Policy:   {finding['policy']}")
            print(f"Action:   {finding['action']}")
            print(f"Resource: {finding['resource']}")

            print("\nRecommendation:")
            print(
                "Restrict IAM permissions to only the actions "
                "and resources required by the workload."
            )

    # --------------------------------------------------
    # CLOUDTRAIL
    # --------------------------------------------------

    print("\nScanning CloudTrail...")
    print("----------------------")

    cloudtrail_findings = scan_cloudtrail()

    all_findings.extend(cloudtrail_findings)

    if not cloudtrail_findings:

        print("No CloudTrail security findings found.")

    else:

        for finding in cloudtrail_findings:

            print("\n" + "=" * 50)
            print(f"[{finding['severity']}] CloudTrail")
            print("=" * 50)

            print(f"Issue:          {finding['issue']}")
            print(f"Resource:       {finding['resource']}")
            print(
                f"Recommendation: "
                f"{finding['recommendation']}"
            )

    # --------------------------------------------------
    # EBS
    # --------------------------------------------------

    print("\nScanning EBS volumes...")
    print("-----------------------")

    ebs_findings = scan_ebs()

    all_findings.extend(ebs_findings)

    if not ebs_findings:

        print("No EBS encryption findings found.")

    else:

        for finding in ebs_findings:

            print("\n" + "=" * 50)
            print(f"[{finding['severity']}] EBS")
            print("=" * 50)

            print(f"Issue:       {finding['issue']}")
            print(f"Occurrences: {finding['count']}")

            print("\nRisk:")
            print(
                "Data stored on these volumes is "
                "not encrypted at rest."
            )

            print("\nRecommendation:")
            print(finding["recommendation"])

    # --------------------------------------------------
    # RDS
    # --------------------------------------------------

    print("\nScanning RDS...")
    print("----------------")

    rds_findings = scan_rds()

    all_findings.extend(rds_findings)

    if not rds_findings:

        print("No RDS security findings found.")

    else:

        for finding in rds_findings:

            print("\n" + "=" * 50)
            print(f"[{finding['severity']}] RDS")
            print("=" * 50)

            print(f"Issue:       {finding['issue']}")
            print(f"Occurrences: {finding['count']}")

            print("\nRisk:")
            print(
                "A database that is publicly accessible "
                "can be targeted directly from the Internet."
            )

            print("\nRecommendation:")
            print(finding["recommendation"])

    # --------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------

    score = calculate_score(all_findings)
    counts = count_severities(all_findings)

    print("\n")
    print("=" * 50)
    print("AWS SECURITY POSTURE")
    print("=" * 50)

    print(f"\nSecurity Score: {score}/100")

    print("\nFindings:")
    print(f"  Critical: {counts['CRITICAL']}")
    print(f"  High:     {counts['HIGH']}")
    print(f"  Medium:   {counts['MEDIUM']}")
    print(f"  Low:      {counts['LOW']}")
    print(f"  Total:    {len(all_findings)}")


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()