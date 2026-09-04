import boto3


def scan_s3_buckets():
    s3 = boto3.client("s3")

    response = s3.list_buckets()

    findings = []

    for bucket in response["Buckets"]:
        bucket_name = bucket["Name"]

        try:
            public_access = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = public_access["PublicAccessBlockConfiguration"]

            if not all(config.values()):
                findings.append({
                    "severity": "HIGH",
                    "service": "S3",
                    "issue": "Public access protection is not fully enabled",
                    "resource": bucket_name
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "severity": "HIGH",
                "service": "S3",
                "issue": "No public access block configuration found",
                "resource": bucket_name
            })

    return findings