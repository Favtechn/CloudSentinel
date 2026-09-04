import boto3


def scan_cloudtrail():
    cloudtrail = boto3.client("cloudtrail")

    findings = []

    response = cloudtrail.describe_trails(
        includeShadowTrails=False
    )

    trails = response.get("trailList", [])

    if not trails:
        findings.append({
            "severity": "HIGH",
            "issue": "No CloudTrail trail is configured",
            "resource": "AWS Account",
            "recommendation": (
                "Configure CloudTrail to record AWS API activity "
                "and security-relevant events."
            )
        })

        return findings

    for trail in trails:

        trail_name = trail["Name"]
        trail_arn = trail["TrailARN"]

        status = cloudtrail.get_trail_status(
            Name=trail_arn
        )

        if not status.get("IsLogging", False):

            findings.append({
                "severity": "HIGH",
                "issue": "CloudTrail trail is not actively logging",
                "resource": trail_name,
                "recommendation": (
                    "Enable logging for the CloudTrail trail."
                )
            })

    return findings