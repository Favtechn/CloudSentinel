import boto3


def scan_ebs():
    ec2 = boto3.client("ec2")

    response = ec2.describe_volumes()

    unencrypted_volumes = []

    for volume in response["Volumes"]:

        if not volume.get("Encrypted", False):
            unencrypted_volumes.append({
                "id": volume["VolumeId"],
                "size": volume["Size"],
                "state": volume["State"]
            })

    if not unencrypted_volumes:
        return []

    return [{
        "severity": "HIGH",
        "issue": "EBS volumes are not encrypted",
        "count": len(unencrypted_volumes),
        "volumes": unencrypted_volumes,
        "recommendation": (
            "Encrypt EBS volumes to protect data at rest."
        )
    }]