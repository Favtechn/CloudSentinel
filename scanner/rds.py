import boto3


def scan_rds():
    rds = boto3.client("rds")

    response = rds.describe_db_instances()

    public_databases = []

    for db in response["DBInstances"]:

        if db.get("PubliclyAccessible", False):
            public_databases.append({
                "id": db["DBInstanceIdentifier"],
                "engine": db["Engine"],
                "status": db["DBInstanceStatus"]
            })

    if not public_databases:
        return []

    return [{
        "severity": "CRITICAL",
        "issue": "RDS database is publicly accessible",
        "count": len(public_databases),
        "databases": public_databases,
        "recommendation": (
            "Disable public accessibility and place the database "
            "in private subnets."
        )
    }]