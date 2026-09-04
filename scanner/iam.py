import boto3
import json
from urllib.parse import unquote
from botocore.exceptions import ClientError


def scan_iam():

    iam = boto3.client("iam")

    findings = []
    skipped = 0
    analyzed = 0

    # --------------------------------------------------
    # DISCOVER LOCAL IAM POLICIES
    # --------------------------------------------------

    try:
        response = iam.list_policies(
            Scope="Local",
            OnlyAttached=False
        )

        policies = response.get("Policies", [])

    except ClientError:
        return {
            "findings": [],
            "discovered": 0,
            "analyzed": 0,
            "skipped": 0,
            "access_denied": True
        }

    # --------------------------------------------------
    # INSPECT EACH POLICY
    # --------------------------------------------------

    for policy in policies:

        policy_arn = policy["Arn"]
        policy_name = policy["PolicyName"]
        version_id = policy["DefaultVersionId"]

        try:

            response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )

            analyzed += 1

            document = response["PolicyVersion"]["Document"]

            # AWS may return the policy document encoded
            if isinstance(document, str):
                document = json.loads(unquote(document))

            statements = document.get("Statement", [])

            # A single statement can be returned as a dictionary
            if isinstance(statements, dict):
                statements = [statements]

            # --------------------------------------------------
            # ANALYZE POLICY STATEMENTS
            # --------------------------------------------------

            for statement in statements:

                # We only care about permissions that are actually allowed
                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])

                if isinstance(actions, str):
                    actions = [actions]

                if isinstance(resources, str):
                    resources = [resources]

                # --------------------------------------------------
                # CRITICAL: FULL WILDCARD PERMISSIONS
                # --------------------------------------------------

                if "*" in actions and "*" in resources:

                    findings.append({
                        "severity": "CRITICAL",
                        "service": "IAM",
                        "issue": "Full administrative wildcard permissions",
                        "policy": policy_name,
                        "action": "*",
                        "resource": "*"
                    })

                # --------------------------------------------------
                # HIGH: WILDCARD SERVICE PERMISSIONS
                # --------------------------------------------------

                else:

                    wildcard_services = [
                        action
                        for action in actions
                        if isinstance(action, str)
                        and action.endswith(":*")
                    ]

                    if wildcard_services:

                        findings.append({
                            "severity": "HIGH",
                            "service": "IAM",
                            "issue": "Wildcard service permissions",
                            "policy": policy_name,
                            "action": ", ".join(wildcard_services),
                            "resource": ", ".join(resources)
                        })

        # --------------------------------------------------
        # AWS ACADEMY DENIES POLICY INSPECTION
        # --------------------------------------------------

        except ClientError as error:

            error_code = error.response.get(
                "Error", {}
            ).get("Code")

            if error_code == "AccessDenied":
                skipped += 1

            else:
                skipped += 1

        # --------------------------------------------------
        # SAFETY NET
        # --------------------------------------------------

        except Exception:
            skipped += 1

    # --------------------------------------------------
    # RETURN RESULTS
    # --------------------------------------------------

    return {
        "findings": findings,
        "discovered": len(policies),
        "analyzed": analyzed,
        "skipped": skipped,
        "access_denied": skipped > 0
    }