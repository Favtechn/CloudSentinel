
SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3
}


def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = finding.get("severity", "LOW")

        deduction = SEVERITY_DEDUCTIONS.get(
            severity,
            0
        )

        score -= deduction

    return max(score, 0)


def count_severities(findings):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = finding.get("severity", "LOW")

        if severity in counts:
            counts[severity] += 1

    return counts