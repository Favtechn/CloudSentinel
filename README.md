# CloudSentinel

### AWS Cloud Security Posture Scanner

CloudSentinel is an automated AWS security assessment tool designed to identify common cloud security misconfigurations across critical AWS services.

It evaluates an AWS environment for security weaknesses involving **network exposure, storage security, identity and access management, logging, encryption, and database exposure**, then consolidates the results into a security posture score.

> **Purpose:** Help cloud engineers and security teams quickly identify high-risk AWS configurations and prioritize remediation.

---

## Features

CloudSentinel currently assesses the following AWS security areas:

### 🔐 Security Groups

Identifies network rules that expose services directly to the public Internet.

Example:

```text
[HIGH] SSH exposed to the Internet

Port:        22
Protocol:    tcp
Source:      0.0.0.0/0
Occurrences: 5
```

This helps identify unnecessarily exposed administrative services such as SSH.

**Recommendation:** Restrict administrative access to trusted IP addresses, VPNs, bastion hosts, or private networks.

---

### 🪣 S3 Security

Checks S3 buckets for insecure public-access protection configurations.

Example finding:

```text
[HIGH] S3

Issue:    Public access protection is not fully enabled
Resource: example-bucket
```

This helps identify storage configurations that could increase the risk of unintended data exposure.

---

### 👤 IAM

Analyzes locally managed IAM policies when the AWS environment permits policy-document inspection.

CloudSentinel looks for excessive permissions such as:

```text
Action:   *
Resource: *
```

and wildcard service permissions such as:

```text
s3:*
ec2:*
iam:*
```

The scanner classifies excessive permissions according to their potential security impact.

CloudSentinel also distinguishes between:

* Policies successfully analyzed
* Policies discovered but inaccessible
* Confirmed IAM findings

This prevents an inaccessible policy from incorrectly being reported as secure.

> **AWS Academy/Vocareum environments may restrict `iam:GetPolicyVersion`. In such environments, CloudSentinel reports the IAM analysis as incomplete rather than treating inaccessible policies as secure.**

---

### 📜 CloudTrail

Checks the AWS environment for CloudTrail-related security issues.

Logging is an important component of cloud security because it provides visibility into:

* API activity
* Account changes
* Authentication activity
* Resource modifications
* Potential security incidents

---

### 💾 EBS

Checks EBS volumes for encryption-at-rest issues.

Unencrypted storage can increase the risk of data exposure if underlying storage or snapshots are improperly accessed.

CloudSentinel reports affected volumes and provides remediation guidance.

---

### 🗄️ RDS

Checks database exposure and identifies databases that may be publicly accessible.

Publicly accessible databases can significantly increase attack surface and should generally be restricted through:

* Private subnets
* Security Groups
* Network controls
* Application-layer access

---

## Security Posture Score

CloudSentinel consolidates discovered findings into an overall security score from:

```text
0 ─────────────────────────────── 100
Poor                              Strong
```

Findings are weighted according to severity:

| Severity | Impact |
| -------- | -----: |
| Critical |    -25 |
| High     |    -15 |
| Medium   |     -8 |
| Low      |     -3 |

The score provides a quick high-level view of the environment's security posture.

**Important:** The score is an assessment metric created by CloudSentinel and should not be interpreted as an official AWS security rating.

---

## Architecture

```text
                    AWS ACCOUNT
                         │
                         ▼
                ┌─────────────────┐
                │  CloudSentinel  │
                └────────┬────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
 Security Groups       S3              IAM
        │                │                │
        └────────────────┼────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
    CloudTrail          EBS             RDS
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                ┌─────────────────┐
                │    Findings     │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Severity Engine │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Security Score  │
                └─────────────────┘
```

---

## Project Structure

```text
CloudSentinel/
│
├── scanner/
│   ├── main.py
│   ├── security_groups.py
│   ├── s3.py
│   ├── iam.py
│   ├── cloudtrail.py
│   ├── ebs.py
│   ├── rds.py
│   └── scoring.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

### Components

| Module               | Responsibility                                    |
| -------------------- | ------------------------------------------------- |
| `main.py`            | Orchestrates the complete assessment              |
| `security_groups.py` | Checks network exposure                           |
| `s3.py`              | Evaluates S3 security configuration               |
| `iam.py`             | Analyzes IAM policy permissions                   |
| `cloudtrail.py`      | Checks CloudTrail configuration                   |
| `ebs.py`             | Checks EBS encryption                             |
| `rds.py`             | Checks RDS exposure                               |
| `scoring.py`         | Calculates security score and severity statistics |

---

## Requirements

* Python 3.9+
* AWS account
* AWS credentials configured through the standard AWS credential chain
* Appropriate IAM permissions for the resources being assessed

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

CloudSentinel uses the AWS SDK for Python (**Boto3**).

Configure your AWS credentials using the AWS CLI:

```bash
aws configure
```

Verify that the credentials are working:

```bash
aws sts get-caller-identity
```

CloudSentinel should only be executed against AWS environments that you own or have explicit authorization to assess.

---

## Running the Scanner

From the project root:

```bash
python scanner/main.py
```

The scanner will:

1. Identify the AWS account
2. Assess Security Groups
3. Assess S3 buckets
4. Analyze IAM policies
5. Assess CloudTrail
6. Assess EBS volumes
7. Assess RDS
8. Aggregate findings
9. Calculate a security posture score

---

## Example Output

```text
AWS Security Scanner
--------------------

Account: 123456789012

Scanning Security Groups...
---------------------------

==================================================
[HIGH] SSH exposed to the Internet
==================================================

Port:        22
Protocol:    tcp
Source:      0.0.0.0/0
Occurrences: 5

Risk: SSH is accessible from the public Internet.

Recommendation:
Restrict access to trusted IP addresses or private networks.


Scanning S3 buckets...
----------------------

==================================================
[HIGH] S3
==================================================

Issue:    Public access protection is not fully enabled
Resource: example-bucket


Scanning IAM policies...
------------------------

Policies discovered: 6
Policies analyzed:   6
Policies skipped:    0


==================================================
AWS SECURITY POSTURE
==================================================

Security Score: 72/100

Findings:
  Critical: 0
  High:     2
  Medium:   1
  Low:      0
  Total:    3
```

---

## Security Assessment Philosophy

CloudSentinel follows an important security principle:

> **Unknown should not be treated as secure.**

For example, if AWS denies access to an IAM policy document, CloudSentinel does not report:

```text
IAM: Secure
```

Instead, it reports that the analysis is incomplete.

This distinction prevents false confidence during security assessments.

---

## Use Cases

CloudSentinel can be used for:

### Cloud Security Assessments

Quickly identify common AWS security misconfigurations during an environment review.

### Security Engineering

Provide engineers with actionable findings and remediation recommendations.

### DevSecOps

Integrate cloud configuration checks into security workflows and infrastructure reviews.

### Security Labs

Use controlled AWS environments to learn practical cloud security assessment techniques.

### Pre-Deployment Reviews

Assess cloud resources before exposing workloads to production traffic.

---

## Security Findings

CloudSentinel focuses on practical security risks such as:

* Publicly exposed administrative services
* Insecure S3 configurations
* Excessive IAM permissions
* Missing or insufficient audit logging
* Unencrypted EBS storage
* Publicly accessible databases

Each finding contains contextual information intended to help engineers understand **what is wrong, why it matters, and how to remediate it**.

---

## Limitations

CloudSentinel is a security assessment tool, not a replacement for a comprehensive cloud security platform.

Results depend on:

* AWS API permissions
* AWS account configuration
* AWS region
* Services deployed in the account
* Scanner coverage

An inability to inspect a resource does **not** mean that the resource is secure.

For example, AWS Academy environments can restrict IAM policy inspection. CloudSentinel therefore reports inaccessible policies separately rather than treating them as successfully assessed.

---

## Roadmap

Future versions may include:

* [ ] Multi-region scanning
* [ ] AWS Organizations assessment
* [ ] CIS AWS Benchmark mapping
* [ ] AWS Security Hub integration
* [ ] GuardDuty integration
* [ ] Secrets exposure detection
* [ ] VPC configuration analysis
* [ ] Lambda security analysis
* [ ] EKS/Kubernetes security checks
* [ ] Terraform/IaC security analysis
* [ ] JSON report generation
* [ ] HTML security reports
* [ ] CI/CD integration
* [ ] Historical security posture tracking
* [ ] Automated remediation recommendations

---

## Security & Responsible Use

CloudSentinel is intended for **authorized security assessments**.

Only run the scanner against:

* AWS accounts you own
* AWS environments where you have explicit authorization
* Dedicated security labs
* Authorized client environments

Do not use CloudSentinel to access, enumerate, or assess cloud environments without permission.

---

## Author

**Favour Alozie**

Cloud Security Engineering Project

Focus areas:

```text
Cloud Security
AWS
IAM
Network Security
Cloud Infrastructure
DevSecOps
Security Automation
```

---

## Why CloudSentinel?

Cloud environments can accumulate security misconfigurations as infrastructure grows.

CloudSentinel provides a lightweight way to answer three fundamental questions:

**1. What is exposed?**

Identify publicly accessible services and resources.

**2. What is misconfigured?**

Detect security weaknesses across identity, storage, networking, logging, encryption, and databases.

**3. What should we fix first?**

Prioritize findings using severity-based scoring and actionable remediation guidance.

---

## License

This project is intended for educational, research, and authorized security assessment purposes.
