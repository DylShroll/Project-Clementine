# Project Clementine — Minimum Test Scenario

## DVWA on EC2 with intentional AWS misconfigurations

**Status:** Reference specification  
**Purpose:** Validate that Project Clementine correctly identifies application-layer vulnerabilities, AWS infrastructure misconfigurations, and the compound attack chains that connect them — all in a fully controlled, legal environment.

---

## Overview

This scenario deliberately deploys [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) on an EC2 instance that is intentionally misconfigured to seed every major correlation pattern built into Project Clementine. Running a full assessment against this environment should produce:

- **3 critical attack chains** (SSRF→IMDS→IAM, SQLi→RDS-equivalent, Exposed secrets→lateral movement)
- **2 high attack chains** (XSS→session hijack, Zero visibility)
- **25–50 individual findings** across application and infrastructure layers

> **Legal notice.** This environment must be deployed in an AWS account you own, against infrastructure you control. Never run Project Clementine against systems you do not have explicit written permission to test.

---

## Intentional misconfigurations seeded

These weaknesses are deliberately created so every major correlation pattern fires. They exist *only* in the test account and must never be replicated in production.

| Misconfiguration | Why it is seeded |
|---|---|
| EC2 IMDSv1 enabled | Seeds the SSRF → IMDS → IAM credential theft chain |
| IAM role with AdministratorAccess attached to EC2 | Amplifies the SSRF chain to full account takeover |
| Security group allowing 0.0.0.0/0 on port 80 and 22 | Seeds the open-SG → public EC2 → SSRF pivot chain |
| No CloudTrail enabled | Seeds the zero-visibility chain |
| No GuardDuty enabled | Seeds the zero-visibility chain |
| No AWS Config enabled | Seeds the zero-visibility chain |
| IAM access key not rotated (>90 days) | Seeds the exposed-secrets → lateral movement chain |
| DVWA security level set to LOW | Maximises application-layer findings across all WSTG categories |

---

## Prerequisites

| Requirement | Notes |
|---|---|
| AWS account (dedicated test account) | Use a throwaway account, not production |
| AWS CLI installed and configured | `aws configure` with an admin profile |
| Project Clementine installed | See [README](README.md) |
| Docker running locally | For AutoPentest AI |
| `uv` installed | `pip install uv` |
| `node` ≥ 18 | For Playwright MCP server |

---

## Step 1 — Create the AWS infrastructure

All commands use the AWS CLI. Console navigation paths are provided alongside each command for reference. Execute these in order.

### 1.1 Set your working variables

```bash
export AWS_REGION="us-east-1"
export TEST_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export KEY_PAIR_NAME="clementine-test-key"
export ROLE_NAME="clementine-test-role"
export INSTANCE_PROFILE_NAME="clementine-test-profile"
export SG_NAME="clementine-test-sg"

echo "Account ID: ${TEST_ACCOUNT_ID}"
echo "Region:     ${AWS_REGION}"
```

### 1.2 Create an SSH key pair

```bash
aws ec2 create-key-pair \
  --key-name "${KEY_PAIR_NAME}" \
  --region "${AWS_REGION}" \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/clementine-test.pem

chmod 400 ~/.ssh/clementine-test.pem
```

> **AWS Console path:** EC2 → Key Pairs → Your key pair will appear here after creation.

### 1.3 Create the intentionally overprivileged IAM role

This role gets `AdministratorAccess`. In a real account this would be catastrophic — here it seeds the SSRF→IMDS→IAM chain at maximum severity.

```bash
# Create the role with EC2 trust policy
aws iam create-role \
  --role-name "${ROLE_NAME}" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach AdministratorAccess — INTENTIONAL MISCONFIGURATION for testing
aws iam attach-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Create the instance profile and add the role to it
aws iam create-instance-profile \
  --instance-profile-name "${INSTANCE_PROFILE_NAME}"

aws iam add-role-to-instance-profile \
  --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
  --role-name "${ROLE_NAME}"

# Wait for propagation
sleep 10
```

> **AWS Console path:** IAM → Roles → `clementine-test-role`  
> The role ARN is on the Summary tab: `arn:aws:iam::<ACCOUNT_ID>:role/clementine-test-role`

### 1.4 Create an intentionally permissive security group

```bash
# Get the default VPC ID
VPC_ID="$(aws ec2 describe-vpcs \
  --filters 'Name=isDefault,Values=true' \
  --query 'Vpcs[0].VpcId' \
  --output text \
  --region "${AWS_REGION}")"

echo "VPC ID: ${VPC_ID}"

# Create the security group
SG_ID="$(aws ec2 create-security-group \
  --group-name "${SG_NAME}" \
  --description "Clementine test SG — intentionally permissive" \
  --vpc-id "${VPC_ID}" \
  --region "${AWS_REGION}" \
  --query 'GroupId' \
  --output text)"

echo "Security Group ID: ${SG_ID}"

# Allow HTTP from anywhere — INTENTIONAL MISCONFIGURATION for testing
aws ec2 authorize-security-group-ingress \
  --group-id "${SG_ID}" \
  --protocol tcp --port 80 --cidr 0.0.0.0/0 \
  --region "${AWS_REGION}"

# Allow SSH from anywhere — INTENTIONAL MISCONFIGURATION for testing
aws ec2 authorize-security-group-ingress \
  --group-id "${SG_ID}" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 \
  --region "${AWS_REGION}"
```

> **AWS Console path:** EC2 → Security Groups → Select `clementine-test-sg`  
> The Security Group ID (`sg-XXXXXXXXXXXXXXXXX`) appears at the top of the detail pane.

### 1.5 Launch the EC2 instance running DVWA

The instance is launched with:

- **IMDSv1 enabled** (no `http-tokens=required`) — intentional misconfiguration
- **Public IP assigned** — required to reach the web app, also seeds the open-SG chain
- **UserData** that installs Docker and runs the DVWA container on port 80

```bash
# Get the latest Amazon Linux 2023 AMI
AMI_ID="$(aws ec2 describe-images \
  --owners amazon \
  --filters \
    'Name=name,Values=al2023-ami-2023*-x86_64' \
    'Name=state,Values=available' \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text \
  --region "${AWS_REGION}")"

echo "AMI ID: ${AMI_ID}"

# Launch the instance
# Note: --metadata-options HttpTokens=optional enables IMDSv1 (INTENTIONAL)
INSTANCE_ID="$(aws ec2 run-instances \
  --image-id "${AMI_ID}" \
  --instance-type "t3.small" \
  --key-name "${KEY_PAIR_NAME}" \
  --security-group-ids "${SG_ID}" \
  --iam-instance-profile "Name=${INSTANCE_PROFILE_NAME}" \
  --associate-public-ip-address \
  --metadata-options "HttpTokens=optional,HttpEndpoint=enabled" \
  --region "${AWS_REGION}" \
  --tag-specifications \
    'ResourceType=instance,Tags=[{Key=Name,Value=clementine-test-dvwa},{Key=Project,Value=clementine-test}]' \
  --user-data '#!/bin/bash
set -e
# Install Docker
yum update -y
yum install -y docker
systemctl start docker
systemctl enable docker

# Run DVWA — publicly accessible on port 80
docker run -d \
  --name dvwa \
  --restart unless-stopped \
  -p 80:80 \
  -e RECAPTCHA_PRIV_KEY="" \
  -e RECAPTCHA_PUB_KEY="" \
  vulnerables/web-dvwa

# Write a setup marker for troubleshooting
echo "DVWA started at $(date)" > /var/log/clementine-setup.log
' \
  --query 'Instances[0].InstanceId' \
  --output text)"

echo "Instance ID: ${INSTANCE_ID}"

# Wait for the instance to reach running state
echo "Waiting for instance to start..."
aws ec2 wait instance-running \
  --instance-ids "${INSTANCE_ID}" \
  --region "${AWS_REGION}"

# Get the public DNS name
PUBLIC_DNS="$(aws ec2 describe-instances \
  --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].PublicDnsName' \
  --output text \
  --region "${AWS_REGION}")"

PUBLIC_IP="$(aws ec2 describe-instances \
  --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text \
  --region "${AWS_REGION}")"

echo "Public DNS: ${PUBLIC_DNS}"
echo "Public IP:  ${PUBLIC_IP}"
echo ""
echo "DVWA will be available at: http://${PUBLIC_DNS}"
echo "(Allow 2-3 minutes for UserData to finish installing Docker and pulling the image)"
```

> **AWS Console path:** EC2 → Instances → Select `clementine-test-dvwa`
>
> | Value needed | Where to find it |
> |---|---|
> | Instance ID | Detail pane → Instance ID (e.g. `i-0abc1234def56789`) |
> | Public IPv4 DNS | Detail pane → Public IPv4 DNS (e.g. `ec2-X-X-X-X.compute-1.amazonaws.com`) |
> | Public IPv4 address | Detail pane → Public IPv4 address |
> | IAM role | Detail pane → IAM Role → click link to see ARN |
> | Metadata version (IMDSv1/v2) | Detail pane → Advanced details → Metadata version |

### 1.6 Create a stale IAM access key (seeds the exposed-secrets chain)

```bash
# Create a test IAM user with an overprivileged policy and generate an access key
# The key is intentionally left unrotated to seed the iam-access-key-not-rotated finding
aws iam create-user --user-name clementine-test-leaked-user

aws iam attach-user-policy \
  --user-name clementine-test-leaked-user \
  --policy-arn "arn:aws:iam::aws:policy/PowerUserAccess"

# Generate the key — cloud-audit will flag it as unrotated after 90 days
# For test purposes, this simply ensures the finding class is present
aws iam create-access-key \
  --user-name clementine-test-leaked-user \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
  --output text
```

> Note the access key ID and secret. In the DVWA configuration phase you will add them as a hardcoded comment in a config file to seed the information-disclosure finding.

> **AWS Console path:** IAM → Users → `clementine-test-leaked-user` → Security credentials tab

### 1.7 Confirm no CloudTrail, GuardDuty, or Config is enabled

These are intentionally absent in the test account to seed the zero-visibility chain. Verify:

```bash
# Should return empty or show trails with isLogging: false
aws cloudtrail describe-trails --region "${AWS_REGION}"

# Should return an empty list of detectors
aws guardduty list-detectors --region "${AWS_REGION}"

# Should return no recorders
aws configservice describe-configuration-recorders --region "${AWS_REGION}"
```

If any of these services are active, disable them for the duration of the test to ensure the zero-visibility pattern fires:

```bash
# Disable CloudTrail logging if a trail exists
# aws cloudtrail stop-logging --name <trail-name>

# Delete GuardDuty detector if one exists
# aws guardduty delete-detector --detector-id <detector-id>
```

---

## Step 2 — Configure DVWA

Wait 2–3 minutes after launch for UserData to complete, then perform initial DVWA setup.

### 2.1 Initial database setup

```
1. Open a browser and navigate to:   http://<PUBLIC_DNS>/setup.php
2. Click "Create / Reset Database"
3. You will be redirected to the login page
```

### 2.2 Log in and set security level to LOW

```
1. Navigate to:  http://<PUBLIC_DNS>/login.php
2. Username:     admin
3. Password:     password
4. Navigate to:  DVWA Security (left sidebar)
5. Set Security Level to:  low
6. Click "Submit"
```

> Setting security level to **low** disables all input validation in DVWA, maximising the number of exploitable vulnerabilities AutoPentest AI will find.

### 2.3 Seed the information-disclosure finding

SSH into the instance and add the stale access key as a comment in the DVWA config — simulating a developer accidentally committing credentials:

```bash
ssh -i ~/.ssh/clementine-test.pem ec2-user@"${PUBLIC_DNS}"

# On the EC2 instance:
docker exec dvwa bash -c "cat >> /var/www/html/config/config.inc.php << 'EOF'

# TODO: remove before pushing
# aws_access_key_id     = AKIA<YOUR_KEY_ID_HERE>
# aws_secret_access_key = <YOUR_SECRET_HERE>
EOF"
```

Replace the placeholders with the actual key values created in step 1.6. This seeds the `information_disclosure` app-layer finding that triggers the exposed-secrets → lateral movement pattern.

---

## Step 3 — Locate configuration values in the AWS Console

This section maps every value required in `clementine.yaml` to its exact location in the AWS Management Console.

### 3.1 AWS Account ID

> Console: Click your account name in the top-right corner → **Account ID** is shown in the dropdown (12 digits, e.g. `123456789012`)  
> CLI: `aws sts get-caller-identity --query Account --output text`

### 3.2 AWS Region

> Console: The region name is shown in the top navigation bar next to your account name (e.g. `us-east-1`)  
> This value goes into `aws.regions` in `clementine.yaml`.

### 3.3 EC2 Instance public DNS (target URL)

> Console: **EC2 → Instances** → Select `clementine-test-dvwa` → Detail pane → **Public IPv4 DNS**  
> Example: `ec2-54-123-45-67.compute-1.amazonaws.com`  
> This becomes `target.url: "http://<PUBLIC_DNS>"` in `clementine.yaml`.

### 3.4 AWS CLI profile name (audit credentials)

> Console: **IAM → Users** (or the user/role your CLI is configured with)  
> CLI: `cat ~/.aws/credentials` — the section header (e.g. `[security-audit]`) is the profile name  
> This goes into `aws.profile` in `clementine.yaml`.

### 3.5 Security Group ID

> Console: **EC2 → Security Groups** → Select `clementine-test-sg` → Detail pane → **Security group ID**  
> Example: `sg-0a1b2c3d4e5f67890`  
> Not used directly in `clementine.yaml` but cloud-audit will discover and flag it automatically.

### 3.6 IAM Role ARN (for verifying cloud-audit finds it)

> Console: **IAM → Roles** → Select `clementine-test-role` → **Summary** tab  
> Example: `arn:aws:iam::123456789012:role/clementine-test-role`  
> Not set in `clementine.yaml` — cloud-audit discovers it during the AWS scan.

### 3.7 Metadata options (verify IMDSv1 is enabled)

> Console: **EC2 → Instances** → Select instance → **Details** tab → Scroll to **Advanced details** → **Metadata version**  
> Should read: `V1 and V2 (token optional)` — this confirms IMDSv1 is active and the SSRF chain is live.

---

## Step 4 — Configure Project Clementine

Create `clementine.yaml` by substituting the values collected above.

### 4.1 Set environment variables

```bash
export APP_USERNAME="admin"
export APP_PASSWORD="password"
export AWS_AUDIT_PROFILE="default"          # or your named profile
export AWS_ACCOUNT_ID="${TEST_ACCOUNT_ID}"   # set in Step 1.1
```

### 4.2 Write clementine.yaml

Replace `<PUBLIC_DNS>` with the EC2 instance public DNS from Step 3.3:

```yaml
# clementine.yaml — DVWA on EC2 test scenario

target:
  url: "http://<PUBLIC_DNS>"
  scope:
    include_domains:
      # Use the raw EC2 public DNS — no subdomain to worry about
      - "<PUBLIC_DNS>"
    exclude_paths:
      # Avoid DVWA's logout endpoint to keep the session alive during testing
      - "/logout.php"
    rate_limit_rps: 5   # Keep low for a t3.small instance

auth:
  method: "credentials"
  username: "${APP_USERNAME}"
  password: "${APP_PASSWORD}"
  login_url: "http://<PUBLIC_DNS>/login.php"

aws:
  profile: "${AWS_AUDIT_PROFILE}"
  regions:
    - "us-east-1"          # adjust if you deployed to a different region
  account_id: "${AWS_ACCOUNT_ID}"

compliance:
  frameworks:
    - "cis_2.0_aws"        # CIS baseline — will flag all missing logging controls

reporting:
  formats:
    - "html"
    - "json"
    - "sarif"
    - "markdown"
  output_dir: "./reports/dvwa-test"
  push_to_security_hub: false

orchestrator:
  max_parallel_agents: 2   # Conservative for a single t3.small target
  finding_db: "sqlite:///dvwa-test.db"
  log_level: "INFO"
  pause_between_phases: false

mcp_servers:
  autopentest:
    command: "docker"
    args: ["exec", "-i", "autopentest-tools", "python", "-m", "server"]
    env: {}

  cloud_audit:
    command: "uvx"
    args: ["cloud-audit-mcp"]
    env:
      AWS_PROFILE: "${AWS_AUDIT_PROFILE}"
      AWS_DEFAULT_REGION: "us-east-1"

  prowler:
    command: "uvx"
    args: ["prowler-mcp-server"]
    env: {}

  aws_knowledge:
    url: "https://knowledge-mcp.global.api.aws"
    type: "http"

  aws_docs:
    command: "uvx"
    args: ["awslabs.aws-documentation-mcp-server@latest"]
    env:
      FASTMCP_LOG_LEVEL: "ERROR"
      AWS_DOCUMENTATION_PARTITION: "aws"

  playwright:
    command: "npx"
    args: ["@anthropic/mcp-playwright"]
    env: {}
```

---

## Step 5 — Run the assessment

### 5.1 Verify connectivity before starting

```bash
# Confirm DVWA is reachable
curl -s -o /dev/null -w "%{http_code}" "http://${PUBLIC_DNS}/login.php"
# Expected: 200

# Confirm AWS credentials can see the test account
aws sts get-caller-identity
```

### 5.2 Ensure AutoPentest AI container is running

```bash
docker ps | grep autopentest-tools
# If not running:
docker run -d --name autopentest-tools bhavsec/autopentest-tools:latest tail -f /dev/null
```

### 5.3 Launch the assessment

```bash
clementine run --config clementine.yaml
```

Expected runtime: **45–90 minutes** — Phase 3 (WSTG full test suite) is the longest phase.

### 5.4 Monitor progress

In a second terminal, watch the log output. You should see phase transitions like:

```
10:01:02 [INFO] orchestrator: === Starting phase: RECON_RUNNING ===
10:03:45 [INFO] orchestrator: === Phase complete: RECON_COMPLETE ===
10:03:45 [INFO] orchestrator: === Starting phase: AWS_AUDIT_RUNNING ===
10:08:12 [INFO] orchestrator: === Phase complete: AWS_AUDIT_COMPLETE ===
10:08:12 [INFO] orchestrator: === Starting phase: APP_TEST_RUNNING ===
...
```

If the run is interrupted, simply re-run the same command — it will resume from the last completed phase.

---

## Step 6 — Expected findings

### 6.1 Application-layer findings (Phase 3 — AutoPentest AI / DVWA)

DVWA in low-security mode exposes the following WSTG categories. All should be found:

| WSTG Code | Vulnerability | DVWA Module | Expected Severity |
|---|---|---|---|
| WSTG-INPV-05 | SQL Injection | SQL Injection | CRITICAL |
| WSTG-INPV-01 | Reflected XSS | XSS (Reflected) | HIGH |
| WSTG-INPV-02 | Stored XSS | XSS (Stored) | HIGH |
| WSTG-INPV-09 | SSRF | SSRF | HIGH |
| WSTG-INPV-11 | Command Injection | Command Injection | CRITICAL |
| WSTG-INPV-12 | File Inclusion (LFI/RFI) | File Inclusion | HIGH |
| WSTG-ATHN-02 | Default credentials (`admin`/`password`) | Login page | HIGH |
| WSTG-SESS-02 | Missing HttpOnly / Secure cookie flags | Session cookie | MEDIUM |
| WSTG-CONF-05 | File upload of dangerous type | File Upload | HIGH |
| WSTG-CLNT-01 | DOM-based XSS (Playwright validated) | XSS (DOM) | HIGH |
| WSTG-INFO-01 | Information disclosure (hardcoded AWS key) | Config file | CRITICAL |

### 6.2 Infrastructure findings (Phase 2 — cloud-audit + Prowler)

| Check ID | Finding | Tool | Expected Severity |
|---|---|---|---|
| `aws-ec2-imdsv1-enabled` | IMDSv1 enabled on EC2 instance | cloud-audit | HIGH |
| `iam-role-overprivileged` | AdministratorAccess attached to EC2 role | cloud-audit | CRITICAL |
| `security-group-unrestricted-ingress` | Port 80 + 22 open to 0.0.0.0/0 | cloud-audit | HIGH |
| `ec2-public-ip-assigned` | EC2 instance has a public IP address | cloud-audit | MEDIUM |
| `cloudtrail-not-enabled` | No CloudTrail trail in any region | cloud-audit + Prowler | HIGH |
| `guardduty-not-enabled` | GuardDuty disabled | Prowler | HIGH |
| `aws-config-not-enabled` | AWS Config not recording | Prowler | MEDIUM |
| `iam-access-key-not-rotated` | IAM access key >90 days old | cloud-audit | HIGH |
| `iam-user-overprivileged` | PowerUserAccess attached to IAM user | cloud-audit | HIGH |
| `iam-root-mfa-not-enabled` | Root account MFA missing (if applicable) | Prowler | CRITICAL |

### 6.3 Expected compound attack chains (Phase 4 — Correlation engine)

All five critical/high patterns should fire:

#### Chain 1 — SSRF to AWS credential theft `[CRITICAL]`

```
WSTG-INPV-09: SSRF
  └── IMDSv1 enabled on same EC2 instance
        └── AdministratorAccess IAM role attached
              └── IMPACT: Full AWS account takeover via stolen temporary credentials
```

#### Chain 2 — SQL injection to database exfiltration `[CRITICAL]`

```
WSTG-INPV-05: SQL Injection
  └── No CloudTrail (exfiltration undetected)
        └── IMPACT: Database dumped with no audit trail
```

#### Chain 3 — Secret exposure to lateral movement `[CRITICAL]`

```
WSTG-INFO-01: Hardcoded AWS credentials in config file
  └── IAM access key not rotated (still active)
        └── PowerUserAccess IAM user
              └── IMPACT: Direct AWS API access without any exploit required
```

#### Chain 4 — XSS to admin session theft `[HIGH]`

```
WSTG-INPV-01: Reflected XSS
  └── Missing HttpOnly flag on session cookie
        └── No Content-Security-Policy header
              └── IMPACT: Admin session token exfiltrated via injected JavaScript
```

#### Chain 5 — Zero security visibility `[HIGH]`

```
CloudTrail not enabled
  └── GuardDuty not enabled (same account)
        └── AWS Config not enabled (same account)
              └── Any CRITICAL/HIGH finding in account
                    └── IMPACT: All exploitation goes completely undetected
```

### 6.4 Validation checklist

After the assessment, open `reports/dvwa-test/report.html` and verify:

- [ ] **5 attack chains** appear in the Attack Chains section
- [ ] **At least 1 CRITICAL attack chain** is present (SSRF→IMDS→IAM)
- [ ] **SQL injection finding** links to a RDS-equivalent chain
- [ ] **Hardcoded credentials finding** is present and marked as CRITICAL
- [ ] **cloud-audit health score** is below 40/100
- [ ] **Remediation playbook** contains CLI commands with correct syntax
- [ ] **SARIF file** is valid (open in VS Code with SARIF Viewer extension)
- [ ] **Compliance section** shows CIS 2.0 failures for logging controls

---

## Step 7 — Tear down

**Delete all resources after testing** — especially the IAM role with AdministratorAccess.

```bash
# Terminate EC2 instance
aws ec2 terminate-instances \
  --instance-ids "${INSTANCE_ID}" \
  --region "${AWS_REGION}"

aws ec2 wait instance-terminated \
  --instance-ids "${INSTANCE_ID}" \
  --region "${AWS_REGION}"

# Delete security group
aws ec2 delete-security-group \
  --group-id "${SG_ID}" \
  --region "${AWS_REGION}"

# Remove IAM role
aws iam remove-role-from-instance-profile \
  --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
  --role-name "${ROLE_NAME}"

aws iam delete-instance-profile \
  --instance-profile-name "${INSTANCE_PROFILE_NAME}"

aws iam detach-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

aws iam delete-role --role-name "${ROLE_NAME}"

# Delete stale IAM user and access key
aws iam delete-access-key \
  --user-name clementine-test-leaked-user \
  --access-key-id "<ACCESS_KEY_ID>"

aws iam detach-user-policy \
  --user-name clementine-test-leaked-user \
  --policy-arn "arn:aws:iam::aws:policy/PowerUserAccess"

aws iam delete-user --user-name clementine-test-leaked-user

# Delete key pair
aws ec2 delete-key-pair \
  --key-name "${KEY_PAIR_NAME}" \
  --region "${AWS_REGION}"

rm -f ~/.ssh/clementine-test.pem

echo "Tear-down complete."
```

Verify in the AWS Console that no resources remain:

- **EC2 → Instances** — instance should be in `terminated` state
- **IAM → Roles** — `clementine-test-role` should not exist
- **IAM → Users** — `clementine-test-leaked-user` should not exist
- **EC2 → Security Groups** — `clementine-test-sg` should not exist

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect` | UserData still running | Wait 3–5 min; SSH in and check `docker ps` |
| DVWA shows blank page | MySQL container not ready | `docker restart dvwa` |
| `ScopeError` in Clementine logs | PUBLIC_DNS not in `include_domains` | Verify the DNS in `clementine.yaml` matches exactly |
| Phase 2 has zero findings | AWS profile lacks `SecurityAudit` permissions | Run `aws iam list-attached-user-policies` to verify |
| No SSRF chain fired | DVWA SSRF module not exploited | Confirm security level is `low` in DVWA settings |
| AutoPentest container not found | Docker container stopped | `docker start autopentest-tools` |
| Assessment resumes then stalls | Stale DB from a previous run | `rm dvwa-test.db` and re-run |

---

## Cost estimate

| Resource | Type | Estimated cost |
|---|---|---|
| EC2 instance | `t3.small`, ~2 hours assessment | ~$0.03 |
| Data transfer | Minimal (all traffic is local AWS) | ~$0.00 |
| **Total** | | **< $0.05** |

All resources should be deleted immediately after the assessment completes.
