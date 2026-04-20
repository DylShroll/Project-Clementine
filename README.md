# Project Clementine

Automated web-app penetration-testing orchestrator. Coordinates six security MCP servers to deliver assessments that span both application-layer vulnerabilities (OWASP WSTG) and AWS infrastructure misconfigurations — then automatically correlates them into compound attack chains that neither layer of tooling can find on its own.

The engine builds a **NetworkX-backed AWS knowledge graph** during each assessment, enabling multi-hop attack path traversal, blast radius calculation, and a visual attack surface map in the HTML report.

```
SSRF (medium)  +  IMDSv1 enabled  +  overprivileged IAM role  =  full account takeover (critical)
```

---

## What it does (right now)

Project Clementine runs five sequential phases:

| Phase | What happens |
| --- | --- |
| 1 — Recon | Crawls endpoints, fingerprints tech stack, maps AWS resources from response headers |
| 2 — AWS Audit | cloud-audit and Prowler run in parallel; findings deduplicated and normalised. Builds the AWS knowledge graph: principals, compute, storage, and network nodes with IAM trust and permission edges |
| 3 — App Test | Full OWASP WSTG test suite via AutoPentest AI; Playwright validates DOM-based findings |
| 3.5 — AI Triage | Claude scores each finding: confidence, false-positive flag, and rationale. Skipped when `ANTHROPIC_API_KEY` is unset |
| 4 — Correlation | Rule-based pattern engine (46 patterns) fuses app + infra findings into compound attack chains using multi-hop graph traversal. Bridges web-app SSRF findings into the AWS graph. Optional AI chain discovery proposes novel paths |
| 5 — Reporting | HTML (with interactive Attack Graph), JSON, SARIF, Markdown, and optional AWS Security Hub push |

---

## AWS Knowledge Graph

Phase 2 constructs a directed graph `G = (V, E)` over the AWS environment:

**Nodes (V)** — IAM users and roles, EC2 instances, EKS pods and nodes, Lambda functions, S3 buckets, RDS instances, Secrets Manager secrets, SSM parameters, VPCs, security groups, VPC endpoints, IMDS (`169.254.169.254`), and web endpoints from AutoPentest AI.

**Edges (E)** — IAM trust relationships (`CAN_ASSUME`), permission grants (`HAS_PERMISSION`, `CAN_PASS_ROLE`), compute attachments (`ATTACHED_TO`, `HOSTS_APP`), network topology (`ROUTES_TO`, `INTERNET_FACING`), exploit paths (`SSRF_REACHABLE`), and EKS IRSA bindings (`IRSA_BOUND`, `OIDC_TRUSTS`).

The graph persists across phases. Phase 4 reconstructs it from the database and bridges SSRF findings from the application layer as `SSRF_REACHABLE` edges into the IMDS node. The correlation engine uses multi-hop graph traversal (up to 4 hops by default) instead of the previous single-hop adjacency check — allowing patterns like `web endpoint → EC2 → IAM role → S3` to be detected automatically.

The HTML report includes an **Attack Graph** tab with a force-directed canvas renderer:

- Purple nodes — IAM principals (roles, users, EKS service accounts)
- Blue nodes — Compute (EC2, EKS pods/nodes)
- Green nodes — Storage (S3, RDS, Secrets Manager, SSM)
- Amber nodes — Lambda functions
- Red nodes — Web endpoints and IMDS
- Teal nodes — Network (VPC, security groups)
- Dashed red edges — Exploit paths (SSRF reachable, internet-facing)

Nodes are colour-bordered by the severity of their linked findings. Drag to pan. The graph is omitted from the report when no graph nodes exist in the database.

---

## Prerequisites

| Tool | Purpose | Install |
| --- | --- | --- |
| Python ≥ 3.11 | Runtime | [python.org](https://python.org) |
| Docker | AutoPentest AI security tools container | [docker.com](https://docker.com) |
| Node.js ≥ 18 | Playwright MCP server | [nodejs.org](https://nodejs.org) |
| `uv` / `uvx` | cloud-audit and Prowler MCP servers | `pip install uv` |
| AWS CLI | Configured profile with read-only audit permissions | `pip install awscli` |
| Prowler CLI | Compliance scanning (optional — gracefully skipped if absent) | `pip install prowler` |
| Anthropic API key | AI triage and novel-chain discovery (optional) | Set `ANTHROPIC_API_KEY` env var |

### AWS audit permissions

The AWS profile used for scanning needs read-only access. Attach these managed policies to the role/user:

```bash
aws iam attach-user-policy \
  --user-name security-audit \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-user-policy \
  --user-name security-audit \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
```

**Never grant write permissions to the audit credentials.**

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/project-clementine
cd project-clementine

# Install the package and its dependencies
pip install -e .

# Verify the CLI is available
clementine --version
```

### Pull the AutoPentest AI Docker image

```bash
docker pull dylshroll/autopentest-tools:latest

# Start the container (keep it running in the background)
docker run -d --name autopentest-tools dylshroll/autopentest-tools:latest tail -f /dev/null
```

### Install the Node.js MCP server

```bash
npm install -g @anthropic/mcp-playwright
```

---

## Configuration

Copy the example config and edit it for your target:

```bash
cp clementine.example.yaml clementine.yaml
```

Set all credentials as environment variables — **never put secrets directly in the YAML file**:

```bash
export APP_USERNAME="testuser"
export APP_PASSWORD="testpass"
export AWS_AUDIT_PROFILE="security-audit"
export AWS_ACCOUNT_ID="123456789012"
```

Then edit `clementine.yaml` to set your target URL and scope:

```yaml
target:
  url: "https://app.example.com"
  scope:
    include_domains:
      - "app.example.com"
      - "api.example.com"
    exclude_paths:
      - "/admin/dangerous-action"
    rate_limit_rps: 10
```

### Authentication methods

```yaml
# Username / password
auth:
  method: "credentials"
  username: "${APP_USERNAME}"
  password: "${APP_PASSWORD}"
  login_url: "https://app.example.com/login"

# Bearer token
auth:
  method: "token"
  bearer_token: "${API_TOKEN}"

# Pre-authenticated cookie
auth:
  method: "cookie"
  cookie: "${SESSION_COOKIE}"

# No authentication
auth:
  method: "none"
```

---

## Usage

### Run a full assessment

```bash
clementine run --config clementine.yaml
```

Reports are written to `./reports/` by default:

- `reports/report.html` — interactive HTML with severity filtering, attack chain step-flow, remediation playbook, and Attack Graph visualisation
- `reports/report.json` — machine-readable JSON
- `reports/report.sarif` — for IDE and CI/CD consumption
- `reports/report.md` — for Git repository integration

### Override output format and directory

```bash
clementine run --config clementine.yaml --format sarif --output ./ci-results
```

`--format` is repeatable:

```bash
clementine run --config clementine.yaml --format html --format json
```

### CI/CD severity gate

Exit non-zero if any HIGH or CRITICAL findings exist:

```bash
clementine check --config clementine.yaml --max-severity HIGH
```

Exit codes: `0` = pass, `1` = findings at or above the threshold.

### Regenerate reports from an existing database

After a completed run, regenerate reports in a different format without re-running the full assessment:

```bash
clementine report --config clementine.yaml --format markdown
```

### Debug logging

```bash
clementine run --config clementine.yaml --debug
```

---

## GitHub Actions integration

```yaml
# .github/workflows/security.yml
name: Security Assessment
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

jobs:
  clementine:
    runs-on: ubuntu-latest
    services:
      autopentest:
        image: bhavsec/autopentest-tools:latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Clementine
        run: pip install -e .

      - name: Run assessment
        env:
          APP_USERNAME: ${{ secrets.TEST_APP_USERNAME }}
          APP_PASSWORD: ${{ secrets.TEST_APP_PASSWORD }}
          AWS_AUDIT_PROFILE: default
          AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AUDIT_AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AUDIT_AWS_SECRET_ACCESS_KEY }}
        run: |
          clementine run --config clementine.yaml --format sarif --output results

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/report.sarif

      - name: Gate on severity
        run: clementine check --config clementine.yaml --max-severity HIGH
```

---

## Docker Compose (continuous monitoring)

```yaml
# docker-compose.yml
services:
  clementine:
    build: .
    environment:
      - AWS_AUDIT_PROFILE=security-audit
      - APP_USERNAME=${APP_USERNAME}
      - APP_PASSWORD=${APP_PASSWORD}
      - AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID}
    volumes:
      - ./clementine.yaml:/config/clementine.yaml:ro
      - ./reports:/reports
      - ~/.aws:/root/.aws:ro
    depends_on:
      - db
      - autopentest

  autopentest:
    image: bhavsec/autopentest-tools:latest

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: clementine
      POSTGRES_USER: clementine
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

Set `finding_db: "postgresql://clementine:${DB_PASSWORD}@db:5432/clementine"` in `clementine.yaml`.

---

## Attack pattern library

Compound attack patterns live in `patterns/` as YAML files. 46 built-in patterns span injection, authentication, cloud infrastructure, privilege escalation, supply chain, and client-side attack classes. All patterns use the same rule format and are auto-discovered at startup — no code changes needed to add or remove them.

### Injection

| Pattern | Entry | Severity |
| --- | --- | --- |
| `ssrf_imds_iam.yaml` | SSRF → IMDSv1 → overprivileged IAM role | CRITICAL |
| `xxe_ssrf_internal_pivot.yaml` | XXE → SSRF to IMDS + internal services | CRITICAL |
| `ssti_rce_credential_theft.yaml` | SSTI → RCE → IMDS IAM credential theft | CRITICAL |
| `cmd_injection_imds_credential_theft.yaml` | OS command injection → IMDSv1 → CloudTrail-blind account access | CRITICAL |
| `insecure_deserialization_rce_pivot.yaml` | Insecure deserialization → RCE → cloud credential theft | CRITICAL |
| `unrestricted_file_upload_rce.yaml` | Web shell upload → RCE → IMDS credential theft | CRITICAL |
| `log4shell_rce_imds_chain.yaml` | Expression-language injection → RCE → GuardDuty-blind account takeover | CRITICAL |
| `sqli_rds_exfil.yaml` | SQLi → unencrypted RDS → no audit logging | CRITICAL |
| `nosqli_auth_bypass_data_access.yaml` | NoSQLi operator injection → auth bypass → unencrypted data access | HIGH |

### Authentication & Session

| Pattern | Entry | Severity |
|---|---|---|
| `jwt_weak_secret_privilege_escalation.yaml` | Weak JWT secret → forged admin token → privilege escalation | CRITICAL |
| `exposed_secrets_lateral.yaml` | Hardcoded creds → stale IAM key → lateral movement | CRITICAL |
| `path_traversal_source_secrets.yaml` | Path traversal → config/source read → stale IAM key | CRITICAL |
| `oauth_open_redirect_token_theft.yaml` | Open redirect → auth code interception → persistent token | HIGH |
| `xss_session_hijack.yaml` | XSS → missing HttpOnly → admin session theft | HIGH |
| `no_mfa_brute_force_takeover.yaml` | No MFA + no account lockout → brute force → root/admin takeover | HIGH |
| `subdomain_takeover_session_theft.yaml` | Dangling CNAME → subdomain takeover → session cookie theft | HIGH |
| `csrf_privileged_state_change.yaml` | CSRF + no SameSite cookie → admin state-changing action | HIGH |

### Authorisation & Access Control

| Pattern | Entry | Severity |
| --- | --- | --- |
| `broken_function_level_auth_rce.yaml` | BFLA → admin endpoint → RCE → cloud credentials | CRITICAL |
| `graphql_introspection_idor.yaml` | GraphQL schema exposure + BOLA → automated bulk data extraction | HIGH |
| `idor_bulk_pii_harvest.yaml` | IDOR + no rate limit + plaintext transport → mass PII dump | HIGH |

### AWS Infrastructure

| Pattern | Entry | Severity |
| --- | --- | --- |
| `cognito_unauth_role_escalation.yaml` | Cognito guest identity → overprivileged role → direct AWS API access | CRITICAL |
| `iam_trust_policy_too_broad.yaml` | Wildcard trust policy → any credential assumes privileged role | CRITICAL |
| `cloudformation_iam_privilege_escalation.yaml` | CFn stack role + iam:PassRole → template-triggered admin escalation | CRITICAL |
| `ecs_task_escape_overprivileged_role.yaml` | Privileged ECS container → host escape → IMDS → account compromise | CRITICAL |
| `lambda_env_secrets_exposed.yaml` | Lambda env var secrets + overprivileged role → account compromise | CRITICAL |
| `rds_public_snapshot_data_dump.yaml` | Public RDS snapshot + no encryption → unauthenticated database dump | CRITICAL |
| `ecr_public_image_secrets.yaml` | Public ECR image + embedded secrets + no scanning | CRITICAL |
| `ssm_parameter_store_ssrf_exfil.yaml` | SSRF + SSM GetParameter over-privilege → plaintext secret exfil | CRITICAL |
| `s3_public_bucket_sensitive_data.yaml` | Public S3 bucket + no MFA delete + no access logging | HIGH |
| `open_sg_ssrf_pivot.yaml` | Open security group → public EC2 → SSRF internal pivot | HIGH |
| `missing_logging_blind_exploit.yaml` | No CloudTrail + no GuardDuty + no Config → blind exploitation | HIGH |

### Privilege Escalation

| Pattern | Entry | Severity |
| --- | --- | --- |
| `lambda_backdoor_privilege_escalation.yaml` | Excessive Lambda permissions + iam:PassRole → code execution under privileged role | HIGH |
| `iam_policy_rollback_privilege_escalation.yaml` | iam:SetDefaultPolicyVersion + stale permissive policy versions → self-escalation without new resources | HIGH |
| `glue_dev_endpoint_privilege_escalation.yaml` | glue:CreateDevEndpoint + iam:PassRole → arbitrary code under any passable role | HIGH |
| `eks_hostnetwork_imds_credential_theft.yaml` | EKS pod hostNetwork:true + IMDSv1 + overprivileged node role → IMDS credential theft | CRITICAL |
| `eks_irsa_oidc_trust_too_broad.yaml` | IRSA OIDC trust wildcard → any pod assumes overprivileged IAM role | HIGH |

### Supply Chain

| Pattern | Entry | Severity |
|---|---|---|
| `ci_oidc_misconfiguration_supply_chain.yaml` | OIDC trust too broad → any repo assumes role → artefact poisoning | CRITICAL |

### Adding a custom pattern

Create a new file in `patterns/` — no code changes needed:

```yaml
# patterns/my_custom_pattern.yaml

pattern:
  name: "My custom attack chain"
  severity: HIGH

entry:
  type: app_finding          # app_finding | infra_finding
  category: IDOR             # matched against finding title/category
  wstg: WSTG-ATHZ            # optional WSTG code prefix

pivot:
  - type: infra_finding
    check: iam-role-overprivileged
    relationship: same_account  # same_account | same_compute_resource

impact: >
  Describe what an attacker can achieve by chaining these findings.

remediation_priority:
  - summary: "The single fix that breaks the chain"
    effort: LOW               # LOW | MEDIUM | HIGH
    breaks_chain: true
  - summary: "Secondary fix"
    effort: MEDIUM
    breaks_chain: false
```

Restart the tool — the new pattern is picked up automatically.

---

## Configuration reference

| Key | Default | Description |
 | --- | --- | --- |
| `target.url` | required | Primary URL to assess |
| `target.scope.include_domains` | required | Domains in scope (subdomains included) |
| `target.scope.exclude_paths` | `[]` | URL path prefixes to never touch |
| `target.scope.rate_limit_rps` | `10` | Max requests/second across all tools |
| `auth.method` | `none` | `credentials` / `token` / `cookie` / `none` |
| `aws.profile` | `default` | AWS CLI profile for the audit role |
| `aws.regions` | `[us-east-1]` | Regions to scan |
| `compliance.frameworks` | `[cis_2.0_aws]` | Prowler compliance frameworks |
| `reporting.formats` | `[html, json]` | `html` / `json` / `sarif` / `markdown` |
| `reporting.output_dir` | `./reports` | Directory for report files |
| `reporting.push_to_security_hub` | `false` | Push findings to AWS Security Hub |
| `orchestrator.finding_db` | `sqlite:///findings.db` | SQLite path or PostgreSQL DSN |
| `orchestrator.pause_between_phases` | `false` | Wait for ENTER before each phase |
| `orchestrator.log_level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## MCP servers

| Server | Transport | Required | Purpose |
 | --- | --- | --- | --- |
| AutoPentest AI | stdio (Docker) | Yes | OWASP WSTG application testing |
| cloud-audit | stdio (`uvx`) | Yes | AWS configuration scanning |
| Prowler | stdio (`uvx`) | No | Compliance framework mapping |
| AWS Knowledge | HTTP (remote) | No | Remediation SOP enrichment |
| AWS Documentation | stdio (`uvx`) | No | Documentation link enrichment |
| Playwright | stdio (`npx`) | No | DOM-based PoC validation |

Clementine degrades gracefully when non-critical servers are unavailable — the assessment continues with reduced enrichment and a warning in the logs.

---

## Security notes

- **Credentials** are read from environment variables at startup and never written to disk.
- **Scope enforcement** is applied at the orchestrator before every MCP tool call — no request is ever sent outside `include_domains`.
- **Rate limiting** is enforced centrally, not delegated to individual tools.
- **Evidence** stored in the database is scrubbed of `Authorization`, `Cookie`, `Bearer`, and password values before writing.
- **AWS audit credentials** should have `SecurityAudit` + `ViewOnlyAccess` only — no write permissions.
- Use **dedicated test accounts** for application credentials; rotate them after each assessment.

---

## Resuming a failed assessment

If a run fails mid-assessment, the orchestrator saves its state to the database. Re-running the same command resumes from the last completed phase:

```bash
# Original run fails partway through Phase 3
clementine run --config clementine.yaml

# Fix the issue, re-run — phases 1 and 2 are skipped automatically
clementine run --config clementine.yaml
```

To force a full restart, delete the findings database:

```bash
rm findings.db
clementine run --config clementine.yaml
```

## Things I want to do with the project

- Embeddings model layer on top of the knowledge graph for semantic similarity search and novel exploit chain suggestion
- GUI / web dashboard for live assessment monitoring
- Azure, GCP integrations
- IaC scanning (Terraform, CloudFormation, CDK)
- Additional correlation patterns based on emerging exploit paths
- Increase backoff time on `clementine.mcp_client` failures during rate-limit errors
- Decrease costs/scan.
- Increase llm tracability/visibility
