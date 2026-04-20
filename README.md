# Project Clementine

Automated web-app penetration-testing orchestrator. Coordinates six security MCP servers to deliver assessments that span both application-layer vulnerabilities (OWASP WSTG) and AWS infrastructure misconfigurations — then automatically correlates them into compound attack chains that neither layer of tooling can find on its own.

```
SSRF (medium)  +  IMDSv1 enabled  +  overprivileged IAM role  =  full account takeover (critical)
```

---

## What it does

Project Clementine runs five sequential phases:

| Phase | What happens |
|---|---|
| 1 — Recon | Crawls endpoints, fingerprints tech stack, maps AWS resources from response headers |
| 2 — AWS Audit | cloud-audit and Prowler run in parallel; findings deduplicated and normalised |
| 3 — App Test | Full OWASP WSTG test suite via AutoPentest AI; Playwright validates DOM-based findings |
| 4 — Correlation | Pattern engine fuses app + infra findings into compound attack chains |
| 5 — Reporting | HTML, JSON, SARIF, Markdown, and optional AWS Security Hub push |

---

## Prerequisites

| Tool | Purpose | Install |
|---|---|---|
| Python ≥ 3.11 | Runtime | [python.org](https://python.org) |
| Docker | AutoPentest AI security tools container | [docker.com](https://docker.com) |
| Node.js ≥ 18 | Playwright MCP server | [nodejs.org](https://nodejs.org) |
| `uv` / `uvx` | cloud-audit and Prowler MCP servers | `pip install uv` |
| AWS CLI | Configured profile with read-only audit permissions | `pip install awscli` |
| Prowler CLI | Compliance scanning (optional — gracefully skipped if absent) | `pip install prowler` |

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
docker pull bhavsec/autopentest-tools:latest

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
- `reports/report.html` — interactive HTML with severity filtering
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

Compound attack patterns live in `patterns/` as YAML files. The six built-in patterns are:

| Pattern | Entry | Severity |
|---|---|---|
| `ssrf_imds_iam.yaml` | SSRF → IMDSv1 → overprivileged IAM role | CRITICAL |
| `sqli_rds_exfil.yaml` | SQLi → unencrypted RDS → no audit logging | CRITICAL |
| `exposed_secrets_lateral.yaml` | Hardcoded creds → stale IAM key → lateral movement | CRITICAL |
| `xss_session_hijack.yaml` | XSS → missing HttpOnly → admin session theft | HIGH |
| `open_sg_ssrf_pivot.yaml` | Open security group → public EC2 → SSRF pivot | HIGH |
| `missing_logging_blind_exploit.yaml` | No CloudTrail + no GuardDuty + no Config | HIGH |

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
|---|---|---|
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
|---|---|---|---|
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
