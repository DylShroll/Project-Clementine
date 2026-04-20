# Project Clementine — Automated Web-App Pen-Testing Orchestrator

## Design Specification v0.1

**Status:** Draft
**Author:** Dylan Shroll
**Date:** January 2026

---

## 1. Executive summary

Project Clementine is an automated security assessment platform that orchestrates multiple MCP (Model Context Protocol) servers to deliver holistic web application penetration testing. It evaluates not only application-layer vulnerabilities (OWASP WSTG methodology) but also AWS infrastructure misconfigurations, compliance posture, and — critically — the compound attack paths that emerge when application and infrastructure weaknesses combine.

### 1.1 Problem statement

Today's security tooling falls into two silos:

- **Application pen-testing tools** (nuclei, sqlmap, Burp Suite) find XSS, SQLi, and auth bypass but are blind to the cloud infrastructure beneath.
- **Cloud security posture tools** (Prowler, cloud-audit, AWS Security Hub) catch misconfigured security groups and overprivileged IAM roles but don't know the web application exists.

Neither silo asks the question that matters most: *"Can an attacker chain an application-layer vulnerability into an infrastructure compromise?"* An SSRF by itself is a medium finding. An SSRF on an EC2 instance running IMDSv1 with an admin IAM role attached is a full account takeover. Project Clementine exists to connect those dots.

### 1.2 Design goals

- **Unified assessment**: Application-layer, infrastructure, and compliance testing in a single orchestrated workflow.
- **Cross-domain correlation**: Automatically identify compound attack paths that span application and infrastructure boundaries.
- **Knowledge-enriched remediation**: Every finding includes current AWS best-practice guidance sourced from official AWS MCP servers, not stale training data.
- **Actionable reporting**: Reports are structured for multiple audiences — executive risk summaries, technical reproduction steps, compliance evidence, and copy-paste remediation commands.
- **Extensibility**: New MCP servers can be added to the orchestrator without modifying core logic.

---

## 2. Architecture overview

Project Clementine follows a hub-and-spoke architecture. The orchestration engine (hub) coordinates six MCP servers (spokes) across five sequential assessment phases. Findings flow into a shared data store, where a cross-domain correlation engine fuses them into compound attack narratives before the reporting pipeline produces output.

```
┌────────────────────────────────────────────────────────────┐
│                   Project Clementine orchestrator                     │
│                                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Phase 1  │→ │ Phase 2  │→ │ Phase 3  │→ │ Phase 4  │  │
│  │ Recon    │  │ AWS Audit│  │ App Test │  │ Correlate│  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │              │        │
│       ▼              ▼              ▼              ▼        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Shared findings store                   │   │
│  └─────────────────────┬───────────────────────────────┘   │
│                        │                                    │
│                        ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          Cross-domain correlation engine              │   │
│  └─────────────────────┬───────────────────────────────┘   │
│                        │                                    │
│                        ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Knowledge enrichment layer                  │   │
│  │         (AWS Knowledge + Docs MCP servers)            │   │
│  └─────────────────────┬───────────────────────────────┘   │
│                        │                                    │
│                        ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │       Phase 5 — Unified reporting pipeline            │   │
│  │   HTML  │  JSON/SARIF  │  Security Hub  │  Markdown   │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘

MCP servers (connected via stdio or HTTP transport):

  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
  │ AutoPentest │ │ cloud-audit │ │   Prowler   │
  │  AI (WSTG)  │ │(AWS config) │ │(compliance) │
  └─────────────┘ └─────────────┘ └─────────────┘
  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
  │AWS Knowledge│ │  AWS Docs   │ │ Playwright  │
  │   (SOPs)    │ │  (API refs) │ │  (browser)  │
  └─────────────┘ └─────────────┘ └─────────────┘
```

### 2.1 Component roles

| Component | Responsibility | Interface |
| --- | --- | --- |
| Orchestration engine | Phase sequencing, parallel dispatch, state management, MCP server lifecycle | Core process |
| Shared findings store | Normalized storage for all findings, metadata, and evidence | SQLite / PostgreSQL |
| Correlation engine | Fuses app-layer and infra findings into compound attack paths | Internal module |
| Knowledge enrichment | Augments findings with current AWS guidance and remediation | AWS MCP servers |
| Reporting pipeline | Multi-format output generation | Templated renderers |

---

## 3. MCP server inventory

### 3.1 AutoPentest AI

- **Purpose**: Application-layer penetration testing using the full OWASP Web Security Testing Guide methodology.
- **Source**: `github.com/bhavsec/autopentest-ai`
- **Transport**: stdio (local Docker container)
- **Key capabilities**:
  - 109 OWASP WSTG test procedures across 10 categories
  - 31 PortSwigger attack technique guides integrated into testing phases
  - 68+ MCP tools for test execution, finding management, coverage tracking
  - 27 Dockerized security tools: nuclei, sqlmap, dalfox, katana, ffuf, nmap, httpx, and more
  - 4 specialized agent roles with dedicated prompt templates
  - Multi-layered QA system with quality gates preventing shallow testing
  - Authentication escalation procedure (6 levels)
- **MCP tools used by Project Clementine**:
  - `create_engagement` — Initialize a new testing engagement with target scope
  - `get_technique_guide` — Load attack-specific methodology before each test category
  - `run_test` — Execute individual WSTG test procedures
  - `get_findings` — Retrieve validated findings with evidence
  - `get_coverage` — Check test completion percentages per category
  - `generate_report` — Produce the final AutoPentest report
- **Configuration**:

  ```json
  {
    "autopentest-ai": {
      "command": "docker",
      "args": ["exec", "-i", "autopentest-tools", "python", "-m", "server"],
      "env": {
        "TARGET_URL": "${TARGET_URL}",
        "AUTH_CONFIG": "${AUTH_CONFIG_PATH}"
      }
    }
  }
  ```

### 3.2 cloud-audit

- **Purpose**: Fast, opinionated AWS security scanning with attack chain detection and financial risk estimation.
- **Source**: `github.com/gebalamariusz/cloud-audit`
- **Transport**: stdio (local process)
- **Key capabilities**:
  - 47 checks across 15 AWS resource types (IAM, S3, EC2, VPC, RDS, Lambda, ECS, CloudTrail, GuardDuty, KMS, SSM, Secrets Manager, CloudWatch, AWS Config, EIP)
  - 16 CIS AWS Foundations Benchmark control mappings
  - 16 attack chain correlation rules (compound risk detection)
  - Breach cost estimation based on published data (IBM Cost of a Data Breach, Verizon DBIR)
  - Copy-paste remediation: AWS CLI commands + Terraform HCL for every finding
  - Scan diffing for drift detection
- **MCP tools used by Project Clementine**:
  - `scan_aws` — Execute a full AWS account scan
  - `get_findings` — Retrieve findings with severity, resource, and remediation
  - `get_attack_chains` — Retrieve correlated compound attack paths
  - `get_remediation` — Get specific fix commands for a finding
  - `get_health_score` — Overall security health score (0-100)
  - `list_checks` — Enumerate available checks
- **Configuration**:

  ```json
  {
    "cloud-audit": {
      "command": "uvx",
      "args": ["cloud-audit-mcp"],
      "env": {
        "AWS_PROFILE": "${AWS_AUDIT_PROFILE}",
        "AWS_DEFAULT_REGION": "${AWS_REGION}"
      }
    }
  }
  ```

### 3.3 Prowler

- **Purpose**: Comprehensive multi-framework compliance assessment and cloud security posture management.
- **Source**: `github.com/prowler-cloud/prowler` (MCP server component)
- **Transport**: stdio (local process) or HTTP (Prowler Cloud API)
- **Key capabilities**:
  - 584+ security checks for AWS
  - Full CIS, NIST 800, NIST CSF, CISA, FedRAMP, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, ISO 27001, AWS Well-Architected, and AWS FTR framework mappings
  - ThreatScore weighted risk prioritization
  - Attack path analysis via Neo4j graph (Prowler App)
  - Security Hub native integration
  - Auto-remediation with `--fix` flag
- **MCP tools used by Project Clementine**:
  - Knowledge base queries (free tier): check descriptions, remediation scripts, compliance mappings
  - Scan execution and findings retrieval (requires Prowler Cloud API key for managed features)
- **Configuration** (knowledge base, no API key required):

  ```json
  {
    "prowler": {
      "command": "uvx",
      "args": ["prowler-mcp-server"],
      "env": {}
    }
  }
  ```

- **Note**: For full scan execution within Project Clementine, Prowler CLI is invoked directly via subprocess rather than MCP, with output parsed into the shared findings store. The MCP server is used for knowledge base enrichment and remediation guidance.

### 3.4 AWS Knowledge MCP Server

- **Purpose**: Real-time access to AWS documentation, best practices, architectural guidance, and Agent SOPs.
- **Source**: AWS-managed remote service (GA)
- **Transport**: HTTP (Streamable HTTP)
- **Endpoint**: `https://knowledge-mcp.global.api.aws`
- **Key capabilities**:
  - Indexes AWS Documentation, What's New posts, Getting Started info, blog posts, Builder Center content, architectural references, and Well-Architected guidance
  - Agent SOPs for complex workflows: deployment, troubleshooting, security, infrastructure setup
  - Regional availability information for AWS APIs and CloudFormation resources
  - No AWS account required for basic usage
- **MCP tools used by Project Clementine**:
  - `search` — Search across all indexed AWS knowledge sources
  - `recommend` — Get content recommendations for specific documentation pages
  - `list_regions` — Retrieve AWS region identifiers
  - `get_regional_availability` — Check service/feature availability by region
  - `retrieve_agent_sops` — Retrieve step-by-step workflows for complex tasks
- **Configuration**:

  ```json
  {
    "aws-knowledge-mcp-server": {
      "url": "https://knowledge-mcp.global.api.aws",
      "type": "http"
    }
  }
  ```

### 3.5 AWS Documentation MCP Server

- **Purpose**: Deep page-level access to AWS documentation with search and recommendation capabilities.
- **Source**: `github.com/awslabs/mcp` (open source, client-hosted)
- **Transport**: stdio (local process)
- **Key capabilities**:
  - Fetch and convert AWS documentation pages to markdown
  - Full-text search across AWS documentation corpus
  - Content recommendations based on page relationships
  - Supports both global AWS and AWS China partitions
- **MCP tools used by Project Clementine**:
  - `read_documentation` — Fetch a specific documentation page as markdown
  - `search_documentation` — Search AWS docs by phrase, with optional product/guide type filters
  - `recommend` — Get related content recommendations
- **Configuration**:

  ```json
  {
    "aws-documentation-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.aws-documentation-mcp-server@latest"],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "AWS_DOCUMENTATION_PARTITION": "aws"
      }
    }
  }
  ```

### 3.6 Playwright MCP Server

- **Purpose**: Browser-based testing for vulnerabilities that require a live DOM environment.
- **Source**: `github.com/anthropics/mcp-playwright` (or equivalent)
- **Transport**: stdio (local process)
- **Key capabilities**:
  - DOM-based XSS proof-of-concept generation and validation
  - Clickjacking frame-busting bypass testing
  - JavaScript-rendered authentication flow testing
  - Client-side storage inspection (localStorage, sessionStorage, cookies)
  - Single-page application (SPA) state manipulation
  - Screenshot capture for evidence collection
- **MCP tools used by Project Clementine**:
  - `navigate` — Load a URL in the headless browser
  - `evaluate` — Execute JavaScript in page context
  - `screenshot` — Capture visual evidence
  - `click` / `fill` / `select` — Interact with page elements
  - `get_cookies` — Inspect cookie attributes (Secure, HttpOnly, SameSite)

### 3.7 Future: Unified AWS MCP Server (Preview)

AWS has announced a unified MCP server (currently in preview) that consolidates the Knowledge MCP and API MCP capabilities into a single endpoint. When this reaches GA, Project Clementine should migrate from the separate Knowledge + Documentation servers to the unified server. Key additions:

- Syntactically validated AWS API call execution
- IAM-based authentication with zero credential exposure
- CloudTrail audit logging for all API operations
- Combined search across documentation, API references, and Agent SOPs

Migration path: Replace the two AWS server entries in `mcp-config.json` with a single unified server entry and update tool call references in the orchestrator.

---

## 4. Assessment phases

### 4.1 Phase 1 — Reconnaissance and asset discovery

**Goal**: Build a complete map of the target's web attack surface and the AWS infrastructure topology beneath it.

**Sub-phases**:

1. **Target scoping**: Accept target URL(s), authentication credentials, and scope boundaries (in-scope domains, out-of-scope paths, rate limits).

2. **Web surface discovery** (via AutoPentest AI):
   - Crawl with katana to discover endpoints, forms, API routes
   - Probe with httpx for live hosts, status codes, technology fingerprinting
   - Fuzz with ffuf for hidden paths, backup files, admin panels
   - Fingerprint frameworks, languages, and server software via response headers and content patterns

3. **AWS resource mapping** (via AWS Knowledge MCP + cloud-audit):
   - Identify AWS services in use from response headers (CloudFront, ALB, API Gateway, S3, Lambda)
   - Map the relationship between web endpoints and AWS resources
   - Enumerate publicly accessible AWS resources (S3 buckets, API Gateway stages, CloudFront distributions)

4. **Output**: A target manifest document stored in the findings database:

   ```yaml
   target:
     primary_url: "https://app.example.com"
     domains:
       - app.example.com
       - api.example.com
       - static.example.com
     endpoints: [...]  # Discovered URL list with method, params, auth requirements
     aws_services:
       - service: cloudfront
         distribution: E1234567890
       - service: alb
         arn: arn:aws:elasticloadbalancing:us-east-1:...
       - service: ec2
         instance_ids: [i-0abc123def456]
         security_groups: [sg-12345]
         imds_version: v1  # CRITICAL FINDING SEED
       - service: rds
         endpoint: mydb.cluster-abc123.us-east-1.rds.amazonaws.com
         publicly_accessible: false
     technologies:
       - name: Django
         version: "4.2"
         confidence: high
   ```

### 4.2 Phase 2 — AWS configuration and compliance audit

**Goal**: Assess the security posture of the AWS infrastructure that hosts the target application.

**Execution strategy**: Run cloud-audit and Prowler in parallel, then merge and deduplicate findings.

**cloud-audit lane**:

1. Execute `scan_aws` against the target AWS account
2. Retrieve `get_findings` — all individual misconfigurations
3. Retrieve `get_attack_chains` — compound paths combining multiple findings
4. Retrieve `get_health_score` — aggregate posture metric

**Prowler lane**:

1. Execute Prowler CLI against the target account with framework filters relevant to the application's compliance requirements (e.g., `--compliance cis_2.0_aws` for baseline, `--compliance pci_4.0` for payment processing applications)
2. Parse JSON output into the shared findings schema
3. Cross-reference with Prowler MCP knowledge base for detailed remediation

**Deduplication logic**: Findings from both tools are normalized to the shared schema (see Section 6). Deduplication keys on `{aws_resource_arn, check_category, finding_type}`. When both tools report the same issue, Project Clementine keeps the richer finding (usually cloud-audit for remediation commands, Prowler for compliance mapping) and merges metadata from the other.

**Key check categories**:

| Category | cloud-audit checks | Prowler checks | Why it matters for web apps |
| --- | --- | --- | --- |
| IAM | Root MFA, access key rotation, overprivileged policies | 60+ IAM checks, credential report | Compromised app → IAM escalation path |
| Network | Public security groups, unrestricted ingress | VPC flow logs, NACLs, peering | Network-level exposure of backend services |
| Data | S3 public access, unencrypted RDS, KMS config | S3, RDS, EBS, DynamoDB encryption | Data exfiltration risk after app compromise |
| Logging | CloudTrail, GuardDuty, Config status | CloudWatch alarms, access logging | Attacker detection capability |
| Compute | IMDSv1, SSM patching, Lambda permissions | EC2, ECS, Lambda, EKS checks | SSRF → IMDS → credential theft |
| Secrets | Secrets Manager rotation, hardcoded creds | SSM Parameter Store, env vars | Credential exposure in application config |

### 4.3 Phase 3 — Application-layer penetration testing

**Goal**: Execute the full OWASP WSTG methodology against the target application's web endpoints.

**Execution strategy**: AutoPentest AI manages this phase through its internal 7-phase workflow. Project Clementine delegates to AutoPentest and monitors progress via coverage tracking tools.

**AutoPentest internal phases** (mapped to WSTG categories):

1. **Information gathering** (WSTG-INFO): 10 tests — web server fingerprinting, application mapping, entry point enumeration
2. **Configuration testing** (WSTG-CONF): 14 tests — including CORS misconfiguration (uses technique guide), file permission checks, admin interface exposure
3. **Authentication testing** (WSTG-ATHN): 11 tests — credential transport, default creds, lockout bypass, password policy (uses AUTHN, JWT, OAUTH technique guides)
4. **Authorization testing** (WSTG-ATHZ): Tests for IDOR, privilege escalation, path traversal to restricted resources
5. **Session management** (WSTG-SESS): Cookie attributes, session fixation, CSRF (uses CSRF technique guide)
6. **Input validation** (WSTG-INPV): SQLi, XSS, command injection, SSTI, SSRF, XXE, path traversal (uses dedicated technique guides per attack type, with WAF bypass patterns)
7. **Client-side testing** (WSTG-CLNT): DOM XSS, clickjacking, WebSocket security, client-side storage — **this sub-phase dispatches to Playwright MCP** for browser-based proof-of-concept validation

**Parallel execution model**: WSTG categories 2-5 can run concurrently on different endpoint subsets. Category 6 (input validation) is the most time-intensive and further parallelizes by attack type (SQLi agent, XSS agent, SSRF agent, etc.). Category 7 (client-side) runs last because it depends on findings from earlier categories to target the most promising endpoints.

**Quality gates** (enforced by AutoPentest's QA system):

- Each finding must include: evidence (request/response), severity classification, reproduction steps, and a confidence score.
- Zero false-positive policy: findings are validated with proof-of-concept before inclusion.
- Coverage thresholds: each WSTG category must reach ≥80% test completion or document why tests are not applicable.

**Authentication handling**: AutoPentest's 6-level authentication escalation procedure:

1. Unauthenticated testing
2. Self-registration
3. Provided credentials (standard user)
4. Provided credentials (admin user)
5. Session token injection
6. Authentication bypass attempts

### 4.4 Phase 4 — Cross-domain correlation

**Goal**: Identify compound attack paths that combine application-layer vulnerabilities with infrastructure misconfigurations.

This is the phase that distinguishes Project Clementine from running each tool independently. See Section 5 for the full correlation engine design.

**Input**: All findings from Phases 2 and 3, normalized in the shared findings store.

**Output**: A set of compound attack chains, each describing a multi-step attack path with:

- Entry point (the initial vulnerability, usually app-layer)
- Pivot points (infrastructure weaknesses that amplify the attack)
- Terminal impact (the worst-case outcome)
- Aggregate severity (higher than any individual finding)
- Estimated breach cost range

### 4.5 Phase 5 — Unified reporting

**Goal**: Produce actionable reports for multiple audiences from a single assessment.

**Report components**:

1. **Executive summary**
   - Overall security health score (composite of cloud-audit health score and app-layer finding severity distribution)
   - Number of compound attack chains by severity
   - Estimated breach cost exposure range (sourced from cloud-audit's financial modeling)
   - Top 5 findings by risk, each in one sentence
   - Compliance posture summary (frameworks passed/failed)

2. **Technical findings**
   - Organized by compound attack chains first (most critical), then individual findings by severity
   - Each finding includes:
     - Severity (Critical / High / Medium / Low / Informational)
     - Category (OWASP WSTG code, CIS Benchmark ID, or both)
     - Affected resource(s) (URL + AWS ARN where applicable)
     - Description
     - Evidence (HTTP request/response, screenshots, CLI output)
     - Reproduction steps
     - Remediation (AWS CLI command, Terraform HCL, or application code fix)
     - References (AWS documentation links, OWASP guide links)

3. **Compliance mapping**
   - Matrix of compliance frameworks vs. findings
   - Pass/fail status per control
   - Evidence references for audit purposes

4. **Remediation playbook**
   - Prioritized list of remediation actions
   - Grouped by effort level (quick wins, medium effort, architectural changes)
   - Each action enriched with AWS Knowledge MCP guidance (current SOPs, best practice documentation)
   - Dependency ordering (e.g., "fix IMDSv2 before addressing SSRF, since IMDSv2 breaks the attack chain regardless of the app fix")

**Output formats**:

- **HTML**: Interactive report with collapsible sections, severity filtering, and evidence viewer
- **Markdown**: For integration into Git repositories and documentation systems
- **JSON / SARIF**: Machine-readable format for CI/CD pipeline integration and IDE consumption
- **AWS Security Hub**: Findings pushed in ASFF (AWS Security Finding Format) for centralized security management

---

## 5. Cross-domain correlation engine

### 5.1 Rationale

Individual findings are atoms. Attack chains are molecules. The correlation engine is the chemistry.

A flat list of 200 findings from five different tools is noise. What matters is: *which combinations of findings create viable attack paths?* The correlation engine answers this by maintaining a directed graph of relationships between findings and evaluating them against a library of compound attack patterns.

### 5.2 Correlation graph model

The correlation engine builds an in-memory directed graph where:

- **Nodes** represent either findings or AWS resources
- **Edges** represent relationships: `exploits`, `leads_to`, `amplifies`, `hosted_on`, `has_access_to`

```
Finding: SSRF (app-layer)
    ──exploits──▶ Resource: EC2 i-0abc123
                      ──has_config──▶ Finding: IMDSv1 enabled
                                          ──leads_to──▶ Finding: Credential theft via IMDS
                                                            ──has_access_to──▶ Resource: IAM Role (admin)
                                                                                  ──amplifies──▶ Impact: Full account compromise
```

### 5.3 Compound attack pattern library

Project Clementine ships with a curated library of cross-domain attack patterns. Each pattern is a template that the correlation engine matches against the findings graph.

#### Pattern: SSRF → IMDS → IAM escalation

```yaml
pattern:
  name: "SSRF to AWS credential theft"
  severity: CRITICAL
  entry:
    type: app_finding
    category: SSRF
    wstg: WSTG-INPV-09
  pivot:
    - type: infra_finding
      check: aws-ec2-imdsv1-enabled
      relationship: same_compute_resource
    - type: infra_finding
      check: iam-role-overprivileged
      relationship: attached_to_compute_resource
  impact: "Attacker exploits SSRF to reach IMDSv1 endpoint, steals temporary IAM credentials, and uses overprivileged role for lateral movement or data exfiltration."
  remediation_priority:
    - "Enforce IMDSv2 (breaks chain immediately, lowest effort)"
    - "Restrict SSRF vector in application code"
    - "Apply least-privilege to IAM role"
```

#### Pattern: SQLi → RDS → data exfiltration

```yaml
pattern:
  name: "SQL injection to database exfiltration"
  severity: CRITICAL
  entry:
    type: app_finding
    category: SQLi
    wstg: WSTG-INPV-05
  pivot:
    - type: infra_finding
      check: rds-no-encryption-at-rest
      relationship: same_data_store
    - type: infra_finding
      check: rds-no-audit-logging
      relationship: same_data_store
    - type: infra_finding
      check: cloudtrail-not-enabled
      relationship: same_account
  impact: "Attacker exploits SQLi to exfiltrate database contents. Lack of encryption means stolen backups/snapshots are readable. Absent audit logging means the exfiltration goes undetected."
  remediation_priority:
    - "Fix SQL injection vulnerability in application code"
    - "Enable RDS audit logging for detection"
    - "Enable encryption at rest for data protection"
    - "Enable CloudTrail for API-level visibility"
```

#### Pattern: XSS → session hijack → admin takeover

```yaml
pattern:
  name: "XSS to admin session theft"
  severity: HIGH
  entry:
    type: app_finding
    category: XSS
    wstg: WSTG-INPV-01
  pivot:
    - type: app_finding
      check: cookie-missing-httponly
      wstg: WSTG-SESS-02
    - type: app_finding
      check: no-csp-header
      wstg: WSTG-CONF-12
  impact: "Stored or reflected XSS combined with missing HttpOnly cookies allows session token theft. Absent CSP means no browser-level mitigation."
  remediation_priority:
    - "Set HttpOnly flag on session cookies (breaks chain)"
    - "Implement Content-Security-Policy header"
    - "Fix XSS vulnerability in application code"
```

#### Pattern: Open security group → public instance → SSRF pivot

```yaml
pattern:
  name: "Network exposure to internal pivot"
  severity: HIGH
  entry:
    type: infra_finding
    check: security-group-unrestricted-ingress
  pivot:
    - type: infra_finding
      check: ec2-public-ip-assigned
      relationship: same_security_group
    - type: app_finding
      category: SSRF
      relationship: same_compute_resource
  impact: "Publicly accessible EC2 instance with permissive security group hosts an application vulnerable to SSRF, enabling internal network reconnaissance and pivot to private resources."
  remediation_priority:
    - "Restrict security group to required ports/sources"
    - "Place instances behind ALB/CloudFront"
    - "Fix SSRF vulnerability"
```

#### Pattern: Exposed secrets → credential reuse → lateral movement

```yaml
pattern:
  name: "Secret exposure to lateral movement"
  severity: CRITICAL
  entry:
    type: app_finding
    category: information_disclosure
    detail: "Hardcoded credentials, .env file exposure, or git history leak"
  pivot:
    - type: infra_finding
      check: iam-access-key-not-rotated
      relationship: same_credential
    - type: infra_finding
      check: iam-user-overprivileged
      relationship: same_identity
  impact: "Leaked credentials from application source or configuration are still active (not rotated) and attached to an overprivileged IAM identity, enabling direct AWS API access."
  remediation_priority:
    - "Rotate compromised credentials immediately"
    - "Remove hardcoded secrets from application"
    - "Implement Secrets Manager with automatic rotation"
    - "Apply least-privilege to IAM identity"
```

#### Pattern: Missing logging → blind exploitation

```yaml
pattern:
  name: "Zero security visibility"
  severity: HIGH
  entry:
    type: infra_finding
    check: cloudtrail-not-enabled
  pivot:
    - type: infra_finding
      check: guardduty-not-enabled
      relationship: same_account
    - type: infra_finding
      check: aws-config-not-enabled
      relationship: same_account
    - type: any_finding
      severity: [CRITICAL, HIGH]
      relationship: same_account
  impact: "Any exploitation of the critical/high findings in this account will go completely undetected. No CloudTrail means no API audit trail. No GuardDuty means no threat detection. No Config means no configuration change tracking."
  remediation_priority:
    - "Enable CloudTrail in all regions (highest impact, lowest effort)"
    - "Enable GuardDuty for automated threat detection"
    - "Enable AWS Config for configuration compliance monitoring"
```

### 5.4 Correlation algorithm

```
For each pattern P in the pattern library:
  1. Search findings store for entry-point matches
  2. For each entry match E:
     a. Resolve the AWS resource(s) associated with E
     b. For each pivot condition in P:
        - Search findings store for matches constrained by relationship to E's resources
     c. If all required pivots are satisfied:
        - Instantiate a compound attack chain
        - Calculate aggregate severity (max of component severities, elevated by one level if ≥3 components)
        - Estimate breach cost range using cloud-audit's financial model
        - Generate a narrative description using the pattern template
        - Store the chain in the findings store with references to all component findings
```

### 5.5 Extensibility

New patterns are added as YAML files in the `patterns/` directory. The correlation engine loads all patterns at startup. Each pattern follows the schema above. Community-contributed patterns can be submitted via pull request with required fields:

- At least one `entry` condition
- At least one `pivot` condition with a `relationship` constraint
- An `impact` description
- A `remediation_priority` list ordered by effort-to-impact ratio

---

## 6. Data model

### 6.1 Shared findings schema

All findings from all MCP servers are normalized to this schema before storage:

```sql
CREATE TABLE findings (
    id              TEXT PRIMARY KEY,       -- UUID
    source          TEXT NOT NULL,          -- 'autopentest' | 'cloud-audit' | 'prowler'
    phase           INTEGER NOT NULL,       -- 1-4
    severity        TEXT NOT NULL,          -- 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
    category        TEXT NOT NULL,          -- OWASP WSTG code or CIS control ID
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    
    -- Resource identification
    resource_type   TEXT,                   -- 'url' | 'ec2' | 's3' | 'iam' | 'rds' | etc.
    resource_id     TEXT,                   -- URL path or AWS ARN
    aws_account_id  TEXT,
    aws_region      TEXT,
    
    -- Evidence
    evidence_type   TEXT,                   -- 'http_exchange' | 'cli_output' | 'screenshot' | 'config_dump'
    evidence_data   TEXT,                   -- JSON blob with evidence details
    
    -- Remediation
    remediation_summary TEXT,
    remediation_cli     TEXT,               -- Copy-paste CLI command
    remediation_iac     TEXT,               -- Terraform / CloudFormation snippet
    remediation_doc_url TEXT,               -- AWS documentation link
    
    -- Compliance
    compliance_mappings TEXT,               -- JSON: {"CIS_2.0": "1.4", "PCI_4.0": "2.2.1", ...}
    
    -- Metadata
    confidence      REAL,                   -- 0.0-1.0, from source tool
    is_validated    BOOLEAN DEFAULT FALSE,  -- True if PoC confirmed
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_source_data TEXT                    -- Original finding JSON from source tool
);

CREATE TABLE attack_chains (
    id              TEXT PRIMARY KEY,
    pattern_name    TEXT NOT NULL,
    severity        TEXT NOT NULL,
    narrative       TEXT NOT NULL,
    entry_finding   TEXT REFERENCES findings(id),
    breach_cost_low REAL,                   -- USD estimate, low end
    breach_cost_high REAL,                  -- USD estimate, high end
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE chain_components (
    chain_id        TEXT REFERENCES attack_chains(id),
    finding_id      TEXT REFERENCES findings(id),
    role            TEXT NOT NULL,           -- 'entry' | 'pivot' | 'amplifier'
    sequence_order  INTEGER NOT NULL,
    PRIMARY KEY (chain_id, finding_id)
);

CREATE TABLE remediation_actions (
    id              TEXT PRIMARY KEY,
    chain_id        TEXT REFERENCES attack_chains(id),
    finding_id      TEXT REFERENCES findings(id),
    priority_order  INTEGER NOT NULL,
    action_summary  TEXT NOT NULL,
    effort_level    TEXT NOT NULL,           -- 'LOW' | 'MEDIUM' | 'HIGH'
    breaks_chain    BOOLEAN DEFAULT FALSE,  -- True if this single fix breaks the attack chain
    cli_command     TEXT,
    iac_snippet     TEXT,
    aws_sop_ref     TEXT,                   -- Reference to AWS Knowledge MCP SOP
    doc_urls        TEXT                    -- JSON array of documentation links
);
```

### 6.2 Resource graph adjacency

To support the correlation engine's relationship queries, a lightweight adjacency table tracks which AWS resources are connected:

```sql
CREATE TABLE resource_graph (
    source_arn      TEXT NOT NULL,
    target_arn      TEXT NOT NULL,
    relationship    TEXT NOT NULL,           -- 'hosts' | 'routes_to' | 'attached_to' | 'has_access_to'
    PRIMARY KEY (source_arn, target_arn, relationship)
);
```

This is populated during Phase 1 (recon) and Phase 2 (AWS audit) as resource relationships are discovered. For example:

- ALB `arn:...alb/...` → `routes_to` → EC2 `arn:...instance/i-0abc123`
- EC2 `arn:...instance/i-0abc123` → `attached_to` → IAM Role `arn:...role/app-role`
- EC2 `arn:...instance/i-0abc123` → `member_of` → Security Group `arn:...sg/sg-12345`

---

## 7. Orchestration engine design

### 7.1 State machine

The orchestrator manages assessment state through a simple finite state machine:

```
INITIALIZED → RECON_RUNNING → RECON_COMPLETE
            → AWS_AUDIT_RUNNING → AWS_AUDIT_COMPLETE
            → APP_TEST_RUNNING → APP_TEST_COMPLETE
            → CORRELATION_RUNNING → CORRELATION_COMPLETE
            → REPORTING → COMPLETE

Any state → FAILED (with error context)
Any state → PAUSED (user-requested, resumes to same state)
```

### 7.2 Parallel dispatch

Within each phase, the orchestrator dispatches work to MCP servers concurrently where dependencies allow:

- **Phase 2**: cloud-audit and Prowler run in parallel (no dependency between them)
- **Phase 3**: WSTG categories 2-5 run in parallel; category 6 parallelizes by attack type; category 7 runs last
- **Phase 4**: Correlation patterns are evaluated in parallel (each pattern is independent)
- **Phase 5**: Report sections are generated in parallel; final assembly is sequential

### 7.3 MCP server health monitoring

The orchestrator maintains a heartbeat check for each MCP server:

- **stdio servers**: Check process is alive and responsive to a lightweight ping tool call
- **HTTP servers**: Check endpoint availability with a timeout (5s for AWS-managed servers)
- **Retry policy**: 3 retries with exponential backoff (1s, 4s, 16s) before marking a server as unavailable
- **Graceful degradation**: If a non-critical server is unavailable (e.g., AWS Docs MCP), the assessment continues with reduced enrichment; if a critical server fails (e.g., AutoPentest), the affected phase is marked as incomplete

### 7.4 Configuration file

Project Clementine is configured via a single YAML file:

```yaml
# Project Clementine.yaml

target:
  url: "https://app.example.com"
  scope:
    include_domains:
      - "app.example.com"
      - "api.example.com"
    exclude_paths:
      - "/admin/dangerous-action"
    rate_limit_rps: 10

auth:
  method: "credentials"           # credentials | token | cookie | none
  username: "${APP_USERNAME}"
  password: "${APP_PASSWORD}"
  login_url: "https://app.example.com/login"
  # Or for token-based:
  # method: "token"
  # bearer_token: "${API_TOKEN}"

aws:
  profile: "security-audit"
  regions:
    - "us-east-1"
    - "us-west-2"
  account_id: "123456789012"

compliance:
  frameworks:
    - "cis_2.0_aws"
    - "pci_4.0"
    - "soc2"

reporting:
  formats:
    - "html"
    - "json"
    - "sarif"
  output_dir: "./reports"
  push_to_security_hub: true
  security_hub_region: "us-east-1"

orchestrator:
  max_parallel_agents: 4
  finding_db: "sqlite:///findings.db"    # or postgres://...
  log_level: "INFO"
  pause_between_phases: false            # If true, requires manual confirmation to proceed

mcp_servers:
  autopentest:
    command: "docker"
    args: ["exec", "-i", "autopentest-tools", "python", "-m", "server"]
  cloud_audit:
    command: "uvx"
    args: ["cloud-audit-mcp"]
  prowler:
    command: "uvx"
    args: ["prowler-mcp-server"]
  aws_knowledge:
    url: "https://knowledge-mcp.global.api.aws"
    type: "http"
  aws_docs:
    command: "uvx"
    args: ["awslabs.aws-documentation-mcp-server@latest"]
  playwright:
    command: "npx"
    args: ["@anthropic/mcp-playwright"]
```

---

## 8. Security considerations

### 8.1 Principle of least privilege for scanning credentials

Project Clementine requires two sets of credentials, each scoped to minimum necessary permissions:

**AWS audit credentials** (for cloud-audit and Prowler):

- Attach the AWS-managed `SecurityAudit` policy (read-only)
- Attach the AWS-managed `ViewOnlyAccess` policy
- Optionally attach Prowler's additions policy for extended checks
- Never grant write permissions to the audit role

**Application test credentials** (for AutoPentest):

- Use dedicated test accounts, not production admin accounts
- Scope to the minimum permissions needed for the test scenarios
- Rotate after each assessment

### 8.2 Network isolation

- Run the AutoPentest Docker container in a dedicated network namespace
- AutoPentest tools should only have network access to the target application and the MCP server socket
- cloud-audit and Prowler only need outbound HTTPS to AWS API endpoints
- AWS Knowledge/Docs MCP servers are remote and require outbound HTTPS to `*.api.aws`

### 8.3 Credential handling

- All credentials are passed via environment variables, never hardcoded in configuration
- The Project Clementine.yaml file references `${ENV_VAR}` placeholders, resolved at runtime
- Finding evidence is sanitized to remove credentials before storage (regex-based scrubbing of `Authorization`, `Cookie`, `X-Api-Key` headers)
- Reports are generated with credential redaction enabled by default

### 8.4 Scope enforcement

- AutoPentest is configured with explicit scope boundaries (in-scope domains, excluded paths)
- The orchestrator validates that no MCP server tool call targets a resource outside the defined scope
- Rate limiting is enforced at the orchestrator level, not delegated to individual tools
- A kill switch halts all testing immediately if triggered (via CLI signal or API endpoint)

### 8.5 Data retention

- Finding databases are encrypted at rest (SQLCipher for SQLite, TLS + encrypted storage for Postgres)
- Reports are classified as confidential by default
- A retention policy configuration allows automatic purging of findings older than N days
- Evidence data (HTTP exchanges, screenshots) can be stored separately from findings metadata for differential retention

---

## 9. Deployment options

### 9.1 Local workstation (single assessment)

The simplest deployment: run Project Clementine from a developer's workstation or a dedicated security testing machine.

```bash
# Prerequisites
docker pull bhavsec/autopentest-tools:latest
pip install cloud-audit Project Clementine-orchestrator
npm install -g @anthropic/mcp-playwright

# Configure
cp Project Clementine.example.yaml Project Clementine.yaml
# Edit Project Clementine.yaml with target details

# Run
Project Clementine run --config Project Clementine.yaml
```

### 9.2 CI/CD integration (continuous assessment)

Run Project Clementine as a pipeline stage that gates deployments on security posture.

```yaml
# .github/workflows/security-assessment.yml
name: Project Clementine Security Assessment
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

jobs:
  Project Clementine:
    runs-on: ubuntu-latest
    services:
      autopentest:
        image: bhavsec/autopentest-tools:latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Project Clementine
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AUDIT_AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AUDIT_AWS_SECRET_ACCESS_KEY }}
          APP_USERNAME: ${{ secrets.TEST_APP_USERNAME }}
          APP_PASSWORD: ${{ secrets.TEST_APP_PASSWORD }}
        run: |
          Project Clementine run --config Project Clementine.yaml --format sarif --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: Gate on severity
        run: |
          Project Clementine check --max-severity HIGH --config Project Clementine.yaml
          # Exits non-zero if any HIGH or CRITICAL findings exist
```

### 9.3 Containerized service (continuous monitoring)

For organizations that want continuous security monitoring, Project Clementine can run as a scheduled container service.

```yaml
# docker-compose.yml
services:
  Project Clementine:
    build: .
    environment:
      - AWS_PROFILE=security-audit
      - Project Clementine_CONFIG=/config/Project Clementine.yaml
      - Project Clementine_DB=postgres://Project Clementine:${DB_PASSWORD}@db:5432/Project Clementine
    volumes:
      - ./config:/config:ro
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
      POSTGRES_DB: Project Clementine
      POSTGRES_USER: Project Clementine
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

---

## 10. Future roadmap

### 10.1 Near-term (v0.2 — v0.5)

- **Unified AWS MCP Server migration**: Replace separate Knowledge + Documentation servers with the unified AWS MCP Server when it reaches GA. Gain authenticated AWS API execution for automated remediation verification.
- **Interactive remediation verification**: After remediation, automatically re-run the specific failing checks to confirm the fix worked.
- **Slack/Teams notification integration**: Alert on new critical findings or regression (using cloud-audit's diff capability).
- **Additional MCP server integrations**:
  - HexStrike AI (150+ security tools as MCP endpoints) for expanded tool coverage
  - pentest-ai (0xSteph) for exploit chaining and PoC validation capabilities
  - OWASP ZAP MCP for active scanning and AJAX spider integration

### 10.2 Medium-term (v0.6 — v1.0)

- **Multi-account assessment**: Scan across AWS Organizations with role assumption chain.
- **Historical trend analysis**: Track security posture over time with trend visualization and regression alerting.
- **Custom pattern authoring UI**: Web interface for creating and testing correlation patterns without YAML editing.
- **Multi-cloud support**: Extend infrastructure audit to Azure (via Prowler's Azure provider) and GCP.
- **IaC scanning integration**: Pre-deployment analysis of Terraform/CloudFormation templates to catch misconfigurations before they reach production.

### 10.3 Long-term (v1.0+)

- **Autonomous remediation**: With the unified AWS MCP Server's API execution capability, implement auto-fix for low-risk, high-confidence findings (e.g., enabling IMDSv2, adding HttpOnly to cookies) with human approval gates.
- **Red team simulation mode**: Chain together exploitation steps across the full kill chain rather than stopping at vulnerability identification.
- **Machine learning-enhanced correlation**: Train on historical assessment data to discover novel attack patterns not in the curated library.
- **Compliance-as-code**: Generate compliance evidence documents automatically from assessment results, mapped to auditor expectations per framework.

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **MCP** | Model Context Protocol — an open protocol for connecting LLM applications to external tools and data sources |
| **WSTG** | Web Security Testing Guide — OWASP's comprehensive methodology for web application security testing |
| **CIS** | Center for Internet Security — publishes security benchmarks for cloud platforms |
| **IMDS** | Instance Metadata Service — EC2 service that provides instance configuration data, exploitable via SSRF if running v1 |
| **SSRF** | Server-Side Request Forgery — vulnerability allowing an attacker to make the server issue requests to unintended destinations |
| **ASFF** | AWS Security Finding Format — standardized format for security findings in AWS Security Hub |
| **SARIF** | Static Analysis Results Interchange Format — standard format for static/dynamic analysis tool output |
| **CSPM** | Cloud Security Posture Management — category of tools that assess cloud configuration against best practices |
| **SOP** | Standard Operating Procedure — step-by-step workflow for completing complex tasks |

## Appendix B: MCP transport reference

| Server | Transport | Requires AWS creds | Requires API key | Local process |
|---|---|---|---|---|
| AutoPentest AI | stdio | No | No | Yes (Docker) |
| cloud-audit | stdio | Yes (SecurityAudit) | No | Yes |
| Prowler | stdio | Yes (SecurityAudit) | Optional (Cloud API) | Yes |
| AWS Knowledge | HTTP | No | No | No (remote) |
| AWS Documentation | stdio | No | No | Yes |
| Playwright | stdio | No | No | Yes |
