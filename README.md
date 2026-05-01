# Project Clementine

Automated penetration-testing orchestrator. Coordinates MCP servers to deliver assessments spanning application-layer vulnerabilities (OWASP WSTG), AWS infrastructure misconfigurations, and Azure cloud misconfigurations — then automatically correlates them into compound attack chains that neither layer of tooling can find on its own.

The engine builds a **NetworkX-backed multi-cloud knowledge graph** during each assessment, enabling multi-hop attack path traversal, edge-typed IAM topology queries, blast radius calculation, and a visual attack surface map in the HTML report.

```text
SSRF (medium)  +  IMDSv1 enabled  +  overprivileged IAM role  =  full AWS account takeover (critical)

SSRF (medium)  +  Azure IMDS reachable  +  MI with Contributor on subscription  =  full Azure subscription takeover (critical)
```

---

## What it does

Project Clementine runs six sequential phases:

| Phase | What happens |
| --- | --- |
| 1 — Recon | Crawls endpoints, fingerprints tech stack, maps AWS and Azure resources from DNS and response headers |
| 2a — AWS Audit | cloud-audit and Prowler run in parallel; findings deduplicated and normalised. Builds the AWS knowledge graph: principals, compute, storage, and network nodes with live IAM trust and permission edges |
| 2b — Azure Audit | azure-mcp, KQL resource graph queries, and prowler-mcp enumerate the Azure environment. Builds the Azure knowledge graph: Entra identities, RBAC assignments (with PIM-eligibility), federated credentials, and network topology |
| 3 — App Test | Full OWASP WSTG test suite via AutoPentest AI; Playwright validates DOM-based findings. Azure-specific probes: IMDS token extraction, App Service identity endpoint, WireServer, and SAS token harvesting |
| 3.5 — AI Triage | Claude (via Amazon Bedrock) scores each finding: confidence, false-positive flag, and rationale. Azure resource IDs are compressed to short aliases to reduce prompt token cost |
| 4 — Correlation | Rule-based pattern engine (84 patterns — 48 AWS + 36 Azure) fuses app + infra findings into compound attack chains using edge-typed multi-hop graph traversal. Optional AI chain discovery proposes novel paths including cross-cloud pivot chains |
| 5 — Reporting | HTML (with interactive Attack Graph, provider lane toggle, per-cloud posture cards, identity hygiene table, and Defender vs Prowler drift section), JSON, SARIF, Markdown, and optional AWS Security Hub push |

Phase 2b runs only when `azure.enabled: true` in the configuration. All existing AWS-only behaviour is unchanged with `azure.enabled: false`.

---

## AWS Knowledge Graph

Phase 2a constructs a directed graph `G = (V, E)` over the AWS environment:

**Nodes (V)** — IAM users and roles, EC2 instances, EKS pods and nodes, Lambda functions and layers, S3 buckets, RDS instances, Secrets Manager secrets, SSM parameters, VPCs, security groups, VPC endpoints, VPC peering connections, transit gateways, API Gateway routes, KMS keys, SNS topics, SQS queues, CloudFront distributions, WAF ACLs, IMDS (`169.254.169.254`), web endpoints from AutoPentest AI, and wildcard resource placeholders (`Resource: "*"`).

**Edges (E)** — IAM trust relationships (`CAN_ASSUME`), permission grants (`HAS_PERMISSION`, `CAN_PASS_ROLE`), compute attachments (`ATTACHED_TO`, `HOSTS_APP`), network topology (`ROUTES_TO`, `INTERNET_FACING`, `PEERED_WITH`), exploit paths (`SSRF_REACHABLE`), EKS IRSA bindings (`IRSA_BOUND`, `OIDC_TRUSTS`), invocation paths (`INVOKES`), encryption (`ENCRYPTS_WITH`, `KEY_POLICY_GRANTS`), messaging (`SUBSCRIBES_TO`), Lambda layer usage (`USES_LAYER`), and WAF coverage (`WAF_PROTECTS`).

### Live IAM Enumeration

Phase 2a runs a live IAM topology pass against the target account via the cloud-audit MCP server. Three sub-passes build the IAM portion of the graph:

1. **Roles + trust policies** — lists all in-scope IAM roles, parses each `AssumeRolePolicyDocument`, and emits `CAN_ASSUME` edges from every principal in the trust policy (account roots, AWS services, federated identities, other roles). OIDC federated principals produce `OIDC_TRUSTS` edges.
2. **Attached + inline policies** — fetches attached managed policies and inline policies for each principal. Emits `HAS_PERMISSION` edges to named resources and to a wildcard placeholder node when `Resource: "*"` is used (marked `is_wildcard: true` on the edge).
3. **PassRole grants** — any policy statement that allows `iam:PassRole` produces `CAN_PASS_ROLE` edges, making Lambda/EC2/ECS privilege-escalation chains visible in the graph.

All three passes are independently failure-tolerant. If IAM listing returns auth errors, the outcome is recorded in the `enrichment_status` table so reports can disclose graph completeness rather than silently emitting a partial topology.

---

## Azure Knowledge Graph

Phase 2b constructs a directed graph over the Azure environment using eight enumeration steps:

**Nodes (V)** — ~50 Azure node types across six categories:

- **Scope**: Tenant, ManagementGroup, Subscription, ResourceGroup
- **Identity**: EntraUser, EntraGroup, EntraDirectoryRole, ServicePrincipal, AppRegistration, SystemAssignedMI, UserAssignedMI, FederatedCredential, RoleAssignment, RoleDefinition
- **Compute**: VirtualMachine, VMSS, AppService, FunctionApp, ContainerApp, ContainerInstance, AKSCluster, AKSNodePool, AKSServiceAccount
- **Storage**: StorageAccount, BlobContainer, FileShare, KeyVault, KVSecret, CosmosAccount, SQLServer, SQLDatabase
- **Network**: VNet, Subnet, NSG, NSGRule, VNetPeering, PrivateEndpoint, AppGateway, FrontDoor, AzureFirewall
- **Governance**: LogAnalytics, DiagnosticSetting, PolicyAssignment, DefenderPlan

**Edges (E)** — 23 Azure edge types: `CAN_ASSUME_MI`, `HAS_RBAC_ROLE`, `HAS_DIRECTORY_ROLE`, `HAS_API_PERMISSION`, `OWNS_APP_REGISTRATION`, `CONSENT_GRANT`, `CAN_ATTACH_MI`, `MI_ATTACHED_TO`, `WORKLOAD_ID_BOUND`, `OIDC_TRUSTS`, `ROUTES_TO`, `INTERNET_FACING`, `SSRF_REACHABLE`, `IMDS_EXPOSED`, `INVOKES`, `ENCRYPTS_WITH`, `STORES_SECRET_FOR`, `PEERED_WITH`, `PRIVATE_LINK_TO`, `POLICY_APPLIES_TO`, `PIM_ELIGIBLE_FOR`, `CAN_RESET_CREDENTIAL_FOR`

### RBAC Modelling

Each role assignment is materialised as a **node** (not just an edge) with properties `(scope, scope_level, inherited, pim_eligible)`. The graph shape is `Principal -[HAS_RBAC_ROLE]-> RoleAssignment -[HAS_RBAC_ROLE]-> scope_node`. Scope inheritance is expanded automatically — a management-group-level Owner assignment produces inherited edges on every child subscription and resource group.

PIM-eligible assignments are modelled as `PIM_ELIGIBLE_FOR` edges with a `pim_discount: 0.7` property. The correlation engine and AI discovery treat these as lower-probability paths (confidence capped accordingly).

### Workload Identity and Federation

Federated credentials are cross-matched against AKS cluster OIDC issuer URLs. When a federated credential subject matches `system:serviceaccount:<ns>:<sa>` and the issuer matches a known AKS cluster, a `WORKLOAD_ID_BOUND` edge is emitted from the Kubernetes service account to the bound UAMI. Wildcard subjects (`"*"`) generate an immediate HIGH finding.

### Compliance Integration

Phase 2b runs both azure-mcp resource enumeration and prowler-mcp compliance scanning. Prowler runs six Azure frameworks: CIS 3.0, MCSB, NIST 800-53, ISO 27001, SOC 2, and Prowler ThreatScore. Results from both tools are cross-referenced — controls where Defender for Cloud and Prowler disagree are surfaced as a **compliance drift** finding with `source='defender-prowler-drift'`.

---

## Graph queries

`AttackSurfaceAnalyzer` provides three queryable operations over the unified multi-cloud graph:

- `paths_between(src, dst, edge_types=None, max_hops=4)` — returns concrete annotated paths (list of `(node, edge_type)` tuples) optionally filtered to specific edge types. AWS and Azure edge types are both accepted.
- `principals_reaching(resource_id, edge_types=...)` — returns every principal (IAM role, Entra user, service principal, managed identity) that can ultimately reach a given resource. Traversal defaults include both `IAM_TRAVERSAL_EDGES` (AWS) and `AZURE_IAM_TRAVERSAL_EDGES`.
- `cycle_detect()` — flags trust cycles in both IAM (role-assume loops) and Azure RBAC (SP owns app registration that resets SP credentials).

---

## Attack graph visualisation

The HTML report includes an **Attack Graph** tab with a force-directed canvas renderer:

### AWS nodes (purple-orange palette)

- Purple — IAM principals (roles, users, EKS service accounts)
- Blue — Compute (EC2, EKS pods/nodes)
- Green — Storage (S3, RDS, Secrets Manager, SSM)
- Amber — Lambda functions and layers
- Red — Web endpoints and IMDS
- Teal — Network (VPC, security groups, VPC peering, transit gateways)
- Orange — Messaging and API (SNS, SQS, API Gateway, CloudFront)
- Grey — KMS keys, WAF ACLs

### Azure nodes (blue-teal palette)

- Dark navy — Tenant and management group scope
- Steel blue — Subscription and resource group scope
- Cyan — Entra identity (users, groups, service principals, app registrations)
- Sky blue — Managed identities and federated credentials
- Teal — AKS clusters and service accounts
- Blue-grey — Compute (VMs, App Service, Function Apps, Container Instances)
- Light teal — Storage, Key Vaults
- Slate — Network and governance

**Lane controls** — three toggle buttons in the graph toolbar filter the view to AWS-only, Azure-only, or multi-cloud nodes. Multi-cloud attack chains (chains containing nodes from both providers) are highlighted with a gold border in the attack chains section.

**Dashed edges** — exploit paths (`SSRF_REACHABLE`, `INTERNET_FACING`, `IMDS_EXPOSED`, `PIM_ELIGIBLE_FOR`) are rendered as dashed lines. Hovering an edge shows the finding IDs that established it.

---

## Token telemetry and cost control

Every Bedrock inference call (triage batches and discovery) is instrumented with per-call usage metrics. Totals are persisted to the `ai_usage` table and printed at the end of each `clementine run`:

```text
AI usage summary
  triage_batch   claude-sonnet-4-6   in=12,340  out=4,210  cache_read=8,100
  discovery      claude-opus-4-7     in=9,180   out=3,220  cache_read=0
  ─────────────────────────────────────────────────────────────────────────
  TOTAL                               in=21,520  out=7,430  cache_read=8,100
```

### Discovery prompt compression

The AI discovery phase uses several techniques to reduce the per-run token cost:

- **ARN aliasing** — long AWS ARNs are replaced with short aliases (`r1`, `r2`, …) defined in a legend block at the top of the prompt.
- **Azure resource ID aliasing** — Azure resource IDs (`/subscriptions/…/resourceGroups/…/providers/…`) are compressed to `type:hash` aliases (`vm:dxz`, `kv:zlq`). The alias legend is appended at the end of the findings block, behind a `cache_control` breakpoint.
- **Subgraph pruning** — only edges whose endpoints are within `discovery.subgraph_hops` (default: 2) of a finding-bearing node are included.
- **Edge grouping** — edges with the same relationship type are emitted as a single compact line (`CAN_ASSUME: r1→r3, r2→r3`) instead of one line per edge.
- **Finding pre-filter** — findings marked as false positives, below the minimum confidence threshold, or at INFO severity are dropped before they reach the prompt.
- **Budget caps** — `max_tokens` is capped at 8192, thinking `effort` defaults to `"medium"`, and `max_retries` is 1.
- **Cache breakpoint** — the static findings/graph block and the short instruction tail are sent as separate `cache_control: ephemeral` blocks so the static portion can be served from cache on subsequent calls.

### Discovery configuration knobs

| Key | Default | Description |
| --- | --- | --- |
| `ai.discovery.max_tokens` | `8192` | Maximum output tokens for the discovery call |
| `ai.discovery.effort` | `"medium"` | Opus thinking depth: `"low"` / `"medium"` / `"high"` |
| `ai.discovery.max_retries` | `1` | Retry budget for the discovery call |
| `ai.discovery.min_finding_confidence` | `0.4` | Drop findings below this triage confidence score |
| `ai.discovery.include_info` | `false` | Include INFO-severity findings in the discovery prompt |
| `ai.discovery.subgraph_hops` | `2` | BFS radius around finding-bearing nodes for subgraph pruning |
| `ai.discovery.drop_unreachable_findings` | `true` | Drop findings with no edges in the pruned subgraph |

---

## Prerequisites

| Tool | Purpose | Install |
| --- | --- | --- |
| Python ≥ 3.11 | Runtime | [python.org](https://python.org) |
| Docker | AutoPentest AI security tools container | [docker.com](https://docker.com) |
| Node.js ≥ 20 | Playwright MCP server; azure-mcp (`npx`) | [nodejs.org](https://nodejs.org) |
| `uv` / `uvx` | cloud-audit and Prowler MCP servers | `pip install uv` |
| AWS CLI | Configured profile with read-only audit permissions | `pip install awscli` |
| Azure CLI | Required when `azure.enabled: true` | [learn.microsoft.com](https://learn.microsoft.com/cli/azure/install-azure-cli) |
| Prowler ≥ 5.6 | Compliance scanning — AWS and Azure | `pip install "prowler[azure]>=5.6"` |
| Amazon Bedrock access | AI triage and novel-chain discovery (optional — skipped when `ai.enabled: false`) | IAM policy — see below |

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

### Azure audit permissions

Create a service principal with Reader on the subscription(s) to be audited. For Key Vault secret metadata, additionally assign Key Vault Reader:

```bash
# Create a service principal for the audit
az ad sp create-for-rbac \
  --name "clementine-audit-sp" \
  --role Reader \
  --scopes "/subscriptions/<SUBSCRIPTION_ID>"

# Export the output values as environment variables
export AZURE_TENANT_ID="<tenant>"
export AZURE_CLIENT_ID="<appId>"
export AZURE_CLIENT_SECRET="<password>"
```

For AKS deployments, use workload identity instead of a client secret — see [k8s/clementine-workload-identity.yaml](k8s/clementine-workload-identity.yaml).

### Amazon Bedrock permissions

The same IAM identity also needs permission to invoke Claude models via Bedrock:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/us.anthropic.claude-sonnet-4-6-*",
        "arn:aws:bedrock:*::foundation-model/us.anthropic.claude-opus-4-7-*"
      ]
    }
  ]
}
```

Before running, verify that cross-region inference profiles for your chosen models are enabled in your AWS account via **Bedrock console → Model access**.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/project-clementine
cd project-clementine

# Install the package and its dependencies
pip install -e .

# For Azure auditing, also install:
pip install "prowler[azure]>=5.6"
npm install -g @azure/mcp@latest   # requires Node.js 20+

# Verify the CLI is available
clementine --version
```

### Pull the AutoPentest AI Docker image

```bash
docker pull dylshroll/autopentest-tools:latest

# Start the container (keep it running in the background)
docker run -d --name autopentest-tools dylshroll/autopentest-tools:latest tail -f /dev/null
```

### Container deployment (Kubernetes / AKS)

For production deployments on AKS, use the provided workload identity manifest which eliminates the need for a client secret:

```bash
# Fill in <UAMI_CLIENT_ID>, <IMAGE>, and <SUBSCRIPTION_ID> in the manifest
kubectl apply -f k8s/clementine-workload-identity.yaml
```

Prerequisites: AKS cluster with OIDC issuer and workload identity enabled, a User-Assigned Managed Identity with Reader on the target subscription(s), and a federated credential on the UAMI with subject `system:serviceaccount:clementine:clementine-orchestrator`.

---

## Configuration

Copy the example config and edit it for your target:

```bash
cp clementine.example.yaml clementine.yaml
```

Set all credentials as environment variables — **never put secrets directly in the YAML file**:

```bash
# AWS (always required)
export APP_USERNAME="testuser"
export APP_PASSWORD="testpass"
export AWS_AUDIT_PROFILE="security-audit"
export AWS_ACCOUNT_ID="123456789012"

# Azure (required when azure.enabled: true)
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<client-id>"
export AZURE_CLIENT_SECRET="<client-secret>"
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

### Enabling Azure auditing

```yaml
azure:
  enabled: true
  tenants:
    - tenant_id: "${AZURE_TENANT_ID}"
      subscription_ids:
        - "${AZURE_SUBSCRIPTION_ID}"   # empty list = all visible subscriptions
  guardrails:
    allow_imds_probe: false   # set true only with explicit engagement approval
    allow_run_command_test: false   # never enable — too disruptive
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

- `reports/report.html` — interactive HTML with severity filtering, attack chain step-flow, remediation playbook, provider lane toggle, per-cloud posture cards, and Attack Graph visualisation
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
        image: dylshroll/autopentest-tools:latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Clementine
        run: pip install -e .

      - name: Run assessment
        env:
          APP_USERNAME: ${{ secrets.TEST_APP_USERNAME }}
          APP_PASSWORD: ${{ secrets.TEST_APP_PASSWORD }}
          AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AUDIT_AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AUDIT_AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: us-east-1
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}        # omit if aws-only
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}        # omit if aws-only
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }} # omit if aws-only
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
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
    volumes:
      - ./clementine.yaml:/config/clementine.yaml:ro
      - ./reports:/reports
      - ~/.aws:/root/.aws:ro
    depends_on:
      - db
      - autopentest

  autopentest:
    image: dylshroll/autopentest-tools:latest

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

Compound attack patterns live in `patterns/` as YAML files. **84 built-in patterns** span injection, authentication, cloud infrastructure, privilege escalation, supply chain, and client-side attack classes — 48 AWS patterns in `patterns/*.yaml` and 36 Azure patterns in `patterns/azure/*.yaml`. All patterns use the same rule format and are auto-discovered at startup — no code changes needed to add or remove them.

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
| --- | --- | --- |
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
| `iam_assume_chain_to_admin_via_edges.yaml` | Over-privileged principal → admin role reachable via ≤3 CAN_ASSUME / CAN_PASS_ROLE hops | CRITICAL |
| `lambda_backdoor_privilege_escalation.yaml` | Excessive Lambda permissions + iam:PassRole → code execution under privileged role | HIGH |
| `iam_policy_rollback_privilege_escalation.yaml` | iam:SetDefaultPolicyVersion + stale permissive policy versions → self-escalation | HIGH |
| `glue_dev_endpoint_privilege_escalation.yaml` | glue:CreateDevEndpoint + iam:PassRole → arbitrary code under any passable role | HIGH |
| `eks_hostnetwork_imds_credential_theft.yaml` | EKS pod hostNetwork:true + IMDSv1 + overprivileged node role → IMDS credential theft | CRITICAL |
| `eks_irsa_oidc_trust_too_broad.yaml` | IRSA OIDC trust wildcard → any pod assumes overprivileged IAM role | HIGH |

### Supply Chain

| Pattern | Entry | Severity |
| --- | --- | --- |
| `ci_oidc_misconfiguration_supply_chain.yaml` | OIDC trust too broad → any repo assumes role → artefact poisoning | CRITICAL |

### Azure — SSRF & Credential Access

| Pattern | Entry | Severity |
| --- | --- | --- |
| `az_ssrf_imds_mi_resource_access.yaml` | SSRF → Azure IMDS → MI token → RBAC on downstream resource | CRITICAL |
| `az_functionapp_ssrf_kv_reference_exfil.yaml` | FunctionApp SSRF → IDENTITY_ENDPOINT → MI token → KV reference secrets | CRITICAL |
| `az_kv_contributor_access_policy_self_grant.yaml` | KV Contributor on non-RBAC vault → self-grant access policy → all secrets | CRITICAL |
| `az_vm_run_command_to_mi_takeover.yaml` | `virtualMachines/runCommand/action` on VM with privileged MI → subscription takeover | CRITICAL |

### Azure — Identity & Privilege Escalation

| Pattern | Entry | Severity |
| --- | --- | --- |
| `az_app_admin_to_global_admin_via_sp.yaml` | Application Admin → SP credential reset → Global Admin escalation | CRITICAL |
| `az_custom_role_iam_write_privesc.yaml` | Custom role with `roleAssignments/write` → self-grant Owner on any scope | CRITICAL |
| `az_aks_workload_identity_overprivileged_uami.yaml` | AKS service account → WORKLOAD_ID_BOUND → UAMI with Owner on subscription | CRITICAL |
| `az_sp_ms_graph_app_role_privesc.yaml` | SP with `AppRoleAssignment.ReadWrite.All` → self-grant Global Admin app role | CRITICAL |
| `az_management_group_owner_inheritance.yaml` | Owner on management group → inherited Owner on all child subscriptions | CRITICAL |
| `az_entra_directory_role_no_pim.yaml` | Privileged Directory Role (Global Admin / PRA) assigned without PIM protection | HIGH |
| `az_pim_eligibility_latent_global_admin.yaml` | PIM-eligible Global Admin + no MFA → latent full-tenant takeover | MEDIUM |
| `az_subscription_owner_no_mfa.yaml` | Subscription Owner assignment to principal without MFA enforced | HIGH |
| `az_sp_client_secret_long_expiry.yaml` | Service principal client secret expiry > 180 days or never-expiring | MEDIUM |

### Azure — Federation & Cross-Cloud

| Pattern | Entry | Severity |
| --- | --- | --- |
| `az_cross_tenant_federation_open_subject.yaml` | Federated credential wildcard subject → any GitHub Actions workflow gets Azure token | HIGH |
| `az_github_actions_oidc_to_azure_sp.yaml` | GitHub Actions OIDC federation → Azure SP with broad RBAC | HIGH |

### Azure — Storage & Data Exposure

| Pattern | Entry | Severity |
| --- | --- | --- |
| `az_storage_anonymous_blob_public_exposure.yaml` | Blob container anonymous access enabled + sensitive data pattern | HIGH |
| `az_storage_long_lived_account_sas.yaml` | Account-scope SAS token with expiry > 7 days | HIGH |
| `az_storage_key_rotation_overdue.yaml` | Storage account key not rotated > 90 days | MEDIUM |
| `az_cosmos_firewall_disabled.yaml` | Cosmos DB with public endpoint and no firewall | HIGH |
| `az_sql_public_endpoint.yaml` | SQL Server public endpoint enabled + broad firewall rule | HIGH |
| `az_acr_anonymous_pull.yaml` | Container registry with anonymous pull enabled | MEDIUM |

### Azure — Network

| Pattern | Entry | Severity |
| --- | --- | --- |
| `az_nsg_star_inbound_management_ports.yaml` | NSG rule allowing `*` inbound to SSH (22) or RDP (3389) | HIGH |
| `az_vm_public_ip_no_jit.yaml` | VM with public IP and no JIT access policy | MEDIUM |
| `az_app_gateway_waf_detection_mode.yaml` | App Gateway WAF in Detection mode (not Prevention) | MEDIUM |
| `az_front_door_no_waf.yaml` | Azure Front Door without WAF policy attached | MEDIUM |
| `az_azure_firewall_threat_intel_off.yaml` | Azure Firewall with threat intelligence mode set to Off or Alert | MEDIUM |

### Azure — Governance & Visibility

| Pattern | Entry | Severity |
| --- | --- | --- |
| `az_diagnostic_settings_missing.yaml` | No diagnostic settings on Key Vault, Storage, or NSG | MEDIUM |
| `az_defender_plans_disabled.yaml` | Defender for Cloud plans disabled on subscription | HIGH |
| `az_defender_prowler_compliance_drift.yaml` | Same control, opposite verdict in Defender and Prowler | MEDIUM |
| `az_kv_no_soft_delete_purge_protection.yaml` | Key Vault without soft-delete or purge protection enabled | MEDIUM |
| `az_service_bus_manage_auth_rule.yaml` | Service Bus namespace-level Manage SAS rule (grants full topic access) | HIGH |
| `az_aks_rbac_disabled.yaml` | AKS cluster with Kubernetes RBAC disabled | HIGH |
| `az_orphan_role_assignment_deleted_principal.yaml` | Role assignment to a deleted principal (Unknown objectType) | LOW |
| `az_entra_legacy_auth_not_blocked.yaml` | No Conditional Access policy blocking legacy authentication protocols | HIGH |
| `az_break_glass_account_no_alert.yaml` | Break-glass account exists without sign-in alert | MEDIUM |
| `az_conditional_access_exclusion_all_users.yaml` | Conditional Access policy with group exclusion that covers all users | HIGH |

### Adding a custom pattern

Create a new file in `patterns/` (AWS) or `patterns/azure/` (Azure) — no code changes needed:

```yaml
# patterns/my_custom_pattern.yaml

pattern:
  name: "My custom attack chain"
  severity: HIGH

entry:
  type: app_finding          # app_finding | infra_finding | azure_finding
  category: IDOR             # matched against finding title/category
  wstg: WSTG-ATHZ            # optional WSTG code prefix

pivot:
  - type: infra_finding
    check: iam-role-overprivileged
    relationship: same_account  # same_account | same_compute_resource | same_subscription | same_tenant
```

For IAM or Azure RBAC chains, use the `via_edges` constraint instead of a loose relationship string:

```yaml
pivot:
  - type: azure_finding
    check: azure:uami_owner_or_contributor_on_subscription
    relationship:
      via_edges:
        - WORKLOAD_ID_BOUND
        - HAS_RBAC_ROLE
      max_hops: 4
```

Without `via_edges`, the engine falls back to any-edge multi-hop reachability, which can produce false-positive chains via shared subscription membership. Use `via_edges` whenever the chain requires a specific IAM access path.

```yaml
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
| `azure.enabled` | `false` | Set `true` to activate Azure audit (Phase 2b) |
| `azure.tenants[].tenant_id` | required if enabled | Entra tenant ID to audit |
| `azure.tenants[].subscription_ids` | `[]` | Subscriptions to audit (empty = all visible) |
| `azure.compliance_frameworks` | CIS 3.0, MCSB, NIST, ISO, SOC 2, ThreatScore | Prowler frameworks to run |
| `azure.pim_activation_cost` | `0.7` | Path-score multiplier for PIM-eligible edges |
| `azure.guardrails.allow_imds_probe` | `false` | Enable IMDS token extraction probe (requires engagement approval) |
| `azure.guardrails.allow_sas_token_extraction` | `true` | Scan HTTP responses for SAS token patterns |
| `azure.guardrails.allow_run_command_test` | `false` | Never enable — too disruptive |
| `azure.guardrails.max_resources_per_type` | `500` | Cap on inherited role assignment expansion |
| `compliance.frameworks` | `[cis_2.0_aws]` | AWS Prowler compliance frameworks |
| `reporting.formats` | `[html, json]` | `html` / `json` / `sarif` / `markdown` |
| `reporting.output_dir` | `./reports` | Directory for report files |
| `reporting.push_to_security_hub` | `false` | Push findings to AWS Security Hub |
| `orchestrator.finding_db` | `sqlite:///findings.db` | SQLite path or PostgreSQL DSN |
| `orchestrator.pause_between_phases` | `false` | Wait for ENTER before each phase |
| `orchestrator.log_level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `ai.enabled` | `true` | Set `false` to skip triage and discovery entirely |
| `ai.aws_region` | `us-east-1` | AWS region for Bedrock inference |
| `ai.primary_model` | `us.anthropic.claude-sonnet-4-6-20251101` | Bedrock model ID for recon, app-test, and triage |
| `ai.critical_model` | `us.anthropic.claude-opus-4-7-20251101` | Bedrock model ID reserved for chain discovery |
| `ai.effort` | `high` | Opus extended-thinking depth (`low` / `medium` / `high` / `xhigh` / `max`) |
| `ai.max_parallel_requests` | `4` | Concurrent Bedrock calls |
| `ai.max_retries` | `3` | Retry budget for throttling / 5xx errors |
| `ai.discovery.max_tokens` | `8192` | Max output tokens for AI discovery call |
| `ai.discovery.effort` | `"medium"` | Opus thinking depth (`low` / `medium` / `high`) |
| `ai.discovery.max_retries` | `1` | Retry budget for AI discovery |
| `ai.discovery.min_finding_confidence` | `0.4` | Minimum triage confidence to include a finding |
| `ai.discovery.include_info` | `false` | Include INFO-severity findings in discovery |
| `ai.discovery.subgraph_hops` | `2` | Graph BFS radius for prompt pruning |
| `ai.discovery.drop_unreachable_findings` | `true` | Exclude findings with no pruned-subgraph edges |

---

## MCP servers

| Server | Transport | Required | Purpose |
| --- | --- | --- | --- |
| AutoPentest AI | stdio (Docker) | Yes | OWASP WSTG application testing |
| cloud-audit | stdio (`uvx`) | Yes | AWS configuration scanning and IAM enumeration |
| Prowler | CLI / stdio | No | AWS compliance framework mapping |
| AWS Knowledge | HTTP (remote) | No | Remediation SOP enrichment |
| AWS Documentation | stdio (`uvx`) | No | Documentation link enrichment |
| Playwright | stdio (`npx`) | No | DOM-based PoC validation |
| azure-mcp | stdio (`npx`) | Azure only | Azure resource enumeration (read-only) |
| prowler-mcp | stdio (`python`) | Azure only | Azure compliance scanning (160+ controls) |
| microsoft-learn | stdio (`python`) | Azure only | Azure documentation grounding for AI triage |

Clementine degrades gracefully when non-critical servers are unavailable — the assessment continues with reduced enrichment and a warning in the logs. If the cloud-audit server is unavailable during IAM enumeration, the outcome is recorded in the `enrichment_status` table and disclosed in the report. Azure MCP server unavailability is handled identically — each of the eight enumeration steps logs `[SKIP]` and continues.

---

## Security notes

- **Credentials** are read from environment variables at startup and never written to disk.
- **Scope enforcement** is applied at the orchestrator before every MCP tool call — no request is ever sent outside `include_domains`.
- **Rate limiting** is enforced centrally, not delegated to individual tools.
- **Evidence** stored in the database is scrubbed of `Authorization`, `Cookie`, `Bearer`, and password values before writing.
- **AWS audit credentials** should have `SecurityAudit` + `ViewOnlyAccess` + `bedrock:InvokeModel` only — no write permissions.
- **Azure audit credentials** should have `Reader` on the target subscription(s) and `Key Vault Reader` for KV metadata. The `azure-mcp` server is launched with `--read-only` enforced server-side.
- **IMDS probes** (`allow_imds_probe: true`) extract JWT payloads — the token signature is stripped before storage and the token is never used to call any downstream service. This guardrail requires explicit engagement approval and is `false` by default.
- **AI authentication** uses the AWS credential chain (env vars, `~/.aws/credentials`, instance profile). No Anthropic API key is used or accepted.
- Use **dedicated test accounts** for application credentials; rotate them after each assessment.

---

## Resuming a failed assessment

If a run fails mid-assessment, the orchestrator saves its state to the database. Re-running the same command resumes from the last completed phase:

```bash
# Original run fails partway through Phase 2b (Azure audit)
clementine run --config clementine.yaml

# Fix the issue, re-run — phases 1 and 2a are skipped automatically
clementine run --config clementine.yaml
```

To force a full restart, delete the findings database:

```bash
rm findings.db
clementine run --config clementine.yaml
```

---

## Things I want to do with the project

- Embeddings model layer on top of the knowledge graph for semantic similarity search and novel exploit chain suggestion
- GUI / web dashboard for live assessment monitoring
- GCP integration
- IaC scanning (Terraform, CloudFormation, Bicep, CDK)
- Additional correlation patterns based on emerging exploit paths
- Increase backoff time on `clementine.mcp_client` failures during rate-limit errors
- Incremental / re-run discovery: cache the static findings+graph block across runs so only deltas are sent to the model
- `cycle_detect()` findings: surface IAM trust loops as their own finding category in the correlation engine
- Switch `AttackSurfaceAnalyzer` to `nx.MultiDiGraph` to properly represent multiple edge types between the same node pair
- Multi-tenant Azure support (`--multi-tenant` flag for cross-tenant federation assessment)
