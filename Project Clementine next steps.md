# Project Clementine — Azure Cloud Auditing Capability: Design Specification

*Version 0.9 (draft for review) · Target release: Clementine 2.0 "Mandarin"*
*Author: Cloud Security Engineering · Last updated: April 30, 2026*

---

## 0. Preface — Why This Document Exists, In One Paragraph

Clementine has, until now, been a citrus tree with one cultivar: AWS. Every node, every edge, every YAML rule, every Bedrock prompt assumes an account/IAM/EC2/STS shape of the world. The orchard, however, is multi‑cloud. This spec grafts an Azure scion onto the existing rootstock without disturbing the AWS canopy: it preserves the five‑phase workflow, the NetworkX `AttackSurfaceAnalyzer`, the YAML pattern engine, and the Bedrock triage/discovery loop, and extends each so an Azure tenant looks, to the correlation engine, like "another account, but with different ARN syntax and different escalation primitives." The fundamental insight is that AWS PassRole, EKS IRSA, IMDSv1 SSRF, and S3 anonymous access all have first‑class Azure analogues — the abuse paths rhyme even when the resource providers don't — so we extend the *taxonomy* rather than fork the *engine*.

---

## 1. Updated MCP Server Inventory

Clementine 1.x ships with six MCP servers: **AutoPentest AI**, **cloud‑audit**, **Prowler**, **AWS Knowledge MCP Server**, **AWS Documentation MCP Server**, and **Playwright**. Clementine 2.0 adds four Azure‑specific servers and re‑purposes one existing server, for a total of ten. All servers continue to run as long‑lived stdio child processes managed by the orchestrator's `MCPSupervisor`, with HTTP transport available for production deployments behind the orchestrator's mTLS sidecar.

### 1.1 New: `azure-mcp` (Microsoft official Azure MCP Server)

- **Source**: `github.com/microsoft/mcp/tree/main/servers/Azure.Mcp.Server` (the project moved from `Azure/azure-mcp` to the `microsoft/mcp` mono‑repo on August 25, 2025; the old repo is archived).
- **Distribution**: `npx -y @azure/mcp@latest server start` or globally `npm install -g @azure/mcp@latest`. A Docker image is available for isolated deployment, and a `ms-azuretools.vscode-azure-mcp-server` VS Code extension exists but is irrelevant here.
- **Transport**: stdio (default, recommended for Clementine), HTTP (production with `--transport http`).
- **Server modes**: `namespace` (default; tools grouped by service area), `consolidated` (one tool per area), `all` (every tool exposed individually), `single`. Clementine uses `namespace` mode with explicit `--namespace` flags to keep the LLM tool window manageable.
- **Read‑only flag**: `--read-only` — **mandatory** for Clementine. Eliminates write tools entirely from the manifest.
- **Sensitive‑data confirmation**: the server uses MCP *elicitation* prompts before returning Key Vault secrets, connection strings, certificate private keys. We set `--insecure-disable-user-confirmation=false` (default) and instruct the AI Triage phase to *never* request raw secret material — only metadata (names, expiry, access mode).
- **Tool annotations** that Clementine's planner consumes: `Destructive`, `Idempotent`, `OpenWorld`, `ReadOnly`, `Secret`, `LocalRequired`. The orchestrator filters to `ReadOnly=true ∧ Destructive=false` before the LLM ever sees the manifest.

#### 1.1.1 Tool inventory (40+ Azure services, organized by Clementine phase relevance)

The following are the Azure MCP namespaces Clementine consumes. Tool names follow `azmcp_<namespace>_<verb>_<noun>` convention.

**Identity & RBAC (highest‑priority for attack‑graph construction)**
- `role` — list role assignments and role definitions (Azure RBAC). Used to enumerate every `principalId → roleDefinitionId @ scope` triple. This is Clementine's primary edge source for `HAS_RBAC_ROLE`.
- `subscription` — list subscriptions in the tenant; produces top‑level scope nodes.
- `group` — list resource groups.

**Compute / Containers**
- `appservice` — list/describe App Services and Function Apps; manage DB connections.
- `functionapp` — list Function Apps and per‑function detail (added in late‑2025 release).
- `aks` — list AKS clusters; the **OIDC issuer URL** and **workload identity** flag are exposed via the cluster `properties` blob.
- `acr` — list Azure Container Registry instances and (where authorized) repositories.

**Storage / Data**
- `storage` — list storage accounts, containers, blobs, tables; surface `allowBlobPublicAccess`, `networkAcls`, `minimumTlsVersion`, `allowSharedKeyAccess`.
- `fileshares`, `storagesync`, `managedlustre`, `confidentialledger` — auxiliary; only the first two matter for Clementine (file share misconfig).
- `cosmos` — Cosmos DB accounts, databases, containers; surfaces firewall and key‑auth settings.
- `sql` — Azure SQL servers, databases, firewall rules, elastic pools (SELECT‑only query mode for actual data).
- `mysql`, `postgres` — flexible/single servers, configurations (case‑insensitive comparisons fixed in late‑2025; relevant when reading `require_secure_transport`).
- `redis` — Managed Redis and Cache for Redis.

**Secrets**
- `keyvault` — list keys, secrets, certificates **(metadata only in our config)**; per the upstream changelog, `get` operations for keys/secrets were temporarily removed and reintroduced behind data‑redaction safeguards. We rely on list + properties (expiry, enabled, RBAC vs access‑policy mode).

**Messaging / Integration**
- `servicebus`, `eventhubs`, `eventgrid` — namespaces, topics, subscriptions; surface authorization rules.
- `signalr`, `communication` — touched only for inventory completeness.

**Monitoring / Governance / Compliance**
- `monitor` — Azure Monitor logs and metrics; **runs KQL** against Log Analytics workspaces. This is Clementine's KQL conduit.
- `workbooks` — list workbooks (low priority).
- `applicationinsights` — App Insights resources.
- `policy` — Azure Policy assignments, definitions, initiatives. Critical for compliance phase.
- `resourcehealth` — health status per resource.
- `quota` — quota usage (low priority for security).
- `extension` — Azure CLI / azd / **Azure Quick Review CLI** invocations. *Quick Review* (`azqr`) is the Microsoft compliance/security tool we surface for supplemental scans.

**AI / Search / Other**
- `search`, `foundry`, `speech` — incidental; included only because the orchestrator may discover them as tenant assets that ought to be in the inventory graph.
- `marketplace`, `cloudarchitect`, `applens` — informational.

**Resource Graph / KQL**
- The Azure MCP Server does **not** expose a top‑level `azmcp_resourcegraph_query` tool as of the November 2025 update; instead, Resource Graph is used internally by individual service tools (e.g., the SQL listing implementation switched to a Resource Graph–based backend in late 2025), and bulk tenant‑wide KQL is reached via the `monitor` namespace against Log Analytics, *or* via our own thin shim (see §1.5). For arbitrary `Resources | …` KQL, Clementine wraps `az graph query` through a custom adapter rather than relying on a first‑class MCP tool.

#### 1.1.2 Authentication model

The Azure MCP Server authenticates to Microsoft Entra ID via the .NET Azure Identity library. Two transport modes, two auth models:

- **stdio (local)**: a custom credential chain — broadly equivalent to `DefaultAzureCredential` with an additional Azure Developer CLI (`azd`) probe and Visual Studio probe. Order: `EnvironmentCredential` (service principal env vars `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID`) → `WorkloadIdentityCredential` and `ManagedIdentityCredential` (only if `AZURE_MCP_INCLUDE_PRODUCTION_CREDENTIALS=true`) → `AzureCliCredential` → `AzurePowerShellCredential` → `AzureDeveloperCliCredential` → `VisualStudioCredential`. Setting `AZURE_MCP_ONLY_USE_BROKER_CREDENTIAL=true` skips the chain and uses Web Account Manager (Windows) or browser fallback.
- **HTTP (remote production)**: inbound = MCP client presents bearer token validated against Entra ID app registration; outbound = `--outgoing-auth-strategy UseOnBehalfOf` (default; OBO flow propagates user identity) or `UseHostingEnvironmentIdentity` (uses the host's managed identity).

For Clementine we use **service principal env vars** for unattended runs and **`az login` device code** for interactive engagements, with `AZURE_MCP_INCLUDE_PRODUCTION_CREDENTIALS=true` set when the orchestrator runs inside an AKS pod with workload identity attached.

### 1.2 New: `prowler-mcp` (Prowler Lighthouse AI MCP Server)

Launched November 6, 2025. Replaces and supersedes the role of the existing AWS‑specific `Prowler` MCP server in Clementine 1.x — i.e., we delete the old one and use this one for both AWS and Azure (and incidentally GCP/M365/Kubernetes).

- **Capabilities**:
  - **Findings analysis**: query/filter/analyze findings across all configured providers (`prowler azure --compliance ...`).
  - **Provider management**: register Azure subscriptions, GCP projects, etc. We pre‑register subscriptions at orchestrator boot.
  - **Scan orchestration**: trigger on‑demand or scheduled scans. Clementine triggers per phase.
  - **Resource inventory**: search audited resources.
  - **Muting**: suppress findings (we use this to mute confirmed false positives across runs).
  - **Hub**: browse 1,000+ checks (160+ for Azure as of Prowler 5.6).
  - **Attack Paths**: Neo4j‑backed cross‑finding graph (auto‑generated for AWS scans; Azure attack‑path generation announced but not yet equivalent in coverage; Clementine continues to do its own correlation rather than relying on Prowler's Neo4j).
  - **Resource events**: who/what/when timeline (AWS only via CloudTrail at this time).
- **Compliance frameworks for Azure** (relevant subset, per Prowler 5.6+):
  - **CIS Microsoft Azure Foundations Benchmark** v2.0.0 and v3.0.0 (v3.0.0 released February 2025; 100+ controls across nine sections).
  - **Microsoft Cloud Security Benchmark (MCSB)** — Microsoft's own canonical benchmark, aligned with NIST SP 800‑53 and PCI‑DSS, and now mapped against AWS/GCP as well.
  - **NIST 800‑53 Rev 5**, **NIST CSF**, **ISO 27001:2013**, **SOC 2** (Azure SOC 2 added in Prowler 5.6), **PCI‑DSS**, **HIPAA**, **GDPR**, **FedRAMP**, **ENS**, **MITRE ATT&CK**, **Prowler ThreatScore** (the unified IAM/Attack Surface/Forensics/Encryption metric).
- **Auth**: Azure service principal (the same one we use for `azure-mcp`) with at minimum `Reader` at subscription scope plus `Storage Blob Data Reader` on storage accounts that need plane‑level reads. See §6.
- **Why we keep Prowler around as a separate signal source**: Prowler provides *control‑level* compliance posture (CIS 1.1.1 pass/fail with citations), whereas Azure MCP Server provides *resource‑level* state. Clementine merges these in the AI Triage phase: a CIS failure becomes a high‑confidence priors signal for path scoring.

> *Status note on alternatives we evaluated and rejected:*
> - **ScoutSuite** has no MCP wrapper and would have to be CLI‑driven; Prowler's coverage now exceeds it for Azure.
> - **Azqr (Azure Quick Review)** — invoked via `azure-mcp`'s `extension` namespace; useful for the *Architecture Best‑Practice* pillar but not a substitute for compliance scanning.
> - **Microsoft Defender for Cloud** *Regulatory Compliance* dashboard exposes CIS/MCSB results via the `Microsoft.Security/regulatoryCompliance*` ARM resource type, queryable through Resource Graph (`securityresources` table). Clementine reads this *in addition to* Prowler so we can compare native‑evaluator vs Prowler‑evaluator drift; see §6.4.
> - **No first‑party "Microsoft compliance MCP server"** exists at GA as of April 2026. Defender data is reached through `azure-mcp`'s `policy` namespace plus our KQL shim.

### 1.3 Re‑purposed: `cloud-audit` (Clementine's existing in‑house MCP server)

The existing `cloud-audit` server is extended with an Azure provider module that wraps `azure-identity` and the Azure SDK for Python directly. Its purpose is to fill the gaps that the official Azure MCP Server doesn't cover well in read‑only mode:

- **Federated identity credentials** for user‑assigned managed identities and app registrations (`Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials`).
- **App registrations / service principals** with **app role assignments**, **delegated permissions**, **OAuth2 consent grants**, **owners**, and **app role assignments to Microsoft Graph** (the privilege‑escalation primitive abused by `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, etc.).
- **Microsoft Entra ID directory roles** (eligible vs active in PIM) and **PIM assignment schedules**.
- **Conditional Access policies**, **named locations**, and **break‑glass account configuration** (for the report's identity hygiene section).
- **Management group hierarchy** (the Azure MCP Server lists subscriptions but not the management group tree above them).
- **Resource Graph** thin wrapper exposing `query_resource_graph(kql, scope, authorization_scope_filter)` — including the `AtScopeAndAbove` filter needed to capture inherited role assignments.
- **AKS workload identity introspection**: pulls the OIDC issuer URL from the cluster's `oidcIssuerProfile.issuerUrl`, then enumerates federated credentials whose `subject == system:serviceaccount:<ns>:<sa>` to bind pods to UAMIs.

### 1.4 Retained, no changes (for context): `AutoPentest AI`, `AWS Knowledge MCP Server`, `AWS Documentation MCP Server`, `Playwright`

The Playwright server's role is unchanged: it remains the App‑Test phase's web automation arm. The two AWS Knowledge/Documentation servers stay; we add **`Microsoft Learn MCP Server`** as their Azure counterpart (see §1.5).

### 1.5 New: `microsoft-learn-mcp` (documentation/knowledge surface for Azure)

Used by the AI Triage phase the same way `AWS Documentation MCP Server` is used: to ground LLM reasoning about Azure service behavior in canonical Microsoft Learn URLs, prevent hallucinated APIs, and resolve resource‑provider‑specific questions ("what does `Microsoft.Authorization/roleAssignments/write` actually grant?"). Implementation is a thin search‑and‑fetch wrapper over `learn.microsoft.com` plus the `Microsoft.Security/regulatoryComplianceStandards` ARM endpoints for control‑text retrieval.

---

## 2. Updated Phase‑by‑Phase Flow

The five phases stay; each gains Azure‑aware behavior. Existing AWS logic runs in parallel — there is no serialization between providers. Each phase emits provider‑tagged findings that converge into the same NetworkX graph.

### Phase 1 — Recon (unchanged surface, Azure‑aware DNS resolution)
Recon discovers public web targets. Azure additions:
- DNS resolution recognizes `*.azurewebsites.net`, `*.azurecontainerapps.io`, `*.cloudapp.azure.com`, `*.trafficmanager.net`, `*.azurefd.net`, `*.blob.core.windows.net`, `*.file.core.windows.net`, `*.queue.core.windows.net`, `*.table.core.windows.net`, `*.vault.azure.net`, `*.azurecr.io`. Each match seeds a **candidate resource node** with a `provider=azure` tag and a `resource_kind` hint that downstream phases can confirm via `azure-mcp`.
- Front Door / Application Gateway WAF detection via response headers (`X-Azure-Ref`, `X-Cache`).

### Phase 2 — Cloud Audit (formerly "AWS Audit"; renamed and split)

Phase 2 splits into two parallel subphases that share a writer lock on the graph DB:

**Phase 2a — AWS Audit** (unchanged).

**Phase 2b — Azure Audit** (new). Sequenced as follows:

1. **Tenancy enumeration**: `azmcp_subscription_list` → for each subscription, `cloud-audit:management_group_tree`. Build `Tenant`, `ManagementGroup`, `Subscription`, `ResourceGroup` nodes.
2. **Identity enumeration**: `cloud-audit:list_entra_users`, `list_entra_groups`, `list_entra_directory_roles`, `list_service_principals`, `list_app_registrations`, `list_user_assigned_managed_identities`, plus `azmcp_role_assignment_list` per scope. Build `EntraUser`, `EntraGroup`, `EntraDirectoryRole`, `ServicePrincipal`, `AppRegistration`, `UserAssignedMI`, `SystemAssignedMI` nodes and their `MEMBER_OF`, `OWNS_APP`, `HAS_RBAC_ROLE`, `HAS_DIRECTORY_ROLE`, `HAS_API_PERMISSION` edges.
3. **Resource inventory** via Resource Graph KQL (single batched query per category — see §6.4 for the queries):
   - VMs and scale sets (with NIC, public IP, system/user MI bindings).
   - App Services and Function Apps (with VNet integration, identity bindings, public network access flag).
   - AKS clusters (with OIDC issuer, workload identity flag, node pool MIs, network plugin, private cluster flag).
   - Container Apps and Container Instances.
   - Storage accounts (`allowBlobPublicAccess`, `allowSharedKeyAccess`, `networkAcls.defaultAction`).
   - Key Vaults (`enableRbacAuthorization`, access policies if RBAC disabled, network ACLs, public network access).
   - Cosmos DB / SQL / MySQL / PostgreSQL (firewall rules, public endpoint, AAD‑only auth).
   - Networking: VNets, subnets, NSGs (with rule expansion), peerings, private endpoints, route tables, App Gateways, Front Doors, Azure Firewall.
   - Service Bus / Event Hubs / Event Grid (with auth rules).
4. **Federation enumeration**: for each user‑assigned MI and app registration, list federated identity credentials. Cross‑match `subject == system:serviceaccount:<ns>:<sa>` against AKS clusters' OIDC issuer to materialize `WORKLOAD_ID_BOUND` edges (the Azure analogue to AWS `IRSA_BOUND`).
5. **Compliance scan**: `prowler azure --subscription-id … --compliance cis_3.0_azure mcsb_azure nist_800_53_revision_5_azure iso27001_2013_azure soc2_azure prowler_threatscore_azure`. Findings stream into the `findings` table tagged with `provider='azure'`, `subscription_id`, `tenant_id`.
6. **Defender for Cloud cross‑check**: query `securityresources | where type == 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols'` to capture Microsoft's own assessment for the same controls. Drift is logged as a meta‑finding.

### Phase 3 — App Test (unchanged surface, Azure‑aware payloads)
The Playwright‑driven SSRF/SSTI/IDOR battery gains Azure‑specific probes:
- **IMDS payload set**: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with the required `Metadata: true` header. The probe is fired only when the recon phase has flagged the host as Azure‑hosted, and it requires explicit scope authorization in the engagement config (`engagement.allow_imds_probe = true`).
- **App Service / Function App identity endpoint payload**: `$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01` with the `X-IDENTITY-HEADER` header. App Service does **not** expose IMDS at 169.254.169.254 — it uses a localhost sidecar exposed via env vars; Clementine's payload generator handles both shapes.
- **WireServer probe**: `http://168.63.129.16/` (DHCP/health endpoint also reachable from VMs; useful PITM signal but not a token source).
- **SAS token harvesting from leaked URLs in app responses** — the existing SSRF response analyzer is extended to detect `?sv=…&sig=…` patterns and tag them as `azure_sas_token` evidence.
- The audience parameter is enumerated against a small canonical list (`management.azure.com`, `vault.azure.net`, `storage.azure.com`, `graph.microsoft.com`, `database.windows.net`, `cosmos.azure.com`) so that a successful exfil reveals which downstream services the MI can reach without ever leaving the IMDS endpoint.

### Phase 4 — AI Triage
The Bedrock prompt gains Azure context: ARN aliasing extends to Azure resource ID compression (`/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vm>` → a stable short alias like `vm:<sub-prefix>:<rg>:<vm>`). The cache breakpoint strategy is unchanged. See §8 for the prompt language.

### Phase 5 — Correlation & Reporting
The correlation engine consumes the unified graph and the unified pattern set. The HTML report's Attack Graph visualization gains a **provider chip** on every node and a **provider lane** option in the force‑directed layout so reviewers can collapse one cloud at a time. Cross‑cloud paths (e.g., a GitHub Actions OIDC trust that federates to *both* an AWS role and an Azure UAMI) are highlighted as a new "multi‑cloud kill chain" severity class.

---

## 3. Azure‑Specific Graph Node and Edge Taxonomy

This is the load‑bearing part of the spec. The principle: every AWS edge type has an Azure analogue with the same *meaning*, even though the *mechanism* differs. We add new edge types only where there is no AWS equivalent (e.g., `OWNS_APP_REGISTRATION`, `CONSENT_GRANT`).

### 3.1 New node types

| Node type | Notes / corresponds to |
|---|---|
| `Tenant` | One per Microsoft Entra tenant. Top scope. |
| `ManagementGroup` | Hierarchical scope above subscriptions. |
| `Subscription` | Analogue to an AWS account (billing + isolation). |
| `ResourceGroup` | Logical container; the smallest scope above resource. |
| `EntraUser` | Human or guest identity in Entra ID. |
| `EntraGroup` | Security/Microsoft 365 group; can be role‑assignable. |
| `EntraDirectoryRole` | Built‑in or custom directory role (e.g., Global Admin, Privileged Role Admin, Application Admin). |
| `ServicePrincipal` | Tenant‑side instance of an app registration. Includes *first‑party* SPs and managed‑identity SPs. |
| `AppRegistration` | Multi‑tenant or single‑tenant application object. |
| `SystemAssignedMI` | System‑assigned managed identity bound 1:1 to a resource. |
| `UserAssignedMI` | Standalone managed identity, may be attached to many resources. |
| `RoleDefinition` | Built‑in or custom Azure RBAC role definition (with its actions/dataActions/notActions). |
| `RoleAssignment` | An *edge‑style node* (modelable as edge or node; we model as node so that PIM‑eligible vs active and `condition` ABAC expressions are first‑class properties). |
| `FederatedCredential` | Trust binding on a UAMI/App Reg to an external OIDC issuer. |
| `VirtualMachine`, `VMSS` | Compute. |
| `AppService`, `FunctionApp`, `ContainerApp`, `ContainerInstance` | PaaS compute. |
| `AKSCluster`, `AKSNodePool` | Kubernetes. |
| `AKSServiceAccount` | A Kubernetes SA inside an AKS cluster, materialized only when bound by federated credential. |
| `StorageAccount`, `BlobContainer`, `FileShare`, `Queue`, `Table` | Storage. |
| `KeyVault`, `KVSecret`, `KVKey`, `KVCertificate` | Secrets. Each child has `enabled`, `expires`, `not_before`, `recovery_level`. |
| `CosmosAccount`, `SQLServer`, `SQLDatabase`, `MySQLServer`, `PostgreSQLServer` | Databases. |
| `VNet`, `Subnet`, `NSG`, `NSGRule`, `RouteTable`, `Peering`, `PrivateEndpoint`, `AppGateway`, `FrontDoor`, `AzureFirewall` | Network. |
| `ServiceBusNamespace`, `EventHubsNamespace`, `EventGridTopic` | Messaging. |
| `LogAnalyticsWorkspace`, `DiagnosticSetting`, `AzurePolicyAssignment`, `DefenderPlan` | Governance. |

### 3.2 New edge types (AWS analogues in italics)

| Azure edge | Meaning | AWS analogue |
|---|---|---|
| `CAN_ASSUME_MI` | A principal can request a token *as* a managed identity (typically by virtue of compute attachment + execute). | *CAN_ASSUME* |
| `HAS_RBAC_ROLE` | `principal --[role @ scope]--> scope_node`. The role is a property of the edge, *or* the edge passes through a `RoleAssignment` node. We use the latter to support PIM and ABAC. | *HAS_PERMISSION* |
| `HAS_DIRECTORY_ROLE` | Entra ID directory role membership (Global Admin etc.). Distinguished from RBAC because it lives in Microsoft Graph, not ARM. | *HAS_PERMISSION* (for AWS SSO) |
| `HAS_API_PERMISSION` | App role assignment / delegated permission on Microsoft Graph or another resource API. | (no direct analogue) |
| `OWNS_APP_REGISTRATION` | Principal owns an app registration; can mint new client secrets/certs. | (no direct analogue; closest is *iam:UpdateLoginProfile*) |
| `CONSENT_GRANT` | OAuth2PermissionGrant or AppRoleAssignment authorizing one SP to act on another's API. | (no direct analogue) |
| `CAN_ATTACH_MI` | Principal can attach a UAMI to a compute resource (i.e., ride the identity). The Azure analogue of `CAN_PASS_ROLE`. | *CAN_PASS_ROLE* |
| `MI_ATTACHED_TO` | `MI --> compute resource` (the actual binding). | *iam:InstanceProfile* attachment |
| `WORKLOAD_ID_BOUND` | `AKSServiceAccount --> UserAssignedMI` via federated credential matching the AKS OIDC issuer. | *IRSA_BOUND* |
| `OIDC_TRUSTS` | `UserAssignedMI/AppRegistration --> ExternalIDP` (GitHub Actions, GitLab, AWS Cognito, SPIFFE, etc.). | *OIDC_TRUSTS* |
| `ROUTES_TO` | Subnet/NIC/route table reachability. Identical semantic to AWS. | *ROUTES_TO* |
| `INTERNET_FACING` | Resource has a public IP, public hostname, or `publicNetworkAccess=Enabled` with permissive NSG/firewall. | *INTERNET_FACING* |
| `SSRF_REACHABLE` | App‑Test confirmed an SSRF path that reaches the Azure IMDS or App Service identity endpoint of this resource. | *SSRF_REACHABLE* |
| `IMDS_EXPOSED` | The compute resource's IMDS is reachable (no IMDS hardening, no network policy block of `169.254.169.254`). Per‑resource flag. | *IMDSv1_ENABLED* |
| `INVOKES` | App Service → Function, Logic App → Function, EventGrid → handler. | *INVOKES* |
| `ENCRYPTS_WITH` | Resource → KMS / Key Vault key used for CMK. | *ENCRYPTS_WITH* |
| `STORES_SECRET_FOR` | KeyVault secret/cert is referenced by an App Service config, AKS CSI driver, Function App, etc. | (no direct analogue) |
| `PEERED_WITH`, `PRIVATE_LINK_TO` | VNet topology. | *PEERED_WITH*, *VPC_ENDPOINT_TO* |
| `POLICY_APPLIES_TO` | Azure Policy assignment scope coverage. | *SCP_APPLIES_TO* |
| `PIM_ELIGIBLE_FOR` | Principal is *eligible* (not active) for a directory or RBAC role via PIM. We graph eligibility because it's a one‑click activation away. | (no direct analogue) |
| `CAN_RESET_CREDENTIAL_FOR` | Application Admin / Cloud Application Admin / Authentication Admin → SP/User. The primitive behind the SpecterOps Application Admin → Global Admin escalation. | *iam:UpdateAccessKey*‑like |

### 3.3 Modeling RoleAssignment as a node, not an edge

In AWS, a permission is a tuple of `(principal, action, resource, condition)`. In Azure, a role assignment is a tuple of `(principalId, roleDefinitionId, scope, condition?, principalType, conditionVersion)` — and **scope inheritance** propagates downward (an assignment at MG level applies to every subscription beneath). To make path‑finding tractable in NetworkX we:

1. Materialize one `RoleAssignment` node per assignment.
2. Add `principal --[ASSIGNED]--> RoleAssignment --[OVER]--> scope_node`.
3. **Pre‑compute downward expansion**: at audit time, expand each assignment to all descendant scopes and emit `principal --[HAS_RBAC_ROLE { role, source_assignment_id, inherited=true }]--> resource_node`. The expanded edges are what `paths_between()` traverses; the `RoleAssignment` node is preserved for explanation in the report.

This preserves the existing `AttackSurfaceAnalyzer` API (`paths_between`, `principals_reaching`, `cycle_detect`) without touching its internals — Azure data simply produces more edges of an existing kind.

### 3.4 Modeling PIM eligibility

PIM eligibility is added as a **dotted edge** (`PIM_ELIGIBLE_FOR`) and the correlation engine's path scoring assigns a discount factor (`pim_activation_cost`, default 0.7) to paths that traverse one or more `PIM_ELIGIBLE_FOR` edges. The HTML report renders these dotted to make the activation step visible.

---

## 4. New YAML Correlation Patterns for Azure Compound Chains

Patterns live in `/patterns/azure/` and use the same schema as existing AWS patterns (`name`, `severity`, `tags`, `via_edges`, `start`, `end`, `predicates`, `narrative_template`, `remediation_refs`). Below are the canonical Azure patterns; the full delivery set is 32 patterns.

### 4.1 IMDS abuse → managed identity → resource access

```yaml
name: azure_ssrf_imds_managed_identity_resource_access
severity: critical
tags: [ssrf, imds, managed-identity, t1552.005, attck-imds]
description: >
  SSRF in an internet-facing Azure compute resource reaches the Azure IMDS
  (or App Service identity endpoint), exfiltrates a managed identity token,
  and the bound identity has RBAC on a downstream resource.
start:
  node_type: AppService | FunctionApp | VirtualMachine | ContainerApp
  predicates:
    - INTERNET_FACING == true
    - SSRF_REACHABLE == true
    - IMDS_EXPOSED == true
via_edges:
  - SSRF_REACHABLE
  - MI_ATTACHED_TO
  - HAS_RBAC_ROLE
end:
  node_type: KeyVault | StorageAccount | CosmosAccount | SQLServer | Subscription
  predicates:
    - role_grants_data_plane: true
narrative_template: |
  {{start.name}} is internet-facing and vulnerable to SSRF
  (evidence: {{evidence.ssrf_finding_id}}). Its attached managed identity
  {{mi.name}} has the role {{role.name}} at {{end.scope}}, which permits
  {{role.dataActions|join(', ')}}. An attacker exploiting the SSRF can mint
  an IMDS token for `{{audience}}` and read/exfiltrate from {{end.name}}.
remediation_refs:
  - cis_azure: "5.1.1"
  - mcsb: "PA-3"
  - microsoft_learn: "azure/security/fundamentals/paas-applications-using-app-services"
```

### 4.2 Application Administrator → Global Admin via service principal abuse

This is the SpecterOps "MyCoolApp" path (Application Admin can add a credential to any SP; if any SP has Privileged Role Administrator or Global Admin, escalation is one auth flow away).

```yaml
name: azure_app_admin_to_global_admin_via_sp
severity: critical
tags: [entra-id, t1098.003, t1078.004, privesc]
start:
  node_type: EntraUser | ServicePrincipal
  predicates:
    - HAS_DIRECTORY_ROLE in [
        "Application Administrator",
        "Cloud Application Administrator",
        "Hybrid Identity Administrator"
      ]
via_edges:
  - CAN_RESET_CREDENTIAL_FOR
end:
  node_type: ServicePrincipal
  predicates:
    - HAS_DIRECTORY_ROLE in [
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator"
      ]
```

### 4.3 Key Vault Contributor → access policy injection → secret exfil

The Datadog 2024 finding: `Key Vault Contributor` can write access policies on legacy (non‑RBAC) vaults, granting itself `secrets/get` and reading every secret. This is documented Microsoft *intended behavior* now but it remains an attack path.

```yaml
name: azure_kv_contributor_access_policy_self_grant
severity: high
tags: [keyvault, t1552.001, privesc]
start:
  node_type: EntraUser | ServicePrincipal | UserAssignedMI
  predicates:
    - HAS_RBAC_ROLE.role in ["Key Vault Contributor", "Contributor", "Owner"]
end:
  node_type: KeyVault
  predicates:
    - enableRbacAuthorization == false
    - kvNetworkAcls.defaultAction != "Deny" OR principal_in_allowed_ips
narrative_template: |
  {{start.name}} holds {{role.name}} on {{end.name}}, a Key Vault using the
  legacy access-policy authorization model. Per documented Azure behavior,
  this role can write access policies, including granting itself
  `Microsoft.KeyVault/vaults/accessPolicies/write` permissions to read
  secrets/keys/certificates on the data plane. Recommend migrating the
  vault to the RBAC permission model (`enableRbacAuthorization: true`).
```

### 4.4 AKS Workload Identity → cross‑service MI compromise

The IRSA analogue: a pod with a service account federated to a UAMI that has Contributor on the subscription = subscription takeover from a single pod RCE.

```yaml
name: azure_aks_workload_identity_overprivileged_uami
severity: critical
tags: [aks, workload-identity, t1078.004, federation]
start:
  node_type: AKSServiceAccount
  predicates:
    - INTERNET_FACING == true   # via ingress reachability traversal
via_edges:
  - WORKLOAD_ID_BOUND       # AKSServiceAccount -> UserAssignedMI
  - HAS_RBAC_ROLE
end:
  node_type: Subscription | ResourceGroup | KeyVault
  predicates:
    - role.name in [
        "Owner", "Contributor", "User Access Administrator",
        "Key Vault Administrator", "Storage Blob Data Owner"
      ]
```

### 4.5 Storage account anonymous blob exposure

```yaml
name: azure_storage_anonymous_blob_public_exposure
severity: high
tags: [storage, public-exposure, cis-3.5, mcsb-dp-2]
start: { node_type: BlobContainer }
predicates:
  - publicAccess in ["Container", "Blob"]
  - storageAccount.allowBlobPublicAccess == true
  - storageAccount.networkAcls.defaultAction == "Allow"
```

### 4.6 SAS token misuse — long‑lived account‑scope SAS

```yaml
name: azure_storage_long_lived_account_sas
severity: high
tags: [storage, sas, t1552.001]
predicates:
  - storageAccount.allowSharedKeyAccess == true
  - sas_evidence.expiry_days > 7
  - sas_evidence.permissions ⊇ ["r","w","l","d"] OR sas_evidence.scope == "account"
notes: |
  This pattern fires when AppTest harvests a SAS from an SSRF response or
  recon finds one in a public asset.
```

### 4.7 Subscription / management‑group escalation via custom role with `Microsoft.Authorization/roleAssignments/write`

```yaml
name: azure_custom_role_iam_write_privesc
severity: critical
tags: [rbac, custom-role, privesc]
start: { node_type: EntraUser | ServicePrincipal | UserAssignedMI }
predicates:
  - exists(role in start.roles where (
        "Microsoft.Authorization/roleAssignments/write" in role.actions
     OR "Microsoft.Authorization/roleDefinitions/write"  in role.actions
     OR "*" in role.actions
    ))
end: { node_type: Subscription | ManagementGroup | ResourceGroup }
```

### 4.8 VM Run Command / Custom Script Extension → MI hijack

The Praetorian path: `Microsoft.Compute/virtualMachines/runCommand/action` or `extensions/write` on a VM that has a privileged MI = full subscription takeover by piggy‑backing on the IMDS from inside the VM.

```yaml
name: azure_vm_run_command_to_mi_takeover
severity: critical
tags: [t1059, vm-extensions, mi-hijack]
predicates:
  - principal.has_action in [
      "Microsoft.Compute/virtualMachines/runCommand/action",
      "Microsoft.Compute/virtualMachines/extensions/write",
      "Microsoft.Compute/virtualMachines/login/action"
    ]
  - vm.MI_ATTACHED_TO is not null
  - vm.MI.HAS_RBAC_ROLE.role in ["Owner","Contributor","User Access Administrator"]
```

### 4.9 PIM eligibility = latent escalation

```yaml
name: azure_pim_eligibility_latent_global_admin
severity: medium
tags: [pim, latent, governance]
predicates:
  - exists PIM_ELIGIBLE_FOR(start, "Global Administrator")
  - start.mfa_enforced == false OR start.account_inactive_days > 90
```

### 4.10 Cross‑tenant federation risk

```yaml
name: azure_cross_tenant_federation_open_subject
severity: high
tags: [federation, cross-tenant, t1199]
start: { node_type: UserAssignedMI | AppRegistration }
predicates:
  - exists fed in start.federatedCredentials where (
        fed.issuer not in trusted_issuers
     OR fed.subject == "*"
     OR fed.audience == "api://AzureADTokenExchange" AND fed.subject_pattern_matches_wildcard
    )
```

### 4.11 Function App SSRF → KeyVault secret reference exfil

Function Apps frequently mount Key Vault secrets via `@Microsoft.KeyVault(SecretUri=…)` references. SSRF that reaches `IDENTITY_ENDPOINT` mints a vault‑audience token; the secret reference URI is recoverable from app settings.

```yaml
name: azure_functionapp_ssrf_kv_reference_exfil
severity: critical
tags: [functions, ssrf, keyvault]
predicates:
  - functionapp.SSRF_REACHABLE == true
  - functionapp.identity != null
  - functionapp.appsettings has_kv_reference == true
  - functionapp.identity.HAS_RBAC_ROLE.scope contains kv_reference.vault
```

The other 21 patterns cover: Cosmos firewall + AAD‑off; SQL public endpoint + no AAD‑only; ACR anonymous pull; Service Bus shared‑access policy with `Manage`; Event Hub `RootManageSharedAccessKey` exposure; orphan role assignments to deleted principals (object‑ID recycling risk); NSG inbound `*` from internet to management ports; Bastion missing while VM has public IP; App Service `scmIpSecurityRestrictionsUseMain=false`; diagnostic settings missing; Defender plans disabled; storage account with `allowSharedKeyAccess=true` plus `Reader and Data Access` role assignments (the role that can list keys); managed identity assigned `User Access Administrator` (a frequent terraform mistake); App Gateway WAF mode `Detection` instead of `Prevention`; Front Door without WAF; Azure Firewall threat intel mode `Off`; private endpoint with `privateLinkServiceConnectionState=Approved` from foreign subscription; cross‑MG inheritance bringing unexpected Owner; Conditional Access policy that excludes "All users" via group; break‑glass account without sign‑in alerts.

---

## 5. SQL Schema Additions

The existing schema (`findings`, `graph_nodes`, `graph_edges`, `enrichment_status`, `ai_usage`) is extended in a backward‑compatible way: new columns are nullable, existing AWS‑only columns continue to be populated for AWS findings.

### 5.1 New columns

```sql
-- findings
ALTER TABLE findings ADD COLUMN provider TEXT NOT NULL DEFAULT 'aws'
    CHECK (provider IN ('aws','azure','gcp','m365','k8s','multi'));
ALTER TABLE findings ADD COLUMN tenant_id TEXT;             -- Entra tenant GUID
ALTER TABLE findings ADD COLUMN subscription_id TEXT;       -- Azure subscription GUID
ALTER TABLE findings ADD COLUMN management_group_id TEXT;
ALTER TABLE findings ADD COLUMN resource_group TEXT;
ALTER TABLE findings ADD COLUMN azure_resource_id TEXT;     -- full /subscriptions/.../providers/...
ALTER TABLE findings ADD COLUMN azure_region TEXT;          -- "westus3" etc; AWS continues to use 'region'

CREATE INDEX idx_findings_provider_subscription
    ON findings(provider, subscription_id);
CREATE INDEX idx_findings_tenant
    ON findings(tenant_id) WHERE tenant_id IS NOT NULL;

-- graph_nodes
ALTER TABLE graph_nodes ADD COLUMN provider TEXT NOT NULL DEFAULT 'aws';
ALTER TABLE graph_nodes ADD COLUMN tenant_id TEXT;
ALTER TABLE graph_nodes ADD COLUMN subscription_id TEXT;
ALTER TABLE graph_nodes ADD COLUMN management_group_id TEXT;
ALTER TABLE graph_nodes ADD COLUMN resource_group TEXT;
ALTER TABLE graph_nodes ADD COLUMN azure_resource_id TEXT;
ALTER TABLE graph_nodes ADD COLUMN node_kind TEXT;          -- e.g., 'EntraUser', 'KeyVault'
ALTER TABLE graph_nodes ADD COLUMN compressed_alias TEXT;   -- for Bedrock prompt compression
CREATE INDEX idx_graph_nodes_kind ON graph_nodes(provider, node_kind);

-- graph_edges
ALTER TABLE graph_edges ADD COLUMN provider TEXT NOT NULL DEFAULT 'aws';
ALTER TABLE graph_edges ADD COLUMN edge_kind TEXT;          -- e.g., 'HAS_RBAC_ROLE'
ALTER TABLE graph_edges ADD COLUMN role_definition_id TEXT; -- Azure
ALTER TABLE graph_edges ADD COLUMN scope TEXT;              -- Azure scope path
ALTER TABLE graph_edges ADD COLUMN scope_level TEXT
    CHECK (scope_level IN ('mg','subscription','rg','resource'));
ALTER TABLE graph_edges ADD COLUMN inherited BOOLEAN DEFAULT FALSE;
ALTER TABLE graph_edges ADD COLUMN source_assignment_id TEXT;
ALTER TABLE graph_edges ADD COLUMN condition_expr TEXT;     -- ABAC / RBAC condition string
ALTER TABLE graph_edges ADD COLUMN pim_eligible BOOLEAN DEFAULT FALSE;
ALTER TABLE graph_edges ADD COLUMN audience TEXT;           -- IMDS token audience for SSRF edges
CREATE INDEX idx_graph_edges_kind ON graph_edges(provider, edge_kind);

-- enrichment_status
ALTER TABLE enrichment_status ADD COLUMN provider TEXT NOT NULL DEFAULT 'aws';
ALTER TABLE enrichment_status ADD COLUMN scope_id TEXT;     -- subscription_id or AWS account_id

-- ai_usage  (no schema change required; tag prompts with provider in metadata JSON)
```

### 5.2 New tables

```sql
CREATE TABLE azure_role_assignments (
    id TEXT PRIMARY KEY,                  -- assignment GUID
    tenant_id TEXT NOT NULL,
    subscription_id TEXT,
    scope TEXT NOT NULL,
    scope_level TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_type TEXT NOT NULL,         -- User|Group|ServicePrincipal|MSI
    role_definition_id TEXT NOT NULL,
    role_definition_name TEXT,
    condition TEXT,
    condition_version TEXT,
    pim_eligible BOOLEAN DEFAULT FALSE,
    pim_eligibility_expires TIMESTAMP,
    created_on TIMESTAMP,
    updated_on TIMESTAMP,
    discovered_at TIMESTAMP NOT NULL
);

CREATE TABLE azure_federated_credentials (
    id TEXT PRIMARY KEY,
    parent_resource_id TEXT NOT NULL,     -- UAMI or AppRegistration
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    audiences TEXT NOT NULL,              -- JSON array
    name TEXT NOT NULL,
    matched_aks_cluster_id TEXT,          -- nullable; populated by post-processor
    matched_k8s_subject TEXT
);

CREATE TABLE azure_compliance_findings (
    id TEXT PRIMARY KEY,
    framework TEXT NOT NULL,              -- 'CIS_3_0_AZURE','MCSB','NIST_800_53_R5','ISO_27001','SOC2','PROWLER_THREATSCORE'
    control_id TEXT NOT NULL,
    resource_id TEXT,
    subscription_id TEXT,
    state TEXT NOT NULL,                  -- 'pass','fail','manual','skipped','greyed'
    severity TEXT,
    source TEXT NOT NULL,                 -- 'prowler','defender_for_cloud','azqr'
    raw JSON
);
CREATE INDEX idx_compliance_state ON azure_compliance_findings(framework, state);
```

---

## 6. Configuration Reference

### 6.1 New `azure` config block (`config.yaml`)

```yaml
azure:
  enabled: true
  tenant_id: "00000000-0000-0000-0000-000000000000"
  # Specific subscriptions to scan; empty list = all the principal can see.
  subscriptions: []
  # Management groups — scan everything beneath, recursively.
  management_groups: []
  # Limit by region; empty = all regions.
  regions: []
  # Authentication: 'service_principal' | 'cli' | 'managed_identity' | 'workload_identity' | 'broker'
  auth:
    method: service_principal
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"      # or use cert_path for cert-based auth
    cert_path: null
    federated_token_file: null                   # for workload identity
  mcp_server:
    transport: stdio                             # stdio | http
    mode: namespace                              # namespace | consolidated | all | single
    namespaces:                                  # whitelist; reduces token cost
      - role
      - subscription
      - group
      - storage
      - keyvault
      - aks
      - appservice
      - functionapp
      - acr
      - cosmos
      - sql
      - mysql
      - postgres
      - servicebus
      - eventhubs
      - eventgrid
      - monitor
      - policy
      - resourcehealth
      - extension
    read_only: true
    insecure_disable_user_confirmation: false    # NEVER set true for prod
    include_production_credentials: true         # for AKS/MI hosting
    only_use_broker_credential: false
  prowler:
    enabled: true
    compliance:
      - cis_3.0_azure
      - mcsb_azure
      - nist_800_53_revision_5_azure
      - iso27001_2013_azure
      - soc2_azure
      - prowler_threatscore_azure
    parallel_scans: 4
  defender_for_cloud:
    enabled: true
    cross_check_against_prowler: true
  resource_graph:
    authorization_scope_filter: AtScopeAndAbove  # to capture inherited assignments
    join_limit: 3                                # default ARG limit; bump per Microsoft support if required
    page_size: 1000
  imds_probe:
    enabled: false                               # only true when engagement allows
    audiences:
      - https://management.azure.com/
      - https://vault.azure.net
      - https://storage.azure.com/
      - https://graph.microsoft.com
      - https://database.windows.net/
      - https://cosmos.azure.com/
  pim:
    treat_eligible_as_active: false              # if true, eligibility edges become solid in graph
    activation_cost: 0.7
  graph:
    expand_inherited_assignments: true
    materialize_role_definitions: true           # full action set per role
    aks_workload_identity_match: true
  prompts:
    enable_resource_id_aliasing: true
    alias_max_length: 24
```

### 6.2 Engagement‑scope guardrails

Clementine's engagement file gains:

```yaml
engagement:
  azure:
    in_scope_subscriptions: ["…"]
    in_scope_management_groups: ["…"]
    excluded_resource_groups: ["sec-tools-rg"]
    allow_imds_probe: false
    allow_anonymous_blob_access_test: true
    allow_kv_secret_metadata_read: true   # never raw values
    allow_sas_token_extraction: true
    allow_run_command_test: false         # too disruptive — confirm reachability only
```

### 6.3 Environment variables consumed by Azure MCP Server

| Variable | Purpose |
|---|---|
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Service principal auth. |
| `AZURE_FEDERATED_TOKEN_FILE` | Workload identity. |
| `AZURE_MCP_INCLUDE_PRODUCTION_CREDENTIALS=true` | Enable workload/managed identity in the credential chain. |
| `AZURE_MCP_ONLY_USE_BROKER_CREDENTIAL=true` | Force WAM/browser broker (interactive). |
| `AZURE_CLOUD` | `AzurePublicCloud` (default), `AzureUSGovernment`, `AzureChinaCloud`. |

### 6.4 Canonical KQL queries Clementine ships

These live in `/queries/azure/*.kql` and are loaded by the `cloud-audit` Resource Graph wrapper.

**Tenant‑wide role assignments with inheritance (the spine of the IAM graph):**

```kusto
authorizationresources
| where type == "microsoft.authorization/roleassignments"
| extend principalId    = tostring(properties.principalId)
| extend principalType  = tostring(properties.principalType)
| extend roleDefId      = tostring(properties.roleDefinitionId)
| extend scope          = tostring(properties.scope)
| extend conditionExpr  = tostring(properties.condition)
| extend createdOn      = todatetime(properties.createdOn)
| project id, principalId, principalType, roleDefId, scope,
          conditionExpr, createdOn
// run with AuthorizationScopeFilter=AtScopeAndAbove and api-version 2021-06-01-preview+
```

**Role definitions with full actions/dataActions:**

```kusto
authorizationresources
| where type == "microsoft.authorization/roledefinitions"
| extend roleName  = tostring(properties.roleName)
| extend rType     = tostring(properties.type)
| extend perms     = properties.permissions
| mv-expand perms
| project id, roleName, rType,
          actions     = perms.actions,
          notActions  = perms.notActions,
          dataActions = perms.dataActions,
          notDataActions = perms.notDataActions,
          assignableScopes = properties.assignableScopes
```

**VMs with managed identity bindings:**

```kusto
Resources
| where type =~ "microsoft.compute/virtualmachines"
| extend identityType = tostring(identity.type)
| extend systemMI     = tostring(identity.principalId)
| extend userMIs      = identity.userAssignedIdentities
| extend nicIds       = properties.networkProfile.networkInterfaces
| project id, name, resourceGroup, subscriptionId, location,
          identityType, systemMI, userMIs, nicIds,
          osType  = tostring(properties.storageProfile.osDisk.osType),
          imdsv2  = tostring(properties.securityProfile.uefiSettings)
```

**Internet‑facing compute via NSG inbound rules + public IPs:**

```kusto
Resources
| where type contains "publicIPAddresses" and isnotempty(properties.ipAddress)
| project pipId=id, ip=tostring(properties.ipAddress),
          attached=tostring(properties.ipConfiguration.id)
| join kind=leftouter (
    Resources
    | where type =~ "microsoft.network/networkinterfaces"
    | mv-expand ipconf=properties.ipConfigurations
    | extend nicId=id, vmId=tostring(properties.virtualMachine.id),
             pipRef=tostring(ipconf.properties.publicIPAddress.id)
    | project nicId, vmId, pipRef
) on $left.pipId == $right.pipRef
```

**Storage accounts with public access flags:**

```kusto
Resources
| where type =~ "microsoft.storage/storageaccounts"
| project id, name, resourceGroup, subscriptionId, location,
          allowBlobPublicAccess = tobool(properties.allowBlobPublicAccess),
          allowSharedKeyAccess  = tobool(properties.allowSharedKeyAccess),
          minimumTlsVersion     = tostring(properties.minimumTlsVersion),
          publicNetworkAccess   = tostring(properties.publicNetworkAccess),
          defaultAction         = tostring(properties.networkAcls.defaultAction),
          httpsOnly             = tobool(properties.supportsHttpsTrafficOnly)
```

**Key Vaults — RBAC vs access policy + network ACLs:**

```kusto
Resources
| where type =~ "microsoft.keyvault/vaults"
| project id, name, resourceGroup, subscriptionId, location,
          rbacEnabled       = tobool(properties.enableRbacAuthorization),
          accessPolicies    = properties.accessPolicies,
          publicNetworkAccess = tostring(properties.publicNetworkAccess),
          defaultAction     = tostring(properties.networkAcls.defaultAction),
          softDelete        = tobool(properties.enableSoftDelete),
          purgeProtection   = tobool(properties.enablePurgeProtection)
```

**AKS clusters with workload identity:**

```kusto
Resources
| where type =~ "microsoft.containerservice/managedclusters"
| project id, name, resourceGroup, subscriptionId,
          oidcIssuerEnabled = tobool(properties.oidcIssuerProfile.enabled),
          oidcIssuerUrl     = tostring(properties.oidcIssuerProfile.issuerUrl),
          workloadIdentity  = tobool(properties.securityProfile.workloadIdentity.enabled),
          aadProfile        = properties.aadProfile,
          apiServerAccess   = properties.apiServerAccessProfile,
          networkPlugin     = tostring(properties.networkProfile.networkPlugin),
          privateCluster    = tobool(properties.apiServerAccessProfile.enablePrivateCluster)
```

**NSG rules allowing inbound from internet to management ports:**

```kusto
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.access) == "Allow"
  and tostring(rule.properties.direction) == "Inbound"
  and tostring(rule.properties.sourceAddressPrefix) in ("*","Internet","0.0.0.0/0")
| extend port = tostring(rule.properties.destinationPortRange)
| where port in ("*","22","3389","3306","5432","1433","6379","27017","9200")
| project nsgId=id, nsgName=name, ruleName=tostring(rule.name), port,
          subnets=properties.subnets, nics=properties.networkInterfaces
```

**Defender for Cloud control state for cross‑check:**

```kusto
securityresources
| where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
| extend standard = tostring(split(id, '/')[8])
| extend control  = tostring(properties.description)
| extend state    = tostring(properties.state)
| where standard in ("CIS-Azure-2.0.0","CIS-Azure-3.0.0","Azure-CSPM",
                     "MCSB","NIST-SP-800-53-Rev5","ISO27001-2013")
| project standard, control, state
```

**Federated identity credentials (joined to UAMIs):**

```kusto
Resources
| where type =~ "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials"
| extend parentUami = tostring(split(id, '/federatedIdentityCredentials/')[0])
| project id, name=tostring(properties.name),
          issuer=tostring(properties.issuer),
          subject=tostring(properties.subject),
          audiences=properties.audiences,
          parentUami
```

---

## 7. Authentication and Least‑Privilege Permission Set

The minimum role bundle for the Clementine Azure auditor service principal:

### 7.1 Azure RBAC (control plane + read‑only data plane)

| Role | Scope | Why |
|---|---|---|
| **Reader** | Tenant root MG (or each in‑scope MG / subscription) | All resource metadata, RBAC assignments via `authorizationresources`, network topology, configurations. |
| **Security Reader** | Tenant root MG | Defender for Cloud assessments and recommendations, regulatory compliance state. |
| **Storage Blob Data Reader** | Per storage account (or subscription) | List/inspect blob containers and metadata via the data plane (control‑plane Reader does *not* let you read container `publicAccess` reliably). |
| **Key Vault Reader** | Per key vault (or subscription) | Vault metadata. |
| **Key Vault Secrets User** *(optional)* | Per vault — typically **disabled** in Clementine | Only if engagement scope allows reading secret values. Default config reads only metadata via `Key Vault Reader`. |
| **Reader and Data Access** | **Avoid** | This built‑in role can list account keys; Clementine does not need it. Audit it as a *finding* if granted. |
| **Log Analytics Reader** | Per workspace | KQL queries over diagnostic data via `azmcp_monitor`. |

### 7.2 Microsoft Entra (directory / Microsoft Graph)

The Azure MCP Server's `role` namespace covers RBAC; everything Entra is reached via Microsoft Graph and requires distinct permissions.

| Permission (application or delegated) | Why |
|---|---|
| **Directory.Read.All** *(Microsoft Graph, application)* | Read users, groups, group memberships, directory roles. |
| **RoleManagement.Read.Directory** | Read directory role assignments and PIM eligibility. |
| **Application.Read.All** | Read app registrations, service principals, federated identity credentials, owners, app role assignments, OAuth2 grants. |
| **Policy.Read.All** | Read Conditional Access policies (for the report's identity hygiene section). |
| **AuditLog.Read.All** *(optional)* | Sign‑in / audit logs for the *resource events* timeline analogue. |
| **Directory Readers** *(directory role)* | Alternative coarser grant to the above for environments that prohibit Graph application permissions; insufficient for app role and federated credential reads. |

> **Hard rule for Clementine 2.0**: never request `Directory.ReadWrite.All`, `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `User.ReadWrite.All`, or any role that can write — these *are* the privileged abuse primitives Clementine is supposed to find. The audit identity must not be capable of any operation in the Top‑10 attack patterns we detect.

### 7.3 Concrete bootstrap recipe

```bash
# Service principal
az ad sp create-for-rbac \
    --name "clementine-auditor" \
    --role "Reader" \
    --scopes "/providers/Microsoft.Management/managementGroups/<root-mg-id>"

# Add Security Reader at root MG
az role assignment create \
    --role "Security Reader" \
    --assignee <sp-object-id> \
    --scope "/providers/Microsoft.Management/managementGroups/<root-mg-id>"

# Add data-plane reads for storage/keyvault at subscription scope (loop per subscription)
az role assignment create \
    --role "Storage Blob Data Reader" \
    --assignee <sp-object-id> \
    --scope "/subscriptions/<sub-id>"

az role assignment create \
    --role "Key Vault Reader" \
    --assignee <sp-object-id> \
    --scope "/subscriptions/<sub-id>"

# Microsoft Graph application permissions (consent required)
az ad app permission add \
    --id <sp-app-id> \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions \
        7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role \
        483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role \
        9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role \
        246dd0d5-5bd0-4def-940b-0421030a5b68=Role
# Then: az ad app permission admin-consent --id <sp-app-id>
```

For **production deployments inside Azure**, prefer a user‑assigned managed identity over a service principal with secrets, attached to the AKS pod / Container App / VM that runs Clementine, with `AZURE_MCP_INCLUDE_PRODUCTION_CREDENTIALS=true`.

---

## 8. System Prompt Guidance per Phase

Each prompt assumes Bedrock Claude Sonnet 4.6 (default) or Opus 4.7 (deep triage). Prompts are stored in `/prompts/azure/<phase>.md` and composed with the existing AWS prompts via the orchestrator's prompt assembler. ARN aliasing is replaced by **Azure resource ID aliasing**: every resource ID is replaced with a 12–24‑char alias (`vm:dxz`, `kv:zlq`) and a lookup table is appended at end of context, behind a cache breakpoint.

### 8.1 Phase 1 — Recon (Azure addendum)

```
You are extending a reconnaissance pass with Azure-aware DNS classification.
For every hostname on the in-scope list:
  1. Classify the hostname against this allowlist of Azure suffixes:
     azurewebsites.net, azurecontainerapps.io, cloudapp.azure.com,
     trafficmanager.net, azurefd.net, blob.core.windows.net,
     vault.azure.net, azurecr.io, file.core.windows.net,
     queue.core.windows.net, table.core.windows.net,
     servicebus.windows.net, database.windows.net,
     documents.azure.com, search.windows.net.
  2. Emit a candidate Azure resource node with provider=azure and a
     resource_kind hint derived from the suffix.
  3. Do NOT call any azure-mcp tool yet; that is Phase 2's job.
  4. If a hostname resolves to 169.254.169.254 (or any RFC3927 link-local
     after DNS rebinding shenanigans), flag it as imds_dns_rebind_suspected
     — but do not probe.
```

### 8.2 Phase 2b — Azure Cloud Audit

```
You are an Azure cloud auditor. Your job is to populate the knowledge graph
with every identity, resource, and edge needed for compound-chain detection.
Tools available: azure-mcp (read-only, namespaces: role, subscription, group,
storage, keyvault, aks, appservice, functionapp, acr, cosmos, sql, monitor,
policy), cloud-audit (Azure module), prowler-mcp, microsoft-learn-mcp.

ORDER OF OPERATIONS (do not deviate):
  1. azmcp_subscription_list                          → subscription nodes
  2. cloud-audit:management_group_tree                → MG hierarchy
  3. cloud-audit:list_entra_users / _groups /
     _service_principals / _app_registrations /
     _user_assigned_managed_identities /
     _directory_roles / _pim_assignments              → identity nodes
  4. cloud-audit:resource_graph_query (KQL files in /queries/azure/*.kql,
     using AuthorizationScopeFilter=AtScopeAndAbove)  → resources + RBAC
  5. cloud-audit:list_federated_identity_credentials  → fed-cred edges
  6. azmcp_aks_cluster_list → for each cluster pull oidcIssuerProfile.issuerUrl
     and bind matching federated credentials by subject string.
  7. prowler-mcp:scan_azure(subscriptions=[…],
     compliance=[cis_3.0_azure, mcsb_azure, nist_800_53_revision_5_azure,
                  iso27001_2013_azure, soc2_azure, prowler_threatscore_azure])
  8. cloud-audit:resource_graph_query for Defender control state
     (securityresources table); diff against Prowler results.

FAILURE MODES:
  - 403 on azmcp_*  → identity is missing the Reader/Security Reader/
    Key Vault Reader/Storage Blob Data Reader role. Log to enrichment_status
    with status='blocked', reason='rbac_insufficient', do NOT abort, continue
    to next subscription.
  - 429 throttling  → exponential backoff per Azure MCP Server's built-in
    retry (mode=exponential, maxRetries=4, retryDelay=2s, retryDelayMax=10s).
    If still 429 after 4 attempts, log and skip this resource type for the
    affected subscription only.
  - Resource Graph DisallowedMaxNumberOfRemoteTables  → split the query;
    you have a 3-join, 3-mv-expand limit per request.
  - Microsoft Graph 403 on application permissions  → log and degrade to
    Directory Readers only; identity coverage will be partial.
  - Elicitation prompt from azmcp (sensitive data)   → DO NOT CONFIRM.
    Skip the call; we do not read raw secret material. Use list/describe
    metadata only.

DO NOT:
  - Call any azmcp_*_create / _update / _delete tool — read-only mode is
    enforced server-side, but verify before issuing.
  - Read Key Vault secret values, even if the engagement allows it; pass
    that to the AppTest phase via SSRF probe instead.
  - Trigger VM Run Command, even for reachability tests, unless
    engagement.azure.allow_run_command_test == true.
```

### 8.3 Phase 3 — App Test (Azure addendum)

```
For Azure-hosted targets identified in recon, the SSRF battery includes:

  IMDS endpoints (only if engagement.azure.allow_imds_probe==true):
    GET http://169.254.169.254/metadata/instance?api-version=2021-02-01
        [Header: Metadata: true]
    GET http://169.254.169.254/metadata/identity/oauth2/token
        ?api-version=2018-02-01&resource=<audience>
        [Header: Metadata: true]
    Audiences to enumerate (one at a time, deduplicate findings by token aud):
      management.azure.com, vault.azure.net, storage.azure.com,
      graph.microsoft.com, database.windows.net, cosmos.azure.com.

  App Service / Function App identity endpoint:
    GET ${IDENTITY_ENDPOINT}?resource=<audience>&api-version=2019-08-01
        [Header: X-IDENTITY-HEADER: ${IDENTITY_HEADER}]
    Note: 169.254.169.254:80 is NOT reachable from App Service sandbox —
    use the env-var-based endpoint only.

  WireServer (information disclosure only, no token):
    GET http://168.63.129.16/

  SAS token harvesting:
    Scan all responses for ?sv=…&sig=…&se=… patterns; record permissions
    (sp=…), expiry (se=…), scope (sr=…), signed resource type, and the
    full URI minus the signature.

EVIDENCE HANDLING:
  - Strip the bearer token's signature segment before persistence
    (split JWT on '.', keep only header.payload, drop signature).
  - Record the JWT's xms_mirid claim (full resource path), aud, oid, tid,
    and exp. These become evidence properties on the SSRF_REACHABLE edge.
  - On token-mint success, do NOT use the token to access any downstream
    service. The orchestrator's correlation phase infers what the token
    *would* unlock from the graph.

Failure modes:
  - 169.254.169.254:80 connection refused  → almost certainly App Service
    or Functions sandbox (not a real VM); switch to IDENTITY_ENDPOINT path.
  - Missing Metadata: true header rejection → IMDS hardening is on; mark
    IMDS_EXPOSED=false and move on.
```

### 8.4 Phase 4 — AI Triage

```
You are correlating cloud findings with web findings to produce ranked
compound attack chains. Inputs in your context:
  - The full graph as a compressed adjacency list (nodes aliased; lookup
    table at end of context behind a cache breakpoint).
  - Findings from prowler-mcp for AWS and Azure, with framework tags.
  - SSRF / RCE evidence from the App-Test phase.
  - YAML pattern matches from the rule engine (47 AWS + 32 Azure = 79).

For each candidate chain, output JSON with:
  chain_id, severity (critical|high|medium|low),
  confidence (0.0-1.0),
  provider_lane ('aws'|'azure'|'multi'),
  start_node, end_node, hops[], evidence_ids[],
  attck_techniques[], compliance_violations[],
  narrative (one paragraph, technical, no marketing tone),
  remediation (concrete Azure CLI / Terraform / Bicep snippet OR
              AWS CLI / IAM policy snippet).

PRIORITIZATION:
  - Multi-cloud chains (a node touches both providers — e.g., a GitHub
    Actions OIDC trust that maps to both an AWS role and an Azure UAMI)
    get +0.2 confidence and 'multi' lane.
  - Chains traversing PIM_ELIGIBLE_FOR edges have confidence multiplied
    by azure.pim.activation_cost (default 0.7).
  - Chains where the start node is INTERNET_FACING and the end node is
    a Subscription/MG/KeyVault are flagged 'critical' regardless.

When in doubt about Azure semantics:
  - microsoft-learn-mcp:search('Microsoft.Authorization/roleAssignments/write')
  - microsoft-learn-mcp:fetch(<canonical URL>)
  Never invent action names. If the role definition's actions[] doesn't
  contain a permission you need to invoke for path validity, the path is
  invalid — drop it.

DO NOT request raw secret values for any reason. The graph already knows
which secrets a path *could* reach; we report the reachability, not the
content.
```

### 8.5 Phase 5 — Correlation & Reporting

```
You are assembling the final HTML report. Sections:
  1. Executive summary — 200 words, plain prose, severity counts per
     provider, top 5 chains.
  2. Per-cloud posture (AWS, Azure) — Prowler ThreatScore + framework
     pass/fail tables for CIS, MCSB, NIST 800-53, ISO 27001, SOC 2.
  3. Compound attack chains — narrative + force-directed graph snippet
     per chain, Azure nodes blue, AWS nodes orange, multi-cloud nodes
     gold-bordered.
  4. Identity hygiene — orphan role assignments, PIM eligibility heatmap,
     dormant SPs with active credentials, Conditional Access gaps.
  5. Network exposure — internet-facing inventory diff vs prior run.
  6. Defender vs Prowler drift — controls where the two evaluators
     disagree, with a one-line hypothesis per row.
  7. Appendix — evidence chain-of-custody, MCP tool call log, KQL
     queries used, RBAC roles required of the auditor identity.

Report style: technical, factual, declarative. No marketing words
('robust', 'comprehensive', 'state-of-the-art'). Quantify everything you
can: "147 role assignments at MG scope, 12 of which include
Microsoft.Authorization/* in actions[]". Where evidence is partial,
say so and name the missing data source.
```

---

## 9. Deployment Changes

### 9.1 Container image

The Clementine container image gains:

```dockerfile
# ... existing AWS/Python layers ...

# Azure MCP Server
RUN apt-get install -y nodejs npm \
 && npm install -g @azure/mcp@latest

# Azure CLI for emergency interactive auth and az graph fallback
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Prowler with Azure provider
RUN pip install --no-cache-dir 'prowler[azure]>=5.6'

# Microsoft Graph SDK (used by cloud-audit Azure module)
RUN pip install --no-cache-dir msgraph-sdk azure-identity azure-mgmt-resource \
        azure-mgmt-resourcegraph azure-mgmt-authorization \
        azure-mgmt-keyvault azure-mgmt-storage azure-mgmt-compute \
        azure-mgmt-containerservice azure-mgmt-network \
        azure-mgmt-msi azure-mgmt-web azure-mgmt-monitor
```

### 9.2 AKS deployment manifest excerpt

```yaml
# clementine-orchestrator deployment
spec:
  template:
    metadata:
      labels:
        azure.workload.identity/use: "true"
    spec:
      serviceAccountName: clementine-orchestrator
      containers:
        - name: orchestrator
          image: ghcr.io/internal/clementine:2.0.0
          env:
            - name: AZURE_CLIENT_ID
              value: "<uami-client-id>"     # injected by workload identity
            - name: AZURE_TENANT_ID
              value: "<tenant-id>"
            - name: AZURE_MCP_INCLUDE_PRODUCTION_CREDENTIALS
              value: "true"
            - name: AZURE_FEDERATED_TOKEN_FILE
              value: /var/run/secrets/azure/tokens/azure-identity-token
            # No AZURE_CLIENT_SECRET — workload identity replaces it
          volumeMounts:
            - name: azure-identity-token
              mountPath: /var/run/secrets/azure/tokens
              readOnly: true
```

The corresponding ServiceAccount has `azure.workload.identity/client-id` annotation pointing at the UAMI; the UAMI has a federated credential whose subject is `system:serviceaccount:<ns>:clementine-orchestrator` and audience is `api://AzureADTokenExchange`.

### 9.3 Egress allowlist

The orchestrator's egress NetworkPolicy / AzFW rule must permit:
- `login.microsoftonline.com` (Entra ID auth)
- `management.azure.com` (ARM)
- `graph.microsoft.com` (Microsoft Graph)
- `*.vault.azure.net`, `*.blob.core.windows.net` (only for resources the engagement permits data‑plane reads on)
- `*.kusto.windows.net`, `*.loganalytics.io` (Log Analytics for KQL via Azure Monitor)
- `learn.microsoft.com` (microsoft-learn-mcp)
- `api.prowler.com` (if using Prowler Cloud)

### 9.4 Observability

A new metric set is exposed:
- `clementine_azure_mcp_calls_total{namespace,tool,outcome}`
- `clementine_azure_resource_graph_rows_total{table}`
- `clementine_azure_rbac_assignments_observed{scope_level}`
- `clementine_azure_findings_total{framework,state}`
- `clementine_correlation_chains_total{provider_lane,severity}`
- `clementine_ai_token_cost_usd{phase,model,provider}` — split by provider to see the cost of Azure addition.

### 9.5 Backward compatibility

- All existing AWS YAML patterns, prompts, and graph data continue to work — `provider` defaults to `'aws'` everywhere.
- Existing reports for in‑flight engagements run to completion on the previous schema; only new engagements opt into Azure via `engagement.azure.enabled = true`.
- The `findings`, `graph_nodes`, `graph_edges`, `enrichment_status` migrations are all additive (new nullable columns, new indexes, new tables).

---

## 10. How Azure Findings Integrate With the Existing Correlation Engine

The thesis of this whole document, restated at the end: **the correlation engine is unchanged**. What changes is that:

1. The graph it operates on now contains Azure nodes and edges with the same shape and the same edge‑kind semantics as AWS. `paths_between(SSRF_REACHABLE_node, sensitive_resource)` returns mixed‑provider paths automatically, because every traversal is over edge *kinds* the engine already knows.
2. The pattern engine's `via_edges` constraint is generic over edge kind names. The 32 new Azure patterns are just additional patterns; they share rule‑evaluation code with the 47 AWS patterns.
3. The AI Triage prompt was already provider‑agnostic in spirit — we extend it with one paragraph of Azure‑specific instructions and a microsoft‑learn‑mcp grounding tool. ARN aliasing extends to Azure resource ID aliasing under the same compression budget.
4. The HTML report's force‑directed graph already supports per‑node coloring and per‑edge styling. We add a *provider lane* control and *PIM dotted‑edge* style. No render‑pipeline changes are required to the underlying D3 layout.
5. The compound‑chain example that defines Clementine's identity — *SSRF + IMDSv1 + overprivileged IAM role = account takeover* — has a near‑perfect Azure rhyme: *SSRF + Azure IMDS + overprivileged user‑assigned managed identity = subscription takeover.* The IMDS at `169.254.169.254` issues OAuth bearer tokens to any process that asks; one HTTP request can mint tokens scoped to ARM, Vault, Storage, Graph, SQL, or Cosmos. The blast radius is dictated by the RBAC assignments on the MI and the Defender visibility on the workspace. Clementine 2.0 detects this with the same shape of pattern, the same shape of graph traversal, and the same shape of report, because we have intentionally preserved every interface that mattered in 1.x.

The orchard now has two cultivars on one rootstock. The fruit tastes the same to the engine; the trees just grow a little differently.

---

## Appendix A — Counts and Sizing

- **MCP servers**: 6 → 10 (added: `azure-mcp`, replaced+expanded: `prowler-mcp` covers AWS+Azure; added: `microsoft-learn-mcp`; reused with extension: `cloud-audit`).
- **Node types**: ~25 AWS → +~30 Azure ≈ 55 total.
- **Edge types**: ~12 AWS → +~16 Azure ≈ 28 total.
- **YAML patterns**: 47 AWS → +32 Azure = 79 total.
- **Compliance frameworks supported (Azure)**: CIS Azure 2.0/3.0, MCSB / Azure Security Benchmark, NIST 800‑53 R5, ISO 27001:2013, SOC 2, PCI‑DSS, HIPAA, GDPR, FedRAMP, ENS, MITRE ATT&CK Azure mappings, Prowler ThreatScore Azure.
- **Minimum auditor RBAC**: Reader + Security Reader + Storage Blob Data Reader + Key Vault Reader + Log Analytics Reader (Azure RBAC); Directory.Read.All + RoleManagement.Read.Directory + Application.Read.All + Policy.Read.All (Microsoft Graph application permissions).
- **Token cost delta** (estimated): +35–45% per engagement at Sonnet 4.6 with default ARN/resource‑ID aliasing on; mitigated by namespace whitelisting in §6.1 keeping the Azure tool manifest under ~120 tools.

## Appendix B — Open Questions for the Engineering Review

1. **PIM activation simulation**: should the engine treat `PIM_ELIGIBLE_FOR` as a solid edge (worst case) or a dotted edge (current proposal)? Trade‑off is false‑positive volume vs missed escalation.
2. **Cross‑tenant federation**: do we want Clementine to walk into other tenants when a federated credential trusts an external IdP we *also* have visibility into? The naive answer is no (scope creep, consent issues); the useful answer is "yes, behind a `--multi-tenant` flag."
3. **Defender vs Prowler drift handling**: when the two disagree, whose verdict is canonical? Proposal: report both, do not auto‑resolve, and let the analyst adjudicate.
4. **Resource Graph join limits**: the default 3‑join cap forces query splits. We can request a tenant limit increase from Microsoft Support, or paginate through subscription scopes. The latter is simpler and is what this spec assumes.
5. **App Service identity endpoint sandbox quirks**: on 32‑bit Windows Consumption plan, the local identity sidecar sometimes fails to start, and `DefaultAzureCredential` falls back to IMDS at 169.254.169.254 which is *blocked* from the sandbox — leading to noisy "managed identity unavailable" failures in the wild. The probe should classify this case rather than treating it as IMDS hardening.

---

*End of spec. Reviewers: please open issues per section number rather than amending inline; cf. `CONTRIBUTING.md` §3.4.*