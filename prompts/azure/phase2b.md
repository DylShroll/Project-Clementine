# Azure Audit — Phase 2b Enumeration Sequence

## Overview

Phase 2b performs authenticated Azure enumeration using azure-mcp, prowler-mcp, and cloud-audit Azure module. Execute the 8 steps below in order. Steps are independently failure-tolerant: log failures to `enrichment_status` and continue to the next step.

---

## Step 1 — Tenancy Enumeration

Call `azmcp_subscription_list` to list all accessible subscriptions.
For each subscription, call `cloud-audit:management_group_tree` to build the scope hierarchy.

Build the node chain: `Tenant → ManagementGroup → Subscription → ResourceGroup`
- All nodes: `provider = 'azure'`
- Subscription node includes `subscriptionId`, `displayName`, `state`

**Failure handling**: 403 on any subscription → log to `enrichment_status` as `status='blocked', reason='rbac_insufficient'`. Continue with remaining subscriptions.

---

## Step 2 — Identity Enumeration (Entra ID)

Call `cloud-audit` Azure module to list:
- Entra users → `AzureNodeType.ENTRA_USER`
- Security groups → `AzureNodeType.ENTRA_GROUP`
- Service principals → `AzureNodeType.SERVICE_PRINCIPAL`
- App registrations → `AzureNodeType.APP_REGISTRATION`
- User-assigned managed identities → `AzureNodeType.USER_ASSIGNED_MI`

Build edges:
- `OWNS_APP_REGISTRATION`: SP → AppRegistration
- `MEMBER_OF`: User/SP → Group

---

## Step 3 — Resource Inventory via KQL

Load all `.kql` files from `cfg.azure.kql_queries_dir`.
Execute `cloud-audit:resource_graph_query(kql, scope)` for each file concurrently (semaphore: 4 parallel).

**KQL join limit error** → split query by subscription and retry individually.

Normalize each result row using `_normalize_azure_resource(row)` before upserting into `graph_nodes`.

---

## Step 4 — RBAC Role Assignment Enumeration

Call `azure_mcp:azmcp_role_assignment_list` per subscription.

For each assignment:
1. Materialize a `RoleAssignment` node with `scope`, `scope_level`, `inherited`, `pim_eligible`
2. Add `Principal -[HAS_RBAC_ROLE]-> RoleAssignment -[HAS_RBAC_ROLE]-> scope_node`
3. If `expand_inherited_assignments=true`: iterate child scopes, emit edges with `inherited=True` (cap at `max_resources_per_type`)
4. Persist to `azure_role_assignments` table
5. PIM-eligible: add `PIM_ELIGIBLE_FOR` edge with `pim_discount=0.7`

---

## Step 5 — Federation Enumeration

Call `cloud-audit:list_federated_identity_credentials`.

For each credential:
- Insert `FederatedCredential` node
- Add `OIDC_TRUSTS` edge: issuer_node → AppRegistration
- Cross-match `subject` against AKS cluster OIDC issuer URLs → emit `WORKLOAD_ID_BOUND` edge
- **Subject = `"*"` → generate HIGH finding** (`azure:federated_credential_wildcard_subject`)

---

## Step 6 — Entra Directory Roles + PIM

List directory role assignments via `cloud-audit` Azure module.

Add `HAS_DIRECTORY_ROLE` edges from identity nodes to role nodes.

Flag without PIM protection as findings:
- Global Admin on SP without PIM → **CRITICAL**
- Privileged Role Admin on SP without PIM → **CRITICAL**
- Application Admin on SP without PIM → **HIGH**

Store role names in the identity node's `properties.directory_roles` as a JSON array for Phase 3 graph enrichment.

---

## Step 7 — Compliance Scan (prowler-mcp)

Call `prowler-mcp:scan_azure(subscriptions=[...], compliance=[...])`.

Stream findings into `azure_compliance_findings` table with `source='prowler'`, `provider='azure'`.

---

## Step 8 — Defender for Cloud Cross-Check

Execute the `defender_compliance_state.kql` query against `securityresources`.

Cross-reference with Prowler results by `control_id` and `framework`.

**Drift detection**: same control, opposite verdict → emit meta-finding with `source='defender-prowler-drift'`, `category='azure:compliance_drift_detected'`.

---

## Error Handling Reference

| Error | Action |
|-------|--------|
| 403 Forbidden | Log `enrichment_status` as `blocked`; skip this resource/subscription |
| 429 Rate Limit | Exponential backoff: 1s, 2s, 4s, 8s; skip after 4 attempts |
| KQL join limit | Split by subscription; retry each individually |
| azure-mcp elicitation prompt | **DO NOT confirm** — skip call, log as `status='skipped', reason='elicitation_refused'` |
| Network timeout | Log warning; mark step as `partial`; continue to next step |
