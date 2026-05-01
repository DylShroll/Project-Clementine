# Azure Triage Guidance — Phase 4

## Overview

This section supplements the standard triage system prompt when the batch contains Azure findings (provider='azure'). Azure-specific false-positive patterns and confidence guidance follow.

---

## Azure Resource ID Aliasing

Azure resource IDs are compressed to short aliases (e.g., `kv:dxz`, `vm:ab7`) in the prompt to reduce token usage. An alias legend is appended at the end of the findings block. When writing your rationale, use the alias form for brevity — do NOT expand aliases back to full resource IDs.

---

## Azure-Specific False-Positive Patterns

### Compliance Checks

**Azure Policy "Deny" effects are NOT vulnerabilities.** A Policy assignment that blocks non-compliant deployments is a control, not a finding. If the evidence shows a policy effect of `"Deny"`, mark as `is_false_positive=true` with rationale "Azure Policy deny effect is a preventive control."

**Resource types unused in this subscription**: CIS controls for SQL, Cosmos DB, or AKS fire on subscriptions where those resources don't exist. If the evidence shows no resources of the checked type, mark as `is_false_positive=true`.

**Diagnostic settings on resource types without sensitive data**: a missing diagnostic setting on a test/dev resource group with no production data is LOW risk, not MEDIUM.

### RBAC and Identity

**Inherited role assignments**: a role assignment marked `inherited=true` is expected in most environments — it does not by itself indicate a misconfiguration. The risk comes from the role type and scope. Focus on the role name (Owner/Contributor) and scope (subscription vs. resource-group) rather than the inheritance flag.

**PIM-eligible assignments**: these are NOT active role assignments. An `PIM_ELIGIBLE_FOR` edge means the principal must activate the role through PIM (with approval, justification, and optionally MFA). Triage these at one confidence tier lower than equivalent permanent assignments.

### Network

**Storage account "allow trusted Microsoft services"**: this flag permits certain Azure platform services (Backup, Site Recovery, Monitor) to bypass network ACLs. It does NOT expose the storage account to the internet. Mark findings about this flag as `is_false_positive=true` if the evidence confirms it's the only ACL bypass.

**Private endpoint + public access "Enabled"**: if a resource has a private endpoint AND `publicNetworkAccess=Enabled`, check whether the resource also has firewall rules restricting public access to specific IPs. If firewall rules are restrictive (not 0.0.0.0/0), reduce confidence accordingly.

---

## Confidence Calibration for Azure Findings

| Finding Type | Starting Confidence |
|-------------|-------------------|
| IMDS token returned (200 response) | 0.95 — almost certainly real |
| Wildcard federated credential subject | 0.90 — real risk, easily exploitable |
| KV access policy model + Contributor on RG | 0.85 — real escalation path |
| NSG `*` inbound to SSH/RDP | 0.80 if VM has public IP; 0.40 if no public IP |
| Storage anonymous blob access | 0.85 if container confirmed public; 0.40 if only account-level flag |
| PIM-eligible Global Admin without MFA | 0.70 — real but requires attacker to hold credentials |
| Defender/Prowler compliance FAILED | 0.60 unless control is unambiguous (e.g. MFA disabled) |
| Inherited Owner on subscription (PIM) | 0.45 — PIM is a meaningful barrier |
| Missing diagnostic setting | 0.50 — detection gap, not direct compromise |

---

## Multi-Cloud Chain Signals

If a finding references both an Azure resource ID and an AWS ARN or GitHub Actions workflow, flag this in your rationale — it may be a multi-cloud chain component. Do not increase confidence solely because the chain spans clouds, but do note the cross-cloud dependency explicitly.
