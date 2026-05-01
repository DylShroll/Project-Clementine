# Multi-Cloud Chain Discovery — Phase 5 Guidance

## Overview

Phase 5 is the AI discovery pass. When the knowledge graph contains both AWS and Azure nodes, this guidance instructs the discovery model to look for chains that cross cloud boundaries. Multi-cloud chains are the highest-value discovery targets because static YAML patterns cannot enumerate the unlimited combinations of cross-cloud trust relationships.

---

## Multi-Cloud Chain Taxonomy

### GitHub Actions → Azure

A GitHub Actions OIDC federation to an Azure App Registration or UAMI allows any workflow in the trusted repository (or a misconfigured wildcard subject) to obtain an Azure token. If the SP/UAMI has:
- `Owner` or `Contributor` on a subscription → subscription takeover
- `Key Vault Secrets User` on a vault → secret exfiltration
- `Storage Blob Data Contributor` → full storage read/write

Graph shape: `GitHubRepo -[OIDC_TRUSTS]-> AppReg -[HAS_RBAC_ROLE]-> Subscription`

### Azure → AWS via SSRF

An SSRF in an Azure-hosted app that can reach the AWS metadata endpoint `169.254.169.254` (e.g., via an EC2 instance in a peered VPC/VNet, or via an app deployed on both clouds) can exfiltrate AWS instance role credentials.

Graph shape: `AzureApp -[SSRF_REACHABLE]-> IMDS_NODE -[HOSTS_APP]-> EC2Instance -[CAN_ASSUME]-> IAMRole`

### Azure Workload Identity → AWS STS Federation

An AKS service account bound to a UAMI that has an AWS STS federation trust can obtain AWS credentials by exchanging the Azure token via `sts:AssumeRoleWithWebIdentity`. This creates a full cross-cloud IAM path.

Graph shape: `AKSServiceAccount -[WORKLOAD_ID_BOUND]-> UAMI -[OIDC_TRUSTS]-> AWSSTSFederatedRole -[CAN_ASSUME]-> AWSRole`

### Azure Function SSRF → AWS Credential in KV Secret

A Function App SSRF reaches the IDENTITY_ENDPOINT, obtains a KV token, reads KV secrets — one of which contains an AWS access key ID. The Azure MI token → KV → AWS credential chain crosses two cloud boundaries.

Graph shape: `FunctionApp -[SSRF_REACHABLE]-> IDENTITY_ENDPOINT -[CAN_ASSUME_MI]-> UAMI -[HAS_RBAC_ROLE]-> KVAccess -[STORES_SECRET_FOR]-> AWSCredential`

---

## Confidence Scoring for Multi-Cloud Chains

| Evidence completeness | Confidence adjustment |
|----------------------|----------------------|
| All graph edges present, all findings confirmed | Base confidence +0.20 above single-cloud equivalent |
| One speculative hop (e.g., "assume peering exists") | Cap at 0.55 |
| Cross-cloud hop requires attacker-controlled infrastructure | Cap at 0.45 |

Label multi-cloud chains with `provider_lane: multi` in the narrative.

---

## Traversal Edge Sets

The discovery model should include the following edge types when evaluating reachability:

**AWS IAM traversal**: `CAN_ASSUME`, `OIDC_TRUSTS`, `CAN_PASS_ROLE`, `IRSA_BOUND`, `HAS_PERMISSION`

**Azure IAM traversal**: `CAN_ASSUME_MI`, `HAS_RBAC_ROLE`, `HAS_DIRECTORY_ROLE`, `WORKLOAD_ID_BOUND`, `OIDC_TRUSTS`, `PIM_ELIGIBLE_FOR`, `CAN_RESET_CREDENTIAL_FOR`, `CAN_ATTACH_MI`

**Cross-cloud links**: `SSRF_REACHABLE`, `IMDS_EXPOSED`, `INTERNET_FACING`, `INVOKES`

---

## What NOT to Propose

- A chain that requires the attacker to already have Azure credentials unless the chain shows how those credentials are obtained from an earlier step.
- A chain where the only connection between AWS and Azure nodes is "both are in the same assessment" — there must be a graph edge or a shared identity/credential.
- A chain where PIM activation is the only barrier but the model has no evidence the principal can activate (lacks credentials or MFA capability). Cap at 0.45.

---

## Narrative Requirements for Multi-Cloud Chains

Every multi-cloud chain narrative must:
1. Name the starting resource and its cloud provider
2. Explicitly describe the cloud-boundary crossing step and mechanism
3. Name the destination resource and its cloud provider
4. State what data or capability the attacker obtains at the end

Example: "An SSRF on the Azure Function App `fn:a3c` (Azure) reaches the App Service IDENTITY_ENDPOINT and obtains an OAuth2 token for managed identity `uami:7f2` (Azure). That token has `Key Vault Secrets User` on vault `kv:d4b`. One secret in the vault contains an AWS IAM access key for role `arn:aws:iam::123456789:role/DataPipelineRole` (AWS). The attacker can now call `sts:AssumeRole` to pivot into the AWS account and access the S3 bucket `s3://customer-data-prod`."
