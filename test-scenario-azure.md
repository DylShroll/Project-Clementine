# Project Clementine — Azure Test Scenario

## DVWA on Azure Container Instance with intentional Azure misconfigurations

**Status:** Reference specification  
**Companion:** For AWS infrastructure testing see [test-scenario-dvwa-aws.md](test-scenario-dvwa-aws.md)  
**Purpose:** Validate that Project Clementine 2.0 "Mandarin" correctly identifies application-layer vulnerabilities, Azure infrastructure misconfigurations, and the compound attack chains that connect them — all in a fully controlled, legal environment.

---

## Overview

This scenario deploys [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) in an Azure Container Instance with a system-assigned managed identity, alongside intentionally misconfigured Azure resources. Running a full assessment against this environment should produce:

- **3 critical attack chains** (SSRF→IMDS→MI→subscription takeover, SSRF→IDENTITY_ENDPOINT→KV self-grant, custom role with roleAssignments/write)
- **2 high attack chains** (anonymous blob access, NSG `*` inbound to RDP, no Defender visibility)
- **30–50 individual findings** across application and infrastructure layers

> **Legal notice.** This environment must be deployed in an Azure subscription you own, against infrastructure you control. Never run Project Clementine against systems you do not have explicit written permission to test.

---

## Intentional misconfigurations seeded

These weaknesses are deliberately created so every major Azure correlation pattern fires. They exist *only* in the test subscription and must never be replicated in production.

| Misconfiguration | Why it is seeded |
| --- | --- |
| Container Instance with system-assigned managed identity | Seeds the SSRF → Azure IMDS → MI token chain |
| MI granted Contributor on subscription | Amplifies the SSRF chain to full subscription takeover |
| Key Vault using access policy model (not RBAC) | Seeds the KV Contributor self-grant chain |
| RG-level Contributor assigned to the MI | Allows self-granting of KV access policy |
| Storage account with `allowBlobPublicAccess: true` + public container | Seeds the anonymous blob public exposure chain |
| NSG with `*` inbound to RDP (TCP 3389) | Seeds the NSG star inbound management ports chain |
| No Defender for Cloud plans enabled | Seeds the defender-plans-disabled and zero-visibility chains |
| No diagnostic settings on Key Vault or storage account | Seeds the diagnostic-settings-missing chain |
| App Registration with overly broad federated credential subject | Seeds the cross-tenant federation open-subject chain |
| DVWA security level set to LOW | Maximises application-layer findings across all WSTG categories |

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Azure subscription (dedicated test subscription) | Use a throwaway subscription, not production |
| Azure CLI installed and authenticated | `az login` with an account that has Owner on the test subscription |
| Project Clementine installed | See [README](README.md) |
| Docker running locally | For AutoPentest AI |
| Node.js ≥ 20 | For azure-mcp via npx |
| `uv` installed | `pip install uv` |
| Prowler with Azure extras | `pip install "prowler[azure]>=5.6"` |

---

## Step 1 — Create the Azure infrastructure

All commands use the Azure CLI. Execute them in order in a single shell session to preserve variable values.

### 1.1 Set your working variables

```bash
export AZ_SUBSCRIPTION_ID="$(az account show --query id --output tsv)"
export AZ_TENANT_ID="$(az account show --query tenantId --output tsv)"
export AZ_LOCATION="eastus"
export AZ_RG="clementine-test-rg"
export AZ_PREFIX="clemtest"   # used to avoid naming collisions

echo "Subscription: ${AZ_SUBSCRIPTION_ID}"
echo "Tenant:       ${AZ_TENANT_ID}"
echo "Location:     ${AZ_LOCATION}"
```

### 1.2 Create the resource group

```bash
az group create \
  --name "${AZ_RG}" \
  --location "${AZ_LOCATION}"
```

> **Azure Portal path:** Resource Groups → `clementine-test-rg`

### 1.3 Create the intentionally overprivileged managed identity

This identity gets Contributor on the entire subscription. In a real account this would be catastrophic — here it seeds the SSRF→IMDS→MI chain at maximum severity.

```bash
# Create the User-Assigned Managed Identity
AZ_UAMI_ID="$(az identity create \
  --name "${AZ_PREFIX}-uami" \
  --resource-group "${AZ_RG}" \
  --query id --output tsv)"

AZ_UAMI_PRINCIPAL_ID="$(az identity show \
  --name "${AZ_PREFIX}-uami" \
  --resource-group "${AZ_RG}" \
  --query principalId --output tsv)"

echo "UAMI ID:           ${AZ_UAMI_ID}"
echo "UAMI Principal ID: ${AZ_UAMI_PRINCIPAL_ID}"

# Wait for the identity to propagate before assigning roles
sleep 15

# Assign Contributor on the subscription — INTENTIONAL MISCONFIGURATION for testing
az role assignment create \
  --assignee "${AZ_UAMI_PRINCIPAL_ID}" \
  --role "Contributor" \
  --scope "/subscriptions/${AZ_SUBSCRIPTION_ID}"
```

> **Azure Portal path:** Microsoft Entra ID → Managed Identities → `clemtest-uami` → Azure role assignments tab

### 1.4 Deploy DVWA in an Azure Container Instance

The container is launched with:

- **System-assigned managed identity** (in addition to the UAMI above) — makes the IMDS endpoint live and injectable via SSRF
- **Public IP** — required to reach the web app and to seed the internet-facing compute finding

```bash
AZ_ACI_IP="$(az container create \
  --resource-group "${AZ_RG}" \
  --name "${AZ_PREFIX}-dvwa" \
  --image "vulnerables/web-dvwa" \
  --assign-identity \
  --ports 80 \
  --protocol TCP \
  --ip-address Public \
  --os-type Linux \
  --cpu 1 \
  --memory 1.5 \
  --environment-variables \
    RECAPTCHA_PRIV_KEY="" \
    RECAPTCHA_PUB_KEY="" \
  --query "ipAddress.ip" \
  --output tsv)"

echo "DVWA public IP: ${AZ_ACI_IP}"
echo "DVWA URL:       http://${AZ_ACI_IP}"
echo "(Allow 1-2 minutes for the container to start)"
```

> **Azure Portal path:** Container Instances → `clemtest-dvwa` → Overview → IP address (Public)

Retrieve the system-assigned managed identity principal ID for later verification:

```bash
AZ_ACI_SAMI_PRINCIPAL_ID="$(az container show \
  --resource-group "${AZ_RG}" \
  --name "${AZ_PREFIX}-dvwa" \
  --query "identity.principalId" \
  --output tsv)"

echo "ACI system-assigned MI principal ID: ${AZ_ACI_SAMI_PRINCIPAL_ID}"
```

### 1.5 Assign Contributor to the container's system-assigned identity

```bash
# INTENTIONAL MISCONFIGURATION — seeds the SSRF→IMDS→MI→subscription takeover chain
az role assignment create \
  --assignee "${AZ_ACI_SAMI_PRINCIPAL_ID}" \
  --role "Contributor" \
  --scope "/subscriptions/${AZ_SUBSCRIPTION_ID}"
```

> **Azure Portal path:** Subscriptions → `<your subscription>` → Access control (IAM) → Role assignments — look for the `clemtest-dvwa` entry under Contributor.

### 1.6 Create the Key Vault with the access policy model (not RBAC)

Using the access policy model instead of RBAC is what makes the self-grant pattern possible. An entity with Contributor on the resource group can modify the access policy without needing a Key Vault data-plane role.

```bash
# Generate a unique name (Key Vault names must be globally unique, 3–24 chars)
AZ_KV_NAME="${AZ_PREFIX}kv$(head -c 4 /dev/urandom | xxd -p)"
echo "Key Vault name: ${AZ_KV_NAME}"

az keyvault create \
  --name "${AZ_KV_NAME}" \
  --resource-group "${AZ_RG}" \
  --location "${AZ_LOCATION}" \
  --enable-rbac-authorization false \
  --sku standard

# Add a test secret so there is something worth stealing
az keyvault secret set \
  --vault-name "${AZ_KV_NAME}" \
  --name "database-connection-string" \
  --value "Server=prod-sql.example.com;Database=CustomerData;User Id=admin;Password=SuperSecret123!"

echo "Key Vault URI: https://${AZ_KV_NAME}.vault.azure.net/"
```

> **Azure Portal path:** Key Vaults → `clemtest-kv…` → Settings → Access policies  
> You should see the vault using the "Vault access policy" permission model (not Azure RBAC).

### 1.7 Grant the container's MI Contributor on the resource group (seeds the KV self-grant chain)

```bash
# RG-level Contributor — in combination with the access policy model vault,
# this allows the MI to set its own access policy and read all secrets.
# INTENTIONAL MISCONFIGURATION for testing.
az role assignment create \
  --assignee "${AZ_ACI_SAMI_PRINCIPAL_ID}" \
  --role "Contributor" \
  --scope "/subscriptions/${AZ_SUBSCRIPTION_ID}/resourceGroups/${AZ_RG}"
```

### 1.8 Create a storage account with public anonymous blob access

```bash
AZ_SA_NAME="${AZ_PREFIX}sa$(head -c 4 /dev/urandom | xxd -p)"
echo "Storage account name: ${AZ_SA_NAME}"

# INTENTIONAL MISCONFIGURATION — allowBlobPublicAccess: true
az storage account create \
  --name "${AZ_SA_NAME}" \
  --resource-group "${AZ_RG}" \
  --location "${AZ_LOCATION}" \
  --sku Standard_LRS \
  --allow-blob-public-access true \
  --min-tls-version TLS1_0

# Get the storage account key so we can create a public container
AZ_SA_KEY="$(az storage account keys list \
  --account-name "${AZ_SA_NAME}" \
  --resource-group "${AZ_RG}" \
  --query "[0].value" --output tsv)"

# Create a public container and upload a sample sensitive file
az storage container create \
  --name "public-data" \
  --account-name "${AZ_SA_NAME}" \
  --account-key "${AZ_SA_KEY}" \
  --public-access blob

echo "test,name,email,ssn" > /tmp/customer-data-sample.csv
echo "1,Alice Smith,alice@example.com,123-45-6789" >> /tmp/customer-data-sample.csv

az storage blob upload \
  --container-name "public-data" \
  --file /tmp/customer-data-sample.csv \
  --name "customer-data-sample.csv" \
  --account-name "${AZ_SA_NAME}" \
  --account-key "${AZ_SA_KEY}"

rm /tmp/customer-data-sample.csv

echo "Public blob URL: https://${AZ_SA_NAME}.blob.core.windows.net/public-data/customer-data-sample.csv"
```

> **Azure Portal path:** Storage accounts → `clemtest-sa…` → Containers → `public-data` → Change access level  
> The container access level should show **Blob (anonymous read access for blobs only)**.

### 1.9 Create an NSG with inbound RDP open to the internet

```bash
az network nsg create \
  --name "${AZ_PREFIX}-nsg" \
  --resource-group "${AZ_RG}" \
  --location "${AZ_LOCATION}"

# INTENTIONAL MISCONFIGURATION — * inbound to RDP (3389) from internet
az network nsg rule create \
  --resource-group "${AZ_RG}" \
  --nsg-name "${AZ_PREFIX}-nsg" \
  --name "Allow-RDP-Internet" \
  --priority 100 \
  --protocol Tcp \
  --direction Inbound \
  --source-address-prefixes '*' \
  --source-port-ranges '*' \
  --destination-address-prefixes '*' \
  --destination-port-ranges 3389 \
  --access Allow

echo "NSG created: ${AZ_PREFIX}-nsg"
```

> **Azure Portal path:** Network security groups → `clemtest-nsg` → Inbound security rules  
> The `Allow-RDP-Internet` rule should appear with source `*` and destination port `3389`.

### 1.10 Create an App Registration with an overly broad federated credential subject

This seeds the `az_cross_tenant_federation_open_subject` pattern. In a real misconfiguration this would allow any GitHub Actions workflow in any repository to obtain an Azure token.

```bash
# Create the App Registration
AZ_APP_ID="$(az ad app create \
  --display-name "${AZ_PREFIX}-app-reg" \
  --query appId --output tsv)"

echo "App Registration app ID: ${AZ_APP_ID}"

# Add a federated credential with an overly broad subject
# "repo:test-org/*:*" matches all refs in all repos under test-org —
# a common misconfiguration when engineers copy-paste from documentation.
# INTENTIONAL MISCONFIGURATION for testing.
az ad app federated-credential create \
  --id "${AZ_APP_ID}" \
  --parameters "{
    \"name\": \"github-actions-broad\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:test-org/*:*\",
    \"audiences\": [\"api://AzureADTokenExchange\"],
    \"description\": \"Intentionally broad subject for Clementine test\"
  }"

echo "Federated credential created on App Registration ${AZ_APP_ID}"
```

> **Azure Portal path:** Microsoft Entra ID → App registrations → `clemtest-app-reg` → Certificates & secrets → Federated credentials  
> The `github-actions-broad` credential should appear with subject `repo:test-org/*:*`.

### 1.11 Verify Defender for Cloud is not enabled

In a fresh subscription, Defender plans are disabled by default. Verify no plans are on:

```bash
az security pricing list \
  --query "[?pricingTier=='Standard'].{Name:name,Tier:pricingTier}" \
  --output table
```

Expected: empty output. If any plans show `Standard`, disable them to seed the `az_defender_plans_disabled` finding:

```bash
# Example — disable Defender for Servers if it was previously enabled
# az security pricing create --name VirtualMachines --tier Free
```

### 1.12 Confirm no diagnostic settings on the Key Vault

New Key Vaults do not have diagnostic settings enabled by default. Verify:

```bash
az monitor diagnostic-settings list \
  --resource "$(az keyvault show --name "${AZ_KV_NAME}" --resource-group "${AZ_RG}" --query id --output tsv)" \
  --output table
```

Expected: empty output (no diagnostic settings). This seeds the `az_diagnostic_settings_missing` chain.

---

## Step 2 — Configure DVWA

Wait 1–2 minutes after container creation for DVWA to finish starting, then perform initial setup.

### 2.1 Initial database setup

```
1. Open a browser and navigate to:   http://<AZ_ACI_IP>/setup.php
2. Click "Create / Reset Database"
3. You will be redirected to the login page
```

### 2.2 Log in and set security level to LOW

```
1. Navigate to:  http://<AZ_ACI_IP>/login.php
2. Username:     admin
3. Password:     password
4. Navigate to:  DVWA Security (left sidebar)
5. Set Security Level to:  low
6. Click "Submit"
```

> Setting security level to **low** disables all input validation in DVWA, maximising the number of exploitable vulnerabilities AutoPentest AI will find, including the SSRF module which is the entry point for the Azure IMDS chain.

---

## Step 3 — Locate configuration values in the Azure Portal

This section maps every value required in `clementine.yaml` to its exact location in the Azure Portal.

### 3.1 Subscription ID

> Portal: Click the search bar at the top → type "Subscriptions" → Select your subscription → **Overview** → **Subscription ID** (GUID format)  
> CLI: `az account show --query id --output tsv`

### 3.2 Tenant ID

> Portal: Microsoft Entra ID → **Overview** → **Tenant ID**  
> CLI: `az account show --query tenantId --output tsv`

### 3.3 DVWA container public IP (target URL)

> Portal: Container Instances → `clemtest-dvwa` → **Overview** → **IP address (Public)**  
> CLI: `az container show --resource-group clementine-test-rg --name clemtest-dvwa --query "ipAddress.ip" --output tsv`  
> This becomes `target.url: "http://<AZ_ACI_IP>"` in `clementine.yaml`.

### 3.4 Service principal credentials (azure-mcp authentication)

Create a read-only service principal for Clementine to authenticate with azure-mcp and prowler-mcp. This is separate from the overprivileged UAMI — audit credentials should be read-only.

```bash
# Create a read-only service principal for the audit
az ad sp create-for-rbac \
  --name "clementine-audit-sp" \
  --role Reader \
  --scopes "/subscriptions/${AZ_SUBSCRIPTION_ID}" \
  --query "{clientId:appId, clientSecret:password, tenantId:tenant}" \
  --output json
```

Note the three values — they go into environment variables `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID`.

> **Azure Portal path:** Microsoft Entra ID → App registrations → `clementine-audit-sp` → Overview → **Application (client) ID**

### 3.5 Key Vault name (for verifying the self-grant chain)

> Portal: Key Vaults → find the vault starting with `clemtest-kv` → **Overview** → **Vault name**  
> CLI: `echo "${AZ_KV_NAME}"` (if the variable is still set)  
> Not set directly in `clementine.yaml` — azure-mcp discovers it during the scan.

### 3.6 Managed identity principal ID (for verifying RBAC chain)

> Portal: Container Instances → `clemtest-dvwa` → **Identity** → **System assigned** → **Object (principal) ID**  
> This is the identity that holds Contributor on the subscription. Clementine discovers this automatically from RBAC enumeration.

---

## Step 4 — Configure Project Clementine

Create `clementine.yaml` by substituting the values collected above.

### 4.1 Set environment variables

```bash
export APP_USERNAME="admin"
export APP_PASSWORD="password"
export AZURE_TENANT_ID="${AZ_TENANT_ID}"       # set in Step 1.1
export AZURE_CLIENT_ID="<appId from Step 3.4>"
export AZURE_CLIENT_SECRET="<password from Step 3.4>"
export AZURE_SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID}"
```

### 4.2 Write clementine.yaml

Replace `<AZ_ACI_IP>` with the container public IP from Step 3.3:

```yaml
# clementine.yaml — Azure DVWA test scenario

target:
  url: "http://<AZ_ACI_IP>"
  scope:
    include_domains:
      - "<AZ_ACI_IP>"
    exclude_paths:
      - "/logout.php"
    rate_limit_rps: 5

auth:
  method: "credentials"
  username: "${APP_USERNAME}"
  password: "${APP_PASSWORD}"
  login_url: "http://<AZ_ACI_IP>/login.php"

aws:
  profile: "default"     # still required — AI calls run via Bedrock
  regions:
    - "us-east-1"
  account_id: ""         # leave blank for Azure-only assessment

azure:
  enabled: true
  tenants:
    - tenant_id: "${AZURE_TENANT_ID}"
      subscription_ids:
        - "${AZURE_SUBSCRIPTION_ID}"
  compliance_frameworks:
    - "cis_3.0_azure"
    - "mcsb_azure"
    - "prowler_threatscore_azure"
  guardrails:
    max_resources_per_type: 500
    allow_imds_probe: true             # approved for this test engagement
    allow_anonymous_blob_access_test: true
    allow_kv_secret_metadata_read: true
    allow_sas_token_extraction: true
    allow_run_command_test: false      # never enable

reporting:
  formats:
    - "html"
    - "json"
    - "sarif"
    - "markdown"
  output_dir: "./reports/azure-test"
  push_to_security_hub: false

orchestrator:
  max_parallel_agents: 2
  finding_db: "sqlite:///azure-test.db"
  log_level: "INFO"
  pause_between_phases: false

ai:
  enabled: true
  aws_region: "us-east-1"
  primary_model: "us.anthropic.claude-sonnet-4-6-20251101"
  critical_model: "us.anthropic.claude-opus-4-7-20251101"
  effort: "high"
  max_parallel_requests: 4
  max_retries: 3

mcp_servers:
  autopentest:
    command: "uv"
    args: ["--directory", "${AUTOPENTEST_DIR}/server", "run", "server.py"]
    env: {}

  cloud_audit:
    command: "uvx"
    args: ["awslabs.well-architected-security-mcp-server@latest"]
    env:
      AWS_PROFILE: "default"
      AWS_REGION: "us-east-1"
      FASTMCP_LOG_LEVEL: "ERROR"

  azure_mcp:
    command: "npx"
    args:
      - "-y"
      - "@azure/mcp@latest"
      - "server"
      - "start"
      - "--read-only"
    env:
      AZURE_TENANT_ID: "${AZURE_TENANT_ID}"
      AZURE_CLIENT_ID: "${AZURE_CLIENT_ID}"
      AZURE_CLIENT_SECRET: "${AZURE_CLIENT_SECRET}"

  prowler_mcp:
    command: "python"
    args: ["-m", "prowler.mcp_server"]
    env:
      AZURE_TENANT_ID: "${AZURE_TENANT_ID}"
      AZURE_CLIENT_ID: "${AZURE_CLIENT_ID}"
      AZURE_CLIENT_SECRET: "${AZURE_CLIENT_SECRET}"

  microsoft_learn:
    command: "python"
    args: ["-m", "clementine.tools.microsoft_learn_mcp"]
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
    args: ["-y", "@playwright/mcp@latest"]
    env: {}
```

---

## Step 5 — Run the assessment

### 5.1 Verify connectivity before starting

```bash
# Confirm DVWA is reachable
curl -s -o /dev/null -w "%{http_code}" "http://${AZ_ACI_IP}/login.php"
# Expected: 200

# Confirm Azure credentials are valid
az account show --query "{subscription:name,tenant:tenantId}"

# Confirm read-only SP can list resources
az resource list \
  --subscription "${AZ_SUBSCRIPTION_ID}" \
  --resource-group "${AZ_RG}" \
  --query "[].{name:name,type:type}" \
  --output table
```

### 5.2 Ensure AutoPentest AI container is running

```bash
docker ps | grep autopentest-tools
# If not running:
docker run -d --name autopentest-tools dylshroll/autopentest-tools:latest tail -f /dev/null
```

### 5.3 Launch the assessment

```bash
clementine run --config clementine.yaml
```

Expected runtime: **60–120 minutes**. Phase 2b (Azure audit) adds approximately 20–30 minutes on top of the standard AWS-only runtime.

### 5.4 Monitor progress

In a second terminal, watch for phase transitions:

```
10:01:02 [INFO] orchestrator: === Starting phase: RECON_RUNNING ===
10:03:45 [INFO] orchestrator: === Phase complete: RECON_COMPLETE ===
10:03:45 [INFO] orchestrator: === Starting phase: AWS_AUDIT_RUNNING ===
10:08:12 [INFO] orchestrator: === Phase complete: AWS_AUDIT_COMPLETE ===
10:08:12 [INFO] orchestrator: === Starting phase: AZURE_AUDIT_RUNNING ===
10:10:01 [INFO] azure_audit: [step 1/8] Tenant/subscription enumeration
10:11:33 [INFO] azure_audit: [step 2/8] Identity enumeration (users, SPs, MIs)
10:14:07 [INFO] azure_audit: [step 3/8] KQL resource inventory
10:18:42 [INFO] azure_audit: [step 4/8] RBAC role assignment enumeration
10:22:15 [INFO] azure_audit: [step 5/8] Federated credential enumeration
10:23:01 [INFO] azure_audit: [step 6/8] Directory role enumeration
10:24:18 [INFO] azure_audit: [step 7/8] Prowler compliance scan (this takes a while)
10:37:09 [INFO] azure_audit: [step 8/8] Defender for Cloud cross-check
10:38:45 [INFO] orchestrator: === Phase complete: AZURE_AUDIT_COMPLETE ===
10:38:45 [INFO] orchestrator: === Starting phase: APP_TEST_RUNNING ===
...
```

If the run is interrupted, re-run the same command — it resumes from the last completed phase.

---

## Step 6 — Expected findings

### 6.1 Application-layer findings (Phase 3 — AutoPentest AI / DVWA)

DVWA in low-security mode exposes the same WSTG categories as the AWS test scenario. The SSRF module is the critical entry point for the Azure chain:

| WSTG Code | Vulnerability | DVWA Module | Expected Severity |
| --- | --- | --- | --- |
| WSTG-INPV-09 | SSRF | SSRF | HIGH |
| WSTG-INPV-05 | SQL Injection | SQL Injection | CRITICAL |
| WSTG-INPV-01 | Reflected XSS | XSS (Reflected) | HIGH |
| WSTG-INPV-02 | Stored XSS | XSS (Stored) | HIGH |
| WSTG-INPV-11 | Command Injection | Command Injection | CRITICAL |
| WSTG-INPV-12 | File Inclusion (LFI/RFI) | File Inclusion | HIGH |
| WSTG-ATHN-02 | Default credentials (`admin`/`password`) | Login page | HIGH |
| WSTG-SESS-02 | Missing HttpOnly / Secure cookie flags | Session cookie | MEDIUM |
| WSTG-CONF-05 | File upload of dangerous type | File Upload | HIGH |
| WSTG-CLNT-01 | DOM-based XSS (Playwright validated) | XSS (DOM) | HIGH |

### 6.2 Azure probe findings (Phase 3 — Azure-specific probes)

With `allow_imds_probe: true`, the Azure IMDS and App Service identity probes run alongside the WSTG test suite. Because the container instance has a system-assigned MI, the IMDS endpoint (`http://169.254.169.254/metadata/identity/oauth2/token`) is reachable from within the container — and from any SSRF originating inside the application context.

| Category | Finding | Expected Severity |
| --- | --- | --- |
| `azure:imds_exposed` | Azure IMDS reachable; MI token obtained for `management.azure.com` | CRITICAL |
| `azure:imds_exposed` | Azure IMDS reachable; MI token obtained for `vault.azure.net` | CRITICAL |
| `SAS_TOKEN` | Long-lived SAS token pattern detected in HTTP evidence (if generated in Step 1.8) | HIGH |

> Note: The IMDS probe extracts only the `header.payload` portions of the JWT (signature stripped). The token is never used to call any downstream Azure service — reachability is reported only.

### 6.3 Azure infrastructure findings (Phase 2b — azure-mcp + prowler-mcp)

| Check ID | Finding | Tool | Expected Severity |
| --- | --- | --- | --- |
| `azure:mi_contributor_subscription` | System-assigned MI on ACI holds Contributor on subscription | azure-mcp / RBAC enum | CRITICAL |
| `azure:kv_access_policy_model` | Key Vault using access policy permission model (not RBAC) | azure-mcp | HIGH |
| `azure:rg_contributor_can_modify_kv_access_policy` | Contributor on RG can self-grant KV access policy | azure-mcp | HIGH |
| `azure:storage_blob_public_access` | Storage account `allowBlobPublicAccess: true`; container `public-data` is public | azure-mcp | HIGH |
| `azure:nsg_star_inbound_rdp` | NSG rule `Allow-RDP-Internet` permits `*` inbound to TCP 3389 | azure-mcp | HIGH |
| `azure:defender_plans_disabled` | No Defender for Cloud plans enabled on subscription | prowler-mcp | HIGH |
| `azure:diagnostic_settings_missing` | No diagnostic settings on Key Vault `${AZ_KV_NAME}` | prowler-mcp | MEDIUM |
| `azure:diagnostic_settings_missing` | No diagnostic settings on storage account `${AZ_SA_NAME}` | prowler-mcp | MEDIUM |
| `azure:federated_credential_broad_subject` | App Registration federated credential subject `repo:test-org/*:*` matches all repos/refs | azure-mcp | HIGH |
| `cis_3.0_azure:*` | Multiple CIS 3.0 control failures (logging, network, identity) | prowler-mcp | MEDIUM–HIGH |

### 6.4 Expected compound attack chains (Phase 4 — Correlation engine)

All five critical/high patterns should fire:

#### Chain 1 — SSRF to Azure subscription takeover `[CRITICAL]`

```
WSTG-INPV-09: SSRF on DVWA
  └── Azure IMDS reachable (169.254.169.254)
        └── System-assigned MI token obtained for management.azure.com
              └── MI holds Contributor on subscription
                    └── IMPACT: Full subscription takeover —
                                create/delete resources, access all storage accounts,
                                modify firewall rules, read all secrets
```

**Pattern fired:** `az_ssrf_imds_mi_resource_access.yaml`

#### Chain 2 — SSRF to Key Vault secret exfiltration `[CRITICAL]`

```
WSTG-INPV-09: SSRF on DVWA
  └── Azure IMDS reachable (169.254.169.254)
        └── MI token obtained for vault.azure.net
              └── MI has Contributor on RG containing the Key Vault
                    └── Key Vault uses access policy model (not RBAC)
                          └── MI can set its own access policy → read all secrets
                                └── IMPACT: database-connection-string secret exfiltrated
```

**Pattern fired:** `az_kv_contributor_access_policy_self_grant.yaml`

#### Chain 3 — Anonymous blob public access to data exposure `[HIGH]`

```
Storage account allowBlobPublicAccess: true
  └── Container "public-data" has anonymous read access
        └── File customer-data-sample.csv contains PII
              └── No diagnostic setting → exfiltration undetected
                    └── IMPACT: PII accessible to the internet without authentication
```

**Pattern fired:** `az_storage_anonymous_blob_public_exposure.yaml`

#### Chain 4 — NSG inbound RDP with zero detection visibility `[HIGH]`

```
NSG rule Allow-RDP-Internet: * → TCP 3389
  └── No Defender for Cloud (no brute-force detection)
        └── No NSG flow logs / diagnostic settings
              └── IMPACT: RDP brute-force attempts are internet-reachable and fully invisible
```

**Patterns fired:** `az_nsg_star_inbound_management_ports.yaml`, `az_defender_plans_disabled.yaml`

#### Chain 5 — Overly broad GitHub Actions federation `[HIGH]`

```
App Registration federated credential
  └── Subject: repo:test-org/*:*
        └── Any GitHub Actions workflow in any test-org repository
              └── Can obtain an Azure AD token for this App Registration
                    └── (If the App Reg had RBAC — escalation to Azure resources)
                          └── IMPACT: Supply chain pivot — all test-org repos
                                      can act as this Azure identity
```

**Pattern fired:** `az_cross_tenant_federation_open_subject.yaml`

### 6.5 Validation checklist

After the assessment, open `reports/azure-test/report.html` and verify:

- [ ] Phase `AZURE_AUDIT_COMPLETE` appears in the log (and in the DB `assessment_state` table)
- [ ] **5 attack chains** appear in the Attack Chains section
- [ ] **At least 2 CRITICAL attack chains** are present (SSRF→IMDS→MI and SSRF→KV self-grant)
- [ ] **Provider chip** shows `AZURE` (blue) on Azure findings and `AWS` (orange) on any AWS findings
- [ ] **Per-cloud posture cards** show Azure severity distribution in the report overview
- [ ] **Identity hygiene table** lists the system-assigned MI with its Contributor assignment
- [ ] **Graph toolbar** — lane toggle filters the attack graph to Azure-only nodes correctly
- [ ] **Multi-cloud chains section** is absent (this is an Azure-only engagement — expected)
- [ ] **Compliance section** shows CIS 3.0 Azure failures for Defender and diagnostic settings
- [ ] **SARIF file** is valid (open in VS Code with SARIF Viewer extension)
- [ ] **Remediation playbook** contains Azure CLI commands with correct syntax

---

## Step 7 — Tear down

**Delete all resources after testing** — especially the managed identity with Contributor access.

```bash
# Remove Contributor role assignments before deleting the identity
# (Azure will block deletion of identities that still have active role assignments)

# Remove subscription-level Contributor from the system-assigned MI
# Note: System-assigned MIs are tied to the container — deleting the container removes it.
# But remove the role assignment first to be explicit.
az role assignment delete \
  --assignee "${AZ_ACI_SAMI_PRINCIPAL_ID}" \
  --role "Contributor" \
  --scope "/subscriptions/${AZ_SUBSCRIPTION_ID}"

# Remove subscription-level Contributor from the UAMI
az role assignment delete \
  --assignee "${AZ_UAMI_PRINCIPAL_ID}" \
  --role "Contributor" \
  --scope "/subscriptions/${AZ_SUBSCRIPTION_ID}"

# Delete the audit service principal
AZ_AUDIT_SP_ID="$(az ad sp list \
  --display-name "clementine-audit-sp" \
  --query "[0].id" --output tsv)"
az ad sp delete --id "${AZ_AUDIT_SP_ID}"

# Delete the App Registration (also removes its federated credential)
az ad app delete --id "${AZ_APP_ID}"

# Delete the entire resource group — removes all resources in one command:
# ACI (+ system-assigned MI), UAMI, Key Vault, Storage Account, NSG
az group delete \
  --name "${AZ_RG}" \
  --yes \
  --no-wait

echo "Resource group deletion queued. Monitor in the portal."
echo "Tear-down complete."
```

> `--no-wait` returns immediately. Monitor deletion progress in the portal under **Resource Groups → clementine-test-rg → Deployments** or via:
>
> ```bash
> az group show --name "${AZ_RG}" --query "properties.provisioningState" --output tsv
> # Returns "Deleting" while in progress, then an error when the group is gone
> ```

Verify in the Azure Portal that no resources remain:

- **Resource Groups** — `clementine-test-rg` should not exist
- **Microsoft Entra ID → Managed Identities** — `clemtest-uami` should not exist
- **Microsoft Entra ID → App Registrations** — `clemtest-app-reg` and `clementine-audit-sp` should not exist
- **Subscriptions → Access control (IAM) → Role assignments** — no `clemtest-*` entries under Contributor

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `curl: (7) Failed to connect to <IP>` | Container still starting | Wait 2 min; check `az container show ... --query "containers[0].instanceView.currentState"` |
| DVWA shows blank/error page | Container unhealthy restart loop | `az container restart --resource-group clementine-test-rg --name clemtest-dvwa` |
| `ScopeError` in Clementine logs | IP not in `include_domains` | Verify the IP in `clementine.yaml` matches exactly (no `http://` prefix in `include_domains`) |
| Phase 2b has zero Azure findings | SP lacks Reader on subscription | `az role assignment list --assignee <CLIENT_ID> --scope /subscriptions/<SUB>` |
| IMDS probe returns 0 findings | `allow_imds_probe` is false in config | Set `azure.guardrails.allow_imds_probe: true` |
| No SSRF chain fired | DVWA SSRF module not exploited | Confirm security level is `low`; confirm SSRF module is in scope |
| azure-mcp reports `[UNAVAILABLE]` | Node.js < 20 or npx not in PATH | `node --version` (must be ≥ 20); `npm install -g @azure/mcp@latest` |
| prowler-mcp shows auth error | Wrong `AZURE_CLIENT_SECRET` | `az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID` |
| Assessment resumes then stalls | Stale DB from a previous run | `rm azure-test.db` and re-run |
| Role assignment delete fails | Role assignment doesn't exist | Check with `az role assignment list --assignee <principal-id>` before deleting |

---

## Cost estimate

| Resource | Type | Estimated cost |
| --- | --- | --- |
| Azure Container Instance | 1 vCPU / 1.5 GB, ~2 hours assessment | ~$0.06 |
| Storage account | Standard LRS, < 1 MB data, < 1 hour | ~$0.00 |
| Key Vault | Standard, < 100 operations | ~$0.00 |
| NSG | Free | $0.00 |
| Managed Identity | Free | $0.00 |
| App Registration | Free | $0.00 |
| **Total** | | **< $0.10** |

All resources should be deleted immediately after the assessment completes.
