# Azure DNS Classification and WAF Detection — Phase 1 Guidance

## Purpose

During Phase 1 (Reconnaissance), the Azure extension checks in-scope domains against a list of Azure service suffixes to classify candidate node types before any authenticated Azure API calls are made. This guidance governs what you SHOULD and SHOULD NOT do in Phase 1.

## Azure Service Suffixes → Node Type Mapping

| Suffix | Azure Service | Node Type |
|--------|--------------|-----------|
| `.azurewebsites.net` | App Service / Functions | `az_app_service` |
| `.azurefd.net` | Front Door | `az_front_door` |
| `.blob.core.windows.net` | Blob Storage | `az_blob_container` |
| `.vault.azure.net` | Key Vault | `az_key_vault` |
| `.database.windows.net` | Azure SQL | `az_sql_server` |
| `.documents.azure.com` | Cosmos DB | `az_cosmos_account` |
| `.servicebus.windows.net` | Service Bus | `az_service_bus_ns` |
| `.azurecontainer.io` | Container Instances | `az_container_instance` |
| `.azurecr.io` | Container Registry | `az_storage_account` |
| `.cloudapp.azure.com` | VM / Public IP | `az_vm` |
| `.trafficmanager.net` | Traffic Manager | `az_front_door` |
| `.azureedge.net` | CDN | `az_front_door` |

## WAF Probe Instructions

Send a single HTTP HEAD request to the primary target URL. Check for:

1. **`X-Azure-Ref` header** → Azure Front Door is in the path. Classify as `az_front_door`.
2. **`Server: Microsoft-Azure-Application-Gateway`** → Application Gateway WAF. Classify as `az_app_gateway`.
3. **`X-Cache` containing "Azure"** → Azure CDN. Classify as `az_front_door`.

**Passive only** — do NOT:
- Make multiple probing requests to enumerate WAF rules.
- Send payloads designed to test WAF bypass techniques.
- Call any Azure MCP server or management API in Phase 1.
- Attempt to enumerate subdomains of Azure-hosted targets.

The WAF probe is a single passive observation to seed the graph topology. All active enumeration happens in Phase 2b (azure_audit).

## Output

For each matched domain or WAF signal, write a `graph_node` row with:
- `provider = 'azure'`
- `node_type` = the matched type from the table above
- `is_candidate = true` in properties (Phase 2b will confirm via KQL)
- `is_internet_facing = true` if the domain resolves publicly
