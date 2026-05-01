"""Azure node and edge type definitions for the knowledge graph.

Kept in a separate module from model.py so AWS and Azure taxonomies stay
clearly separated. Both use str-Enum so comparisons against raw string
column values from the DB work without explicit coercion.
"""
from __future__ import annotations

from enum import Enum


class AzureNodeType(str, Enum):
    # Scope hierarchy
    TENANT = "az_tenant"
    MANAGEMENT_GROUP = "az_management_group"
    SUBSCRIPTION = "az_subscription"
    RESOURCE_GROUP = "az_resource_group"
    # Identity — Entra ID
    ENTRA_USER = "az_entra_user"
    ENTRA_GROUP = "az_entra_group"
    ENTRA_DIRECTORY_ROLE = "az_entra_directory_role"
    SERVICE_PRINCIPAL = "az_service_principal"
    APP_REGISTRATION = "az_app_registration"
    SYSTEM_ASSIGNED_MI = "az_system_assigned_mi"
    USER_ASSIGNED_MI = "az_user_assigned_mi"
    # RBAC
    ROLE_DEFINITION = "az_role_definition"
    ROLE_ASSIGNMENT = "az_role_assignment"   # modeled as a node (spec §3.3)
    FEDERATED_CREDENTIAL = "az_federated_credential"
    # Compute
    VIRTUAL_MACHINE = "az_vm"
    VMSS = "az_vmss"
    APP_SERVICE = "az_app_service"
    FUNCTION_APP = "az_function_app"
    CONTAINER_APP = "az_container_app"
    CONTAINER_INSTANCE = "az_container_instance"
    AKS_CLUSTER = "az_aks_cluster"
    AKS_NODE_POOL = "az_aks_node_pool"
    AKS_SERVICE_ACCOUNT = "az_aks_service_account"
    # Storage
    STORAGE_ACCOUNT = "az_storage_account"
    BLOB_CONTAINER = "az_blob_container"
    FILE_SHARE = "az_file_share"
    QUEUE = "az_queue"
    TABLE = "az_table"
    # Secrets / Key Vault
    KEY_VAULT = "az_key_vault"
    KV_SECRET = "az_kv_secret"
    KV_KEY = "az_kv_key"
    KV_CERTIFICATE = "az_kv_certificate"
    # Database
    COSMOS_ACCOUNT = "az_cosmos_account"
    SQL_SERVER = "az_sql_server"
    SQL_DATABASE = "az_sql_database"
    MYSQL_SERVER = "az_mysql_server"
    POSTGRESQL_SERVER = "az_postgresql_server"
    # Networking
    VNET = "az_vnet"
    SUBNET = "az_subnet"
    NSG = "az_nsg"
    NSG_RULE = "az_nsg_rule"
    ROUTE_TABLE = "az_route_table"
    PEERING = "az_peering"
    PRIVATE_ENDPOINT = "az_private_endpoint"
    APP_GATEWAY = "az_app_gateway"
    FRONT_DOOR = "az_front_door"
    AZURE_FIREWALL = "az_firewall"
    # Messaging
    SERVICE_BUS_NS = "az_service_bus_ns"
    EVENT_HUBS_NS = "az_event_hubs_ns"
    EVENT_GRID_TOPIC = "az_event_grid_topic"
    # Monitoring / Governance
    LOG_ANALYTICS = "az_log_analytics"
    DIAGNOSTIC_SETTING = "az_diagnostic_setting"
    POLICY_ASSIGNMENT = "az_policy_assignment"
    DEFENDER_PLAN = "az_defender_plan"


class AzureEdgeType(str, Enum):
    # Identity → resource
    CAN_ASSUME_MI = "CAN_ASSUME_MI"              # principal can request MI token (via compute attachment)
    HAS_RBAC_ROLE = "HAS_RBAC_ROLE"             # principal → RoleAssignment → scope
    HAS_DIRECTORY_ROLE = "HAS_DIRECTORY_ROLE"   # principal → Entra directory role
    HAS_API_PERMISSION = "HAS_API_PERMISSION"   # SP → MS Graph app role / delegated permission
    OWNS_APP_REGISTRATION = "OWNS_APP_REGISTRATION"
    CONSENT_GRANT = "CONSENT_GRANT"             # OAuth2PermissionGrant
    CAN_ATTACH_MI = "CAN_ATTACH_MI"             # principal can attach a UAMI to compute (like CAN_PASS_ROLE)
    MI_ATTACHED_TO = "MI_ATTACHED_TO"           # MI → compute resource binding
    WORKLOAD_ID_BOUND = "WORKLOAD_ID_BOUND"     # AKSServiceAccount → UserAssignedMI (IRSA analogue)
    OIDC_TRUSTS = "OIDC_TRUSTS"                 # UAMI/AppReg → external OIDC issuer
    # Network
    ROUTES_TO = "ROUTES_TO"
    INTERNET_FACING = "INTERNET_FACING"
    PEERED_WITH = "PEERED_WITH"
    PRIVATE_LINK_TO = "PRIVATE_LINK_TO"
    # Exploit evidence
    SSRF_REACHABLE = "SSRF_REACHABLE"
    IMDS_EXPOSED = "IMDS_EXPOSED"               # Azure IMDS reachable without Metadata header check
    # App relationships
    INVOKES = "INVOKES"                          # App Service → Function, EventGrid → handler
    ENCRYPTS_WITH = "ENCRYPTS_WITH"             # resource → Key Vault key (CMK)
    STORES_SECRET_FOR = "STORES_SECRET_FOR"     # KV secret/cert referenced by App Service / AKS CSI
    # Governance
    POLICY_APPLIES_TO = "POLICY_APPLIES_TO"     # Azure Policy assignment → scope
    # PIM / privilege
    PIM_ELIGIBLE_FOR = "PIM_ELIGIBLE_FOR"       # principal is eligible (not active) for a role via PIM
    CAN_RESET_CREDENTIAL_FOR = "CAN_RESET_CREDENTIAL_FOR"  # App Admin → SP (SpecterOps escalation path)
    # Generic membership
    MEMBER_OF = "MEMBER_OF"


# Edges an attacker can traverse during exploitation — used by the correlation
# engine's `via_edges` shortcut and AttackSurfaceAnalyzer.principals_reaching().
AZURE_IAM_TRAVERSAL_EDGES: frozenset[str] = frozenset({
    AzureEdgeType.CAN_ASSUME_MI.value,
    AzureEdgeType.HAS_RBAC_ROLE.value,
    AzureEdgeType.HAS_DIRECTORY_ROLE.value,
    AzureEdgeType.WORKLOAD_ID_BOUND.value,
    AzureEdgeType.OIDC_TRUSTS.value,
    AzureEdgeType.PIM_ELIGIBLE_FOR.value,
    AzureEdgeType.CAN_RESET_CREDENTIAL_FOR.value,
    AzureEdgeType.CAN_ATTACH_MI.value,
})

# Azure principal node types — used to filter the graph when looking for
# identities that can reach a sensitive resource.
AZURE_PRINCIPAL_NODE_TYPES: frozenset[str] = frozenset({
    AzureNodeType.ENTRA_USER.value,
    AzureNodeType.ENTRA_GROUP.value,
    AzureNodeType.SERVICE_PRINCIPAL.value,
    AzureNodeType.APP_REGISTRATION.value,
    AzureNodeType.SYSTEM_ASSIGNED_MI.value,
    AzureNodeType.USER_ASSIGNED_MI.value,
    AzureNodeType.AKS_SERVICE_ACCOUNT.value,
})
