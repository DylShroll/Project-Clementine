"""Node and edge type definitions for the AWS knowledge graph."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

IMDS_NODE_ID = "169.254.169.254"


class AWSNodeType(str, Enum):
    # Principals
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    EKS_SERVICE_ACCOUNT = "eks_service_account"
    # Compute
    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    LAMBDA_LAYER = "lambda_layer"
    EKS_POD = "eks_pod"
    EKS_NODE = "eks_node"
    # Storage / secrets
    S3_BUCKET = "s3_bucket"
    RDS_INSTANCE = "rds_instance"
    SECRETS_MANAGER = "secrets_manager"
    SSM_PARAMETER = "ssm_parameter"
    KMS_KEY = "kms_key"
    # Messaging
    SNS_TOPIC = "sns_topic"
    SQS_QUEUE = "sqs_queue"
    # Networking
    VPC = "vpc"
    SECURITY_GROUP = "security_group"
    VPC_ENDPOINT = "vpc_endpoint"
    VPC_PEERING = "vpc_peering"
    TRANSIT_GATEWAY = "transit_gateway"
    # Edge / API
    API_GATEWAY_ROUTE = "api_gateway_route"
    CLOUDFRONT_DISTRIBUTION = "cloudfront_distribution"
    WAF_ACL = "waf_acl"
    # Bridge / special
    WEB_ENDPOINT = "web_endpoint"
    IMDS = "imds"
    # Wildcard placeholder for `Resource: "*"` in IAM policies
    WILDCARD = "wildcard"


class AWSEdgeType(str, Enum):
    # IAM
    CAN_ASSUME = "CAN_ASSUME"
    HAS_PERMISSION = "HAS_PERMISSION"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"
    # Compute
    ATTACHED_TO = "ATTACHED_TO"
    HOSTS_APP = "HOSTS_APP"
    # Network
    ROUTES_TO = "ROUTES_TO"
    INTERNET_FACING = "INTERNET_FACING"
    PEERED_WITH = "PEERED_WITH"
    # Exploit
    SSRF_REACHABLE = "SSRF_REACHABLE"
    # EKS
    IRSA_BOUND = "IRSA_BOUND"
    OIDC_TRUSTS = "OIDC_TRUSTS"
    # Edge / data plane
    INVOKES = "INVOKES"               # API Gateway → Lambda, EventBridge → target
    ENCRYPTS_WITH = "ENCRYPTS_WITH"   # resource → KMS key
    KEY_POLICY_GRANTS = "KEY_POLICY_GRANTS"  # principal → KMS key (with action)
    SUBSCRIBES_TO = "SUBSCRIBES_TO"   # SQS/Lambda → SNS topic
    USES_LAYER = "USES_LAYER"         # Lambda → layer
    WAF_PROTECTS = "WAF_PROTECTS"     # WAF ACL → distribution/ALB/API


# Edges that an attacker can reasonably traverse during exploitation, used by
# the `via_edges` correlation pattern shortcut and `principals_reaching`.
IAM_TRAVERSAL_EDGES: frozenset[str] = frozenset({
    AWSEdgeType.CAN_ASSUME.value,
    AWSEdgeType.CAN_PASS_ROLE.value,
    AWSEdgeType.HAS_PERMISSION.value,
    AWSEdgeType.IRSA_BOUND.value,
    AWSEdgeType.OIDC_TRUSTS.value,
    AWSEdgeType.KEY_POLICY_GRANTS.value,
})


@dataclass
class GraphNode:
    """A node in the knowledge graph (AWS or Azure)."""
    node_id: str
    node_type: str  # AWSNodeType or AzureNodeType value; str so Azure nodes don't need coercion
    label: str
    properties: dict = field(default_factory=dict)
    is_internet_facing: bool = False

    def merge_properties(self, other: dict) -> None:
        """Merge additional properties, concatenating finding_ids lists."""
        for k, v in other.items():
            if k == "finding_ids" and k in self.properties:
                existing = self.properties["finding_ids"]
                if isinstance(existing, list) and isinstance(v, list):
                    for fid in v:
                        if fid not in existing:
                            existing.append(fid)
            elif k not in self.properties:
                self.properties[k] = v
