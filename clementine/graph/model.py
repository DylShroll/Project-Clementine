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
    EKS_POD = "eks_pod"
    EKS_NODE = "eks_node"
    # Storage / secrets
    S3_BUCKET = "s3_bucket"
    RDS_INSTANCE = "rds_instance"
    SECRETS_MANAGER = "secrets_manager"
    SSM_PARAMETER = "ssm_parameter"
    # Networking
    VPC = "vpc"
    SECURITY_GROUP = "security_group"
    VPC_ENDPOINT = "vpc_endpoint"
    # Bridge / special
    WEB_ENDPOINT = "web_endpoint"
    IMDS = "imds"


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
    # Exploit
    SSRF_REACHABLE = "SSRF_REACHABLE"
    # EKS
    IRSA_BOUND = "IRSA_BOUND"
    OIDC_TRUSTS = "OIDC_TRUSTS"


@dataclass
class GraphNode:
    """A node in the AWS knowledge graph."""
    node_id: str
    node_type: AWSNodeType
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
