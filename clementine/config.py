"""
Configuration loading and validation for Project Clementine.

All credentials are passed via environment-variable placeholders (${VAR}) in
the YAML file and are resolved at runtime — never stored in plaintext config.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Annotated, Union


# ---------------------------------------------------------------------------
# Regex to detect ${ENV_VAR} placeholders in string values
# ---------------------------------------------------------------------------
_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _resolve_env(value: str) -> str:
    """Replace every ${VAR} token with the corresponding environment variable.

    Raises EnvironmentError if a referenced variable is not set, so bad configs
    fail loudly at startup rather than silently using empty strings.
    """
    def _replace(match: re.Match) -> str:
        var = match.group(1)
        resolved = os.environ.get(var)
        if resolved is None:
            raise EnvironmentError(
                f"Config references undefined environment variable: ${{{var}}}"
            )
        return resolved

    return _ENV_PLACEHOLDER.sub(_replace, value)


def _resolve_dict(data: dict | list | str | None) -> dict | list | str | None:
    """Recursively resolve ${ENV_VAR} tokens in a nested dict/list."""
    if isinstance(data, str):
        return _resolve_env(data)
    if isinstance(data, dict):
        return {k: _resolve_dict(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_resolve_dict(item) for item in data]
    return data


# ---------------------------------------------------------------------------
# Target configuration
# ---------------------------------------------------------------------------

class ScopeConfig(BaseModel):
    """Defines what is in-scope for the assessment.

    The orchestrator enforces these boundaries before dispatching any MCP
    tool call — nothing outside the allowed domains/paths is ever tested.
    """
    include_domains: list[str]
    exclude_paths: Optional[list[str]] = []

    @field_validator("exclude_paths", mode="before")
    @classmethod
    def _coerce_none_to_empty(cls, v: object) -> list[str]:
        return v if v is not None else []
    # Maximum requests per second the orchestrator will issue across all tools
    rate_limit_rps: int = 10


class TargetConfig(BaseModel):
    url: str
    scope: ScopeConfig


# ---------------------------------------------------------------------------
# Authentication configuration
# ---------------------------------------------------------------------------

class AuthConfig(BaseModel):
    """Credentials for the target application.

    Credentials are always resolved from environment variables at load time;
    they are never written back to disk.
    """
    method: Literal["credentials", "token", "cookie", "none"] = "none"
    # Credential-based auth
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None
    # Token-based auth
    bearer_token: Optional[str] = None
    # Cookie-based auth (raw Cookie header value)
    cookie: Optional[str] = None


# ---------------------------------------------------------------------------
# AWS configuration
# ---------------------------------------------------------------------------

class AWSConfig(BaseModel):
    """AWS account details for the infrastructure audit phases."""
    profile: str = "default"
    regions: list[str] = ["us-east-1"]
    account_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Azure configuration
# ---------------------------------------------------------------------------

class AzureTenantConfig(BaseModel):
    """One Entra tenant to audit."""
    tenant_id: str
    subscription_ids: list[str] = []         # empty = all visible subscriptions
    management_group_ids: list[str] = []     # scan everything beneath, recursively
    regions: list[str] = []                  # empty = all regions


class AzureEngagementGuardrails(BaseModel):
    """Per-engagement safety limits for Azure audit actions."""
    allowed_subscriptions: list[str] = []    # empty = all in tenant config
    skip_resource_types: list[str] = []
    max_resources_per_type: int = 500        # prevents runaway scope-expansion loops
    allow_imds_probe: bool = False           # IMDS token probes — off by default
    allow_anonymous_blob_access_test: bool = True
    allow_kv_secret_metadata_read: bool = True  # metadata only; never raw values
    allow_sas_token_extraction: bool = True
    allow_run_command_test: bool = False     # VM Run Command — too disruptive


class AzureConfig(BaseModel):
    """Azure cloud auditing configuration (Clementine 2.0 'Mandarin')."""
    enabled: bool = False
    tenants: list[AzureTenantConfig] = []
    compliance_frameworks: list[str] = [
        "cis_3.0_azure",
        "mcsb_azure",
        "nist_800_53_revision_5_azure",
        "iso27001_2013_azure",
        "soc2_azure",
        "prowler_threatscore_azure",
    ]
    kql_queries_dir: Path = Path("./queries/azure")
    guardrails: AzureEngagementGuardrails = AzureEngagementGuardrails()
    pim_activation_cost: float = 0.7        # path-score discount for PIM_ELIGIBLE_FOR edges
    expand_inherited_assignments: bool = True


# ---------------------------------------------------------------------------
# Compliance configuration
# ---------------------------------------------------------------------------

class ComplianceConfig(BaseModel):
    """Compliance frameworks to evaluate during the Prowler audit phase."""
    frameworks: list[str] = ["cis_2.0_aws"]


# ---------------------------------------------------------------------------
# Reporting configuration
# ---------------------------------------------------------------------------

class ReportingConfig(BaseModel):
    """Controls which report formats are generated and where they are written."""
    formats: list[Literal["html", "json", "sarif", "markdown"]] = ["html", "json"]
    output_dir: Path = Path("./reports")
    # If true, findings are pushed to AWS Security Hub in ASFF format
    push_to_security_hub: bool = False
    security_hub_region: str = "us-east-1"


# ---------------------------------------------------------------------------
# Orchestrator tuning
# ---------------------------------------------------------------------------

class OrchestratorConfig(BaseModel):
    """Runtime tuning for the orchestration engine."""
    # Maximum number of MCP tool calls that may run concurrently
    max_parallel_agents: int = 4
    # SQLite path (sqlite:///path) or PostgreSQL DSN (postgresql://...)
    finding_db: str = "sqlite:///findings.db"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # When True the orchestrator waits for manual confirmation before each phase
    pause_between_phases: bool = False


# ---------------------------------------------------------------------------
# MCP server configurations
# ---------------------------------------------------------------------------

class StdioServerConfig(BaseModel):
    """Configuration for an MCP server accessed via stdio transport."""
    type: Literal["stdio"] = "stdio"
    command: str
    args: list[str] = []
    # Extra environment variables passed to the child process (resolved from env)
    env: dict[str, str] = {}


class HttpServerConfig(BaseModel):
    """Configuration for a remote MCP server accessed via HTTP transport."""
    type: Literal["http"] = "http"
    url: str
    # Optional headers forwarded with every request (e.g. Authorization: Bearer …)
    headers: dict[str, str] = {}


# Discriminated union — Pydantic picks the right model based on the `type` field.
# Configs without an explicit `type` key default to stdio.
AnyServerConfig = Annotated[
    Union[StdioServerConfig, HttpServerConfig],
    Field(discriminator="type"),
]


class MCPServersConfig(BaseModel):
    """Collection of all MCP server configurations.

    All servers are optional so the orchestrator can gracefully degrade when
    a non-critical server is unavailable.
    """
    # Existing servers
    autopentest: Optional[AnyServerConfig] = None
    cloud_audit: Optional[AnyServerConfig] = None
    prowler: Optional[AnyServerConfig] = None
    aws_knowledge: Optional[HttpServerConfig] = None
    aws_docs: Optional[StdioServerConfig] = None
    playwright: Optional[AnyServerConfig] = None
    # Azure servers (Clementine 2.0)
    azure_mcp: Optional[AnyServerConfig] = None        # @azure/mcp@latest
    prowler_mcp: Optional[AnyServerConfig] = None      # prowler-mcp (unified AWS+Azure)
    microsoft_learn: Optional[AnyServerConfig] = None  # learn.microsoft.com wrapper

    @model_validator(mode="before")
    @classmethod
    def _inject_type_tags(cls, data: object) -> object:
        """Inject a 'type' tag so the discriminated union can resolve correctly.

        YAML configs that omit 'type' are disambiguated by shape:
          - has 'url'     → http
          - has 'command' → stdio
        Configs that already carry an explicit 'type' are left untouched.
        """
        if not isinstance(data, dict):
            return data
        for value in data.values():
            if isinstance(value, dict) and "type" not in value:
                if "url" in value:
                    value["type"] = "http"
                elif "command" in value:
                    value["type"] = "stdio"
        return data


# ---------------------------------------------------------------------------
# AI configuration (Anthropic-backed triage + discovery)
# ---------------------------------------------------------------------------

class AITriageConfig(BaseModel):
    """Per-feature tuning for the finding-triage pass."""
    enabled: bool = True
    # Findings are batched so each request fits comfortably in context while
    # still getting amortized prompt-cache hits on the system prompt / schema.
    batch_size: int = 10
    # Confidence below this threshold marks a finding as likely false-positive.
    false_positive_threshold: float = 0.35


class AIDiscoveryConfig(BaseModel):
    """Per-feature tuning for novel attack-chain discovery."""
    enabled: bool = True
    # Cap discovery output so the model can't flood the database with chains
    # of dubious quality; matches the spirit of the rule-based correlator's
    # conservative pattern set.
    max_chains: int = 10
    # Chains the model scores below this confidence are dropped, since the
    # AI-discovery path is inherently more speculative than rule patterns.
    min_confidence: float = 0.5
    # Output token cap for the discovery call. The schema is bounded by
    # max_chains, so 16K was wildly over-provisioned; 8K is a comfortable
    # cap for ~10 narrative chains.
    max_tokens: int = 8192
    # Opus thinking effort for discovery only — kept separate from the
    # global ai.effort so triage stays at the configured default.
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    # Discovery is one large call; retries silently multiply spend, so the
    # default is "fail loudly after one transient error" rather than three.
    max_retries: int = 1
    # Findings whose triage confidence is below this are dropped before the
    # call. Acts as a quality floor — anything the triage pass thinks is
    # noise can't end up as the entry/pivot of a discovered chain.
    min_finding_confidence: float = 0.4
    # Whether to feed INFO-severity findings into discovery. INFO findings
    # almost never participate in real chains; excluding them is the
    # cheapest no-quality-loss reduction we can make.
    include_info: bool = False
    # Hop radius around finding-bearing resources used to prune the resource
    # graph before serialisation. 2 hops captures realistic pivot chains
    # without dragging in the whole account topology.
    subgraph_hops: int = 2
    # When True, findings whose resource is isolated in the pruned subgraph
    # are also dropped — they can't multi-hop to anything else.
    drop_unreachable_findings: bool = True


class AIConfig(BaseModel):
    """Amazon Bedrock Claude integration for triage and novel-chain discovery.

    Authentication is handled entirely via the standard AWS credential chain
    (env vars, ~/.aws/credentials, instance profile, ECS task role). No
    Anthropic API key is required — access is governed by IAM policies that
    grant bedrock:InvokeModel on the target model ARNs.
    """
    enabled: bool = True
    # AWS region where Bedrock inference is available for the target models.
    # Must match a region where cross-region inference profiles are enabled.
    aws_region: str = "us-east-1"
    # Primary model — cross-region inference profile ID for the heavy phases
    # (recon, app-test, triage). Verify availability in your account/region
    # via the Bedrock console before deploying.
    primary_model: str = "us.anthropic.claude-sonnet-4-6-20251101"
    # Critical model — reserved for novel attack-chain discovery. Opus earns
    # its cost here; verify the cross-region inference profile is enabled.
    critical_model: str = "us.anthropic.claude-opus-4-7-20251101"
    # Effort controls extended-thinking budget on Opus 4.x (Sonnet ignores it).
    # Maps to budget_tokens: low=1024 medium=4096 high=10000 xhigh=16000 max=32000
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    # How many parallel Anthropic requests may be in flight at once. Kept
    # conservative so a large assessment doesn't exhaust rate limits.
    max_parallel_requests: int = 4
    # Retry budget for transient API errors (rate-limit / 5xx).
    max_retries: int = 3
    triage: AITriageConfig = AITriageConfig()
    discovery: AIDiscoveryConfig = AIDiscoveryConfig()


# ---------------------------------------------------------------------------
# Root configuration
# ---------------------------------------------------------------------------

class ClementineConfig(BaseModel):
    """Root configuration object loaded from clementine.yaml."""
    target: TargetConfig
    auth: AuthConfig = AuthConfig()
    aws: AWSConfig = AWSConfig()
    azure: AzureConfig = AzureConfig()
    compliance: ComplianceConfig = ComplianceConfig()
    reporting: ReportingConfig = ReportingConfig()
    orchestrator: OrchestratorConfig = OrchestratorConfig()
    mcp_servers: MCPServersConfig = MCPServersConfig()
    ai: AIConfig = AIConfig()

    @model_validator(mode="before")
    @classmethod
    def resolve_env_vars(cls, data: dict) -> dict:
        """Walk the entire config dict and resolve all ${ENV_VAR} tokens."""
        return _resolve_dict(data)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def load_config(path: Path | str) -> ClementineConfig:
    """Load and validate a clementine.yaml config file.

    Resolves all ${ENV_VAR} placeholders before validation so that Pydantic
    sees fully-resolved string values.

    Raises:
        FileNotFoundError: if the config file does not exist.
        EnvironmentError: if a required env var is missing.
        pydantic.ValidationError: if the config schema is invalid.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open() as fh:
        raw = yaml.safe_load(fh)

    return ClementineConfig.model_validate(raw)
