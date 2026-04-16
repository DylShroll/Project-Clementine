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
    autopentest: Optional[AnyServerConfig] = None
    cloud_audit: Optional[AnyServerConfig] = None
    prowler: Optional[AnyServerConfig] = None
    aws_knowledge: Optional[HttpServerConfig] = None
    aws_docs: Optional[StdioServerConfig] = None
    playwright: Optional[AnyServerConfig] = None

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
# Root configuration
# ---------------------------------------------------------------------------

class ClementineConfig(BaseModel):
    """Root configuration object loaded from clementine.yaml."""
    target: TargetConfig
    auth: AuthConfig = AuthConfig()
    aws: AWSConfig = AWSConfig()
    compliance: ComplianceConfig = ComplianceConfig()
    reporting: ReportingConfig = ReportingConfig()
    orchestrator: OrchestratorConfig = OrchestratorConfig()
    mcp_servers: MCPServersConfig = MCPServersConfig()

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
