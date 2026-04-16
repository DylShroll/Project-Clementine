"""
Credential scrubbing for evidence storage and report generation.

Before any HTTP exchange or raw tool output is written to the findings
database, sanitize() is called to strip credential values.  This prevents
secrets from leaking into reports that may be shared with stakeholders.

Scrubbing is intentionally conservative: it replaces header *values* (not
names), Bearer tokens, Base64 Basic-auth strings, and common secret patterns.
"""

from __future__ import annotations

import base64
import re

# ---------------------------------------------------------------------------
# Patterns to redact
# ---------------------------------------------------------------------------

# HTTP headers whose values must always be redacted
_SENSITIVE_HEADERS = re.compile(
    r"(?i)^(authorization|cookie|set-cookie|x-api-key|x-auth-token"
    r"|x-amz-security-token|x-amz-session-token|proxy-authorization)$"
)

# Bearer / token patterns in header values
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-_.~+/]+=*")

# AWS-style access key IDs and secret keys
_AWS_KEY_RE = re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])")
_AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")

# Generic password-like fields in JSON/query strings
_PASSWORD_RE = re.compile(
    r'(?i)("?(?:password|passwd|secret|token|api_key|apikey|private_key)"?\s*[:=]\s*)'
    r'("[^"]{3,}"|[^\s&"]{3,})'
)

_REDACTED = "[REDACTED]"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of *headers* with sensitive values replaced by [REDACTED].

    The header *names* are preserved so the structure remains readable.
    """
    cleaned: dict[str, str] = {}
    for name, value in headers.items():
        if _SENSITIVE_HEADERS.match(name):
            cleaned[name] = _REDACTED
        else:
            cleaned[name] = value
    return cleaned


def sanitize_text(text: str) -> str:
    """Scrub credential patterns from an arbitrary text string.

    Applies in order:
    1. Bearer tokens in Authorization header values
    2. Generic password/secret key=value pairs
    Returns the cleaned string.
    """
    # Remove bearer tokens but keep the "Bearer " prefix so context is clear
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    # Remove password/secret values in key=value or key:value patterns
    text = _PASSWORD_RE.sub(r"\1[REDACTED]", text)
    return text


def sanitize_evidence(evidence: dict) -> dict:
    """Deep-sanitize an evidence dict before persisting to the database.

    Handles the three common evidence shapes:
    - http_exchange: {request: {headers, body}, response: {headers, body}}
    - cli_output:    {stdout, stderr, command}
    - config_dump:   {raw}
    """
    if not isinstance(evidence, dict):
        return evidence

    result = dict(evidence)

    # HTTP exchange evidence
    for direction in ("request", "response"):
        if direction in result and isinstance(result[direction], dict):
            exchange = dict(result[direction])
            if "headers" in exchange and isinstance(exchange["headers"], dict):
                exchange["headers"] = sanitize_headers(exchange["headers"])
            if "body" in exchange and isinstance(exchange["body"], str):
                exchange["body"] = sanitize_text(exchange["body"])
            result[direction] = exchange

    # CLI output evidence
    for field in ("stdout", "stderr", "command"):
        if field in result and isinstance(result[field], str):
            result[field] = sanitize_text(result[field])

    # Raw config dump
    if "raw" in result and isinstance(result["raw"], str):
        result["raw"] = sanitize_text(result["raw"])

    return result


def is_base64_credential(value: str) -> bool:
    """Heuristic: return True if *value* looks like a Base64-encoded credential.

    Used to redact Basic auth header values before storage.
    """
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        # Basic auth is "username:password" — colon is the tell
        return ":" in decoded and len(decoded) >= 3
    except Exception:
        return False
