"""AWS credential resolution that survives non-standard dev-env layouts.

Subprocess scanners (Prowler) and stdio MCP servers (cloud_audit, iam) each
spin up their own boto3 session and therefore each face the same credential-
chain question. Resolving once here and exporting the result as
``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` / ``AWS_SESSION_TOKEN``
keeps every consumer on a single, predictable surface.

Resolution order:

  1. ``boto3.Session(profile_name=…)`` — covers shared_credentials_file,
     SSO profiles, credential_process, instance metadata, and any AWS_*
     env overrides already in scope.
  2. ``boto3.Session()`` with no profile — the standard default chain,
     used when the configured profile is empty / missing / unauthenticated.
  3. ``~/.aws/login/cache/*.json`` — the credential layout produced by
     aws-cli-login (https://github.com/aws-cli-login/aws-cli-login), which
     appears on machines that have ``login_session = …`` entries in
     ``~/.aws/config``. boto3 doesn't read this format, so we parse it
     ourselves to keep Prowler and MCP servers from face-planting on a
     setup that the AWS CLI itself handles fine.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import boto3
from botocore.exceptions import ClientError, ProfileNotFound

log = logging.getLogger(__name__)


def verify_aws_credentials(env: dict[str, str], region: str = "us-east-1") -> Optional[str]:
    """Run sts:GetCallerIdentity with the resolved env to confirm liveness.

    Returns the AWS account ID on success, or None when credentials are
    rejected. Logs a tight, actionable message on the common failure modes
    (ExpiredToken / InvalidClientTokenId) so the user knows whether to
    re-auth vs. fix a config typo, without having to hunt through tracebacks
    that wouldn't surface until a downstream phase tried to use the creds.
    """
    if not env.get("AWS_ACCESS_KEY_ID"):
        return None
    try:
        session = boto3.Session(
            aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=env.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
        identity = session.client("sts").get_caller_identity()
        log.info(
            "AWS credentials verified: account=%s arn=%s",
            identity.get("Account"), identity.get("Arn"),
        )
        return identity.get("Account")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ExpiredToken":
            log.error(
                "AWS session token is expired. Re-authenticate (e.g. `aws login` "
                "or `aws sso login`) and re-run Clementine."
            )
        elif code == "InvalidClientTokenId":
            log.error(
                "AWS access key is invalid. Check the profile / env vars feeding "
                "Clementine's credential chain."
            )
        else:
            log.error("AWS credential verification failed (%s): %s", code, exc)
        return None
    except Exception as exc:
        log.error("AWS credential verification failed: %s", exc)
        return None

_LOGIN_CACHE_DIR = Path.home() / ".aws" / "login" / "cache"


def resolve_aws_env(profile: Optional[str] = None) -> dict[str, str]:
    """Resolve AWS credentials, returning them as env-var dict (or {})."""
    creds = _try_boto3_with_profile(profile) if profile else None
    if creds is None:
        creds = _try_boto3_default_chain()
    if creds is None:
        creds = _try_aws_cli_login_cache()
    if creds is None:
        log.error(
            "AWS credentials not found via profile=%r, boto3 default chain, "
            "or ~/.aws/login/cache. Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY "
            "(+ AWS_SESSION_TOKEN for STS) or run your SSO/login flow before "
            "starting Clementine.",
            profile,
        )
        return {}

    env = {
        "AWS_ACCESS_KEY_ID": creds["access_key"],
        "AWS_SECRET_ACCESS_KEY": creds["secret_key"],
    }
    if creds.get("token"):
        env["AWS_SESSION_TOKEN"] = creds["token"]
    return env


def _try_boto3_with_profile(profile: str) -> Optional[dict[str, Optional[str]]]:
    try:
        session = boto3.Session(profile_name=profile)
        raw = session.get_credentials()
        if not raw:
            return None
        frozen = raw.get_frozen_credentials()
        if frozen.access_key:
            log.info("AWS credentials resolved via profile=%s", profile)
            return {
                "access_key": frozen.access_key,
                "secret_key": frozen.secret_key,
                "token": frozen.token,
            }
    except ProfileNotFound:
        log.warning("AWS profile %r not found; trying default chain", profile)
    except Exception as exc:
        log.warning("AWS profile %r failed: %s; trying default chain", profile, exc)
    return None


def _try_boto3_default_chain() -> Optional[dict[str, Optional[str]]]:
    try:
        session = boto3.Session()
        raw = session.get_credentials()
        if not raw:
            return None
        frozen = raw.get_frozen_credentials()
        if frozen.access_key:
            log.info("AWS credentials resolved via boto3 default chain")
            return {
                "access_key": frozen.access_key,
                "secret_key": frozen.secret_key,
                "token": frozen.token,
            }
    except Exception as exc:
        log.warning("boto3 default credential chain failed: %s", exc)
    return None


def _try_aws_cli_login_cache() -> Optional[dict[str, Optional[str]]]:
    """Read the most recently-modified aws-cli-login cache entry, if any."""
    if not _LOGIN_CACHE_DIR.is_dir():
        return None
    candidates = sorted(
        _LOGIN_CACHE_DIR.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for path in candidates:
        try:
            with path.open() as fh:
                payload = json.load(fh)
        except Exception as exc:
            log.debug("Could not parse %s: %s", path, exc)
            continue
        # aws-cli-login nests creds under "accessToken"; tolerate either shape.
        inner = payload.get("accessToken") if isinstance(payload, dict) else None
        if not isinstance(inner, dict):
            inner = payload if isinstance(payload, dict) else {}
        ak = inner.get("accessKeyId") or inner.get("AccessKeyId")
        sk = inner.get("secretAccessKey") or inner.get("SecretAccessKey")
        token = inner.get("sessionToken") or inner.get("SessionToken")
        if ak and sk:
            log.info(
                "AWS credentials resolved via aws-cli-login cache: %s",
                path.name,
            )
            return {"access_key": ak, "secret_key": sk, "token": token}
    return None
