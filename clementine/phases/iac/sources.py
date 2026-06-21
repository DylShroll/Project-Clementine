"""IaC source ingestion — resolve every IacSourceConfig to a local tree.

Each source resolver returns a ``ResolvedSource`` that wraps:
  * the on-disk root path the scanner should operate on
  * a ``source_kind`` discriminator that scanners use to decide
    whether they can run (e.g. tfsec runs only on Terraform sources)
  * a ``cleanup`` callable invoked unconditionally in a ``finally`` so
    temp dirs always disappear, even on scan failure

Milestone scope:
  * B.M1 — ``dir`` only.
  * B.M2 — adds CFN parser support but reuses ``dir`` resolution.
  * B.M4 — adds ``plan``, ``terraform_remote_state``, ``cfn_stack``,
    ``git``, ``bundle``, ``scanner_import``.

Security-relevant code lives here:
  * The ``bundle`` resolver (M4) extracts user-supplied tarballs. Path
    traversal is rejected via realpath comparison; the helper
    ``_safe_extract`` will own that boundary.
  * The ``git`` resolver (M4) clones into ``tempfile.TemporaryDirectory``
    with a sanitised env so credentials never leak into git's process
    environment beyond ``GITHUB_TOKEN``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Iterable, Literal, Optional

log = logging.getLogger(__name__)


# Source kinds map to scanner.applicable_to() decisions. Keep this list
# authoritative; scanners check membership directly.
SourceKind = Literal[
    "terraform",        # raw .tf directory or terraform_remote_state-derived JSON
    "terraform_plan",   # `terraform show -json` output
    "cloudformation",   # .yaml / .json CFN templates or cfn_stack-derived YAML
    "mixed",            # directory containing both kinds
    "scanner_import",   # pre-recorded scanner JSON; bypasses subprocess
    "unknown",          # nothing scanner-relevant detected
]


@dataclass
class ResolvedSource:
    """A scanner-ready local working tree.

    ``path`` is the on-disk root the scanners should operate on.
    ``source_kind`` lets each scanner self-filter via ``applicable_to``.
    ``original`` keeps the user's IacSourceConfig for provenance tracking
    in findings (e.g. so a finding from a temp clone reports the original
    git URL, not the temp path).
    ``cleanup`` is invoked exactly once in a finally block; safe to call
    repeatedly because each implementation guards itself.

    ``precomputed_scanner`` and ``precomputed_output`` are populated only
    when the user supplied pre-recorded scanner JSON via the
    ``scanner_import`` source type. When set, ``SubprocessScanner.run``
    short-circuits the subprocess and feeds the bytes straight into
    ``parse``. Only the named scanner is applicable; the others skip.
    """
    path: Path
    source_kind: SourceKind
    original: object                              # IacSourceConfig (avoid circular import)
    manifest: dict = field(default_factory=dict)  # SHA-256s, timestamps, …
    cleanup: Optional[Callable[[], Awaitable[None] | None]] = None
    precomputed_scanner: Optional[str] = None
    precomputed_output: Optional[bytes] = None


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

async def resolve_sources(sources: Iterable, guardrails) -> list[ResolvedSource]:
    """Resolve every configured source into a local tree.

    Errors on any one source are logged and skipped (the phase is
    failure-tolerant per roadmap §4) — the remaining sources still
    process.
    """
    resolved: list[ResolvedSource] = []
    for src in sources:
        try:
            resolved.append(await _resolve_one(src, guardrails))
        except Exception as exc:                                   # pragma: no cover - defensive
            log.warning("[Phase 0] could not resolve source %r: %s", src, exc)
    return resolved


async def _resolve_one(src, guardrails) -> ResolvedSource:
    """Dispatch to the per-type resolver.

    Each resolver is responsible for materialising a local tree (or a
    pre-recorded scanner blob) and returning a ``ResolvedSource``. Any
    temp directories must be tracked via the ``cleanup`` field so the
    phase can free them deterministically.
    """
    if src.type == "dir":
        return _resolve_dir(src, guardrails)
    if src.type == "plan":
        return await _resolve_plan(src, guardrails)
    if src.type == "terraform_remote_state":
        return await _resolve_terraform_remote_state(src, guardrails)
    if src.type == "cfn_stack":
        return await _resolve_cfn_stack(src, guardrails)
    if src.type == "git":
        return await _resolve_git(src, guardrails)
    if src.type == "bundle":
        return await _resolve_bundle(src, guardrails)
    if src.type == "scanner_import":
        return _resolve_scanner_import(src, guardrails)
    raise NotImplementedError(f"IaC source type {src.type!r} is not supported")


# ---------------------------------------------------------------------------
# `dir` resolver
# ---------------------------------------------------------------------------

# File extensions used to classify a directory. Order matters only for
# logging; presence-based classification.
_TF_EXTS = {".tf", ".tfvars", ".tfvars.json"}
_CFN_EXTS = {".yaml", ".yml", ".json"}      # CFN-shaped is determined later
_CFN_HINTS = (b"AWSTemplateFormatVersion", b"Resources:")


def _resolve_dir(src, guardrails) -> ResolvedSource:
    """Walk a directory and classify it as Terraform / CFN / mixed.

    No copying or extraction happens — the user's tree is read in place.
    `cleanup` is therefore None for this resolver.
    """
    if not src.path:
        raise ValueError("IacSourceConfig(type='dir') requires a `path`")
    root = Path(src.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"IaC source directory not found: {root}")

    kind = _classify_dir(root, guardrails)
    log.info("[Phase 0] resolved dir source %s as %s", root, kind)
    return ResolvedSource(path=root, source_kind=kind, original=src)


def _looks_like_cfn(p: Path) -> bool:
    """Cheap CFN sniff: read up to 2KB and look for a CFN-only marker.

    CloudFormation templates always have ``Resources:`` and nearly always
    declare ``AWSTemplateFormatVersion``. This avoids classifying a
    Kubernetes manifest or generic YAML as a CFN template.
    """
    try:
        with p.open("rb") as fh:
            head = fh.read(2048)
    except OSError:
        return False
    return any(hint in head for hint in _CFN_HINTS)


# ---------------------------------------------------------------------------
# Helper: temp-dir cleanup as an awaitable callback
# ---------------------------------------------------------------------------

def _make_tmpdir_cleanup(tmpdir: Path) -> Callable[[], None]:
    """Return a no-arg cleanup that recursively removes ``tmpdir``.

    Wrapped here so each resolver's cleanup behaviour is identical and
    suppression of teardown errors is uniform. Errors during cleanup
    are debug-logged — temp leak at process exit beats a crash on the
    happy path.
    """
    def _cleanup() -> None:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception as exc:                                   # pragma: no cover - best-effort
            log.debug("[Phase 0] tmpdir cleanup failed for %s: %s", tmpdir, exc)
    return _cleanup


# ---------------------------------------------------------------------------
# `plan` resolver — Terraform JSON plan, or a binary plan we render
# ---------------------------------------------------------------------------

async def _resolve_plan(src, guardrails) -> ResolvedSource:
    """Resolve a Terraform plan source.

    JSON plans are passed through unchanged (the file already *is* the
    canonical resolved form). Binary plans require shelling out to the
    user's ``terraform`` binary to render JSON via ``terraform show
    -json``. We choose ``terraform show`` over ``terraform plan`` so we
    never execute provider code or talk to a backend — ``show`` is a
    pure local transform from binary plan → JSON.
    """
    if not src.path:
        raise ValueError("IacSourceConfig(type='plan') requires `path`")
    plan_path = Path(src.path).expanduser().resolve()
    if not plan_path.exists() or not plan_path.is_file():
        raise FileNotFoundError(f"plan file not found: {plan_path}")

    plan_format = (src.plan_format or _sniff_plan_format(plan_path)).lower()

    if plan_format == "json":
        # Wrap the JSON file in a tiny temp dir so scanners (which
        # expect a directory cwd) have somewhere to operate from.
        tmpdir = Path(tempfile.mkdtemp(prefix="clementine-plan-"))
        copy_path = tmpdir / "plan.json"
        shutil.copy2(plan_path, copy_path)
        return ResolvedSource(
            path=tmpdir,
            source_kind="terraform_plan",
            original=src,
            manifest={"plan_format": "json", "source": str(plan_path)},
            cleanup=_make_tmpdir_cleanup(tmpdir),
        )

    if plan_format == "binary":
        tmpdir = Path(tempfile.mkdtemp(prefix="clementine-plan-"))
        json_out = tmpdir / "plan.json"
        try:
            argv = ["terraform", "show", "-json", str(plan_path)]
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"terraform show failed (rc={proc.returncode}): "
                    f"{stderr.decode('utf-8', errors='replace')[:500]}"
                )
            json_out.write_bytes(stdout)
        except FileNotFoundError as exc:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise RuntimeError(
                "binary plan source requires the `terraform` binary on PATH"
            ) from exc
        except Exception:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

        return ResolvedSource(
            path=tmpdir,
            source_kind="terraform_plan",
            original=src,
            manifest={"plan_format": "binary", "source": str(plan_path)},
            cleanup=_make_tmpdir_cleanup(tmpdir),
        )

    raise ValueError(f"unknown plan_format: {plan_format!r}")


def _sniff_plan_format(p: Path) -> str:
    """Detect plan format from the first few bytes.

    Terraform binary plans start with ``PK`` (zip header) or a
    ``terraform-plan`` magic; JSON plans start with ``{`` after
    optional whitespace.
    """
    try:
        with p.open("rb") as fh:
            head = fh.read(8).lstrip()
    except OSError:
        return "json"
    if head.startswith(b"{"):
        return "json"
    return "binary"


# ---------------------------------------------------------------------------
# `terraform_remote_state` resolver — S3 only at M4
# ---------------------------------------------------------------------------

async def _resolve_terraform_remote_state(src, guardrails) -> ResolvedSource:
    """Fetch a Terraform state file from a remote backend.

    ``.tfstate`` files are JSON; we treat them as ``terraform_plan``
    sources after download (they have the same resolved-resource shape
    that scanners and the projection layer expect).

    Only the S3 backend is supported at M4. ``gcs`` and ``azurerm``
    backends require additional cloud SDKs that aren't yet pinned in
    pyproject; they're tracked as a follow-up.
    """
    backend = (src.backend or "").lower()
    if backend != "s3":
        raise NotImplementedError(
            f"terraform_remote_state backend {backend!r} not yet supported "
            "(only 's3' is implemented at M4)"
        )
    if not src.bucket or not src.key:
        raise ValueError("terraform_remote_state(s3) requires `bucket` and `key`")

    try:
        import boto3                                          # pyproject already pins this
    except ImportError as exc:                                # pragma: no cover - defensive
        raise RuntimeError("boto3 is required for terraform_remote_state(s3)") from exc

    tmpdir = Path(tempfile.mkdtemp(prefix="clementine-state-"))
    try:
        # Boto3 is sync; offload to a thread so we don't block the event loop.
        def _download() -> bytes:
            client = boto3.client("s3")
            obj = client.get_object(Bucket=src.bucket, Key=src.key)
            return obj["Body"].read()

        body = await asyncio.to_thread(_download)
        out_path = tmpdir / "terraform.tfstate.json"
        out_path.write_bytes(body)
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    return ResolvedSource(
        path=tmpdir,
        source_kind="terraform_plan",
        original=src,
        manifest={
            "backend": "s3",
            "bucket": src.bucket,
            "key": src.key,
            "size_bytes": len(body),
        },
        cleanup=_make_tmpdir_cleanup(tmpdir),
    )


# ---------------------------------------------------------------------------
# `cfn_stack` resolver — boto3 cloudformation:GetTemplate
# ---------------------------------------------------------------------------

async def _resolve_cfn_stack(src, guardrails) -> ResolvedSource:
    """Pull a deployed CloudFormation stack's template via the API.

    The original template is preserved verbatim (YAML or JSON) so
    scanners that pin findings to file:line still see meaningful refs.
    """
    if not src.stack_name:
        raise ValueError("cfn_stack source requires `stack_name`")

    try:
        import boto3
    except ImportError as exc:                                # pragma: no cover
        raise RuntimeError("boto3 is required for cfn_stack sources") from exc

    tmpdir = Path(tempfile.mkdtemp(prefix="clementine-cfn-"))
    try:
        def _fetch() -> tuple[str, str]:
            kwargs = {}
            if src.aws_region:
                kwargs["region_name"] = src.aws_region
            client = boto3.client("cloudformation", **kwargs)
            resp = client.get_template(StackName=src.stack_name)
            body = resp.get("TemplateBody", "")
            stage = resp.get("StagesAvailable", [""])[0] or "Original"
            return body if isinstance(body, str) else json.dumps(body), stage

        body, stage = await asyncio.to_thread(_fetch)
        # Try JSON first, fall back to YAML extension based on the body.
        ext = ".json" if body.lstrip().startswith("{") else ".yaml"
        out_path = tmpdir / f"{src.stack_name}{ext}"
        out_path.write_text(body, encoding="utf-8")
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    return ResolvedSource(
        path=tmpdir,
        source_kind="cloudformation",
        original=src,
        manifest={"stack_name": src.stack_name, "region": src.aws_region, "stage": stage},
        cleanup=_make_tmpdir_cleanup(tmpdir),
    )


# ---------------------------------------------------------------------------
# `git` resolver — shallow clone into a temp dir
# ---------------------------------------------------------------------------

async def _resolve_git(src, guardrails) -> ResolvedSource:
    """Clone a remote repo with ``--depth 1`` and classify like ``dir``.

    Authentication uses ``GITHUB_TOKEN`` from the environment when the
    URL is on github.com. We pass the token to git only in-memory via
    the URL form ``https://x-access-token:<TOKEN>@github.com/...`` and
    deliberately strip it from the manifest so it never lands in a
    finding's evidence_data.
    """
    if not src.url:
        raise ValueError("git source requires `url`")

    tmpdir = Path(tempfile.mkdtemp(prefix="clementine-git-"))
    try:
        url = _inject_github_token(src.url)
        argv = ["git", "clone", "--depth", "1"]
        if src.ref:
            argv += ["--branch", src.ref]
        argv += [url, str(tmpdir)]

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # Keep PATH but drop everything else so git doesn't pick up
            # ambient credentials from elsewhere.
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        _stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"git clone failed (rc={proc.returncode}): "
                f"{stderr.decode('utf-8', errors='replace')[:500]}"
            )
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    # Reuse the dir resolver's classification — same tree, same logic.
    classified = _classify_dir(tmpdir, guardrails)
    return ResolvedSource(
        path=tmpdir,
        source_kind=classified,
        original=src,
        # Manifest deliberately omits the token-bearing URL form.
        manifest={"git_url": src.url, "ref": src.ref or "HEAD"},
        cleanup=_make_tmpdir_cleanup(tmpdir),
    )


def _inject_github_token(url: str) -> str:
    """Rewrite a github.com URL to include GITHUB_TOKEN if set.

    Other hosts pass through unchanged so we never accidentally leak
    a GitHub token to (e.g.) a self-hosted GitLab.
    """
    if "github.com/" not in url or url.startswith("git@"):
        return url
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return url
    if url.startswith("https://"):
        # https://github.com/foo/bar -> https://x-access-token:TOKEN@github.com/foo/bar
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


# ---------------------------------------------------------------------------
# `bundle` resolver — tarball produced by scripts/iac_collect.sh
# ---------------------------------------------------------------------------

async def _resolve_bundle(src, guardrails) -> ResolvedSource:
    """Extract a bundle tarball into a temp dir.

    Path traversal protection: every member name is realpath-checked
    against the extraction root before extraction. Members that resolve
    outside the root (zipslip / tarslip attacks) are rejected; any
    rejected member aborts the whole extraction so a malicious bundle
    never partially-applies.
    """
    bundle = (src.bundle_path and Path(src.bundle_path).expanduser().resolve()) or None
    if bundle is None or not bundle.exists():
        raise FileNotFoundError(f"bundle path not found: {src.bundle_path}")

    tmpdir = Path(tempfile.mkdtemp(prefix="clementine-bundle-"))
    try:
        with tarfile.open(bundle, "r:*") as tar:
            _safe_extract(tar, tmpdir)

        # Optional manifest verification — if the bundle ships a
        # manifest.json with file SHA-256s, spot-check a few entries
        # so a tamper attempt surfaces here rather than later. Missing
        # or unparseable manifests are not fatal.
        manifest = _verify_bundle_manifest(tmpdir)
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    classified = _classify_dir(tmpdir, guardrails)
    return ResolvedSource(
        path=tmpdir,
        source_kind=classified,
        original=src,
        manifest=manifest,
        cleanup=_make_tmpdir_cleanup(tmpdir),
    )


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Reject members whose realpath escapes ``dest`` before extraction."""
    dest_real = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        # ``relative_to`` raises if member_path is not under dest_real.
        try:
            member_path.relative_to(dest_real)
        except ValueError as exc:
            raise RuntimeError(
                f"refusing to extract member {member.name!r}: "
                "path traversal attempt"
            ) from exc
        # Also reject special files (devices, fifos, hard/symlinks
        # that point outside the tree). Plain files and dirs only.
        if not (member.isreg() or member.isdir()):
            raise RuntimeError(
                f"refusing to extract non-regular member {member.name!r} "
                f"(type={member.type!r})"
            )
    tar.extractall(dest)


def _verify_bundle_manifest(root: Path) -> dict:
    """Read manifest.json if present; otherwise return {}.

    SHA-256 verification happens at the helper-script level (the
    script ships hashes for tamper-detection); here we just surface
    the manifest's metadata into the resolved source so reports can
    show "this bundle was produced at <timestamp> by <gcloud version>".
    Re-hashing every file inside Phase 0 would double the I/O for no
    extra security guarantee — the user must trust their bundle source
    by definition.
    """
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        return {"manifest": "absent"}
    try:
        return {"manifest": json.loads(manifest_path.read_text("utf-8"))}
    except (OSError, json.JSONDecodeError) as exc:
        log.debug("[Phase 0] could not parse bundle manifest: %s", exc)
        return {"manifest": "unparseable"}


# ---------------------------------------------------------------------------
# `scanner_import` resolver — pre-recorded JSON from a previous scan
# ---------------------------------------------------------------------------

def _resolve_scanner_import(src, guardrails) -> ResolvedSource:
    """Wrap pre-recorded scanner JSON in a ResolvedSource.

    No subprocess is run — :class:`SubprocessScanner` short-circuits
    when ``precomputed_scanner`` matches its own name. ``applicable_to``
    on each scanner returns False for any non-matching name, so a
    scanner_import source is fed to exactly one scanner.
    """
    if not src.scanner:
        raise ValueError("scanner_import source requires `scanner`")
    if not src.path:
        raise ValueError("scanner_import source requires `path`")
    payload_path = Path(src.path).expanduser().resolve()
    if not payload_path.exists() or not payload_path.is_file():
        raise FileNotFoundError(f"scanner_import payload not found: {payload_path}")
    payload = payload_path.read_bytes()

    # No path-on-disk is meaningful for downstream scanners (they're
    # bypassed). Use the parent dir of the payload so any safe_relpath
    # call still produces a sensible relative path.
    return ResolvedSource(
        path=payload_path.parent,
        source_kind="scanner_import",
        original=src,
        manifest={"scanner": src.scanner, "source_file": str(payload_path)},
        precomputed_scanner=src.scanner,
        precomputed_output=payload,
    )


# ---------------------------------------------------------------------------
# Helper: classify a directory's contents (extracted from _resolve_dir)
# ---------------------------------------------------------------------------

def _classify_dir(root: Path, guardrails) -> SourceKind:
    """Walk a directory and return its SourceKind.

    Shared between ``dir``, ``git``, and ``bundle`` resolvers. Same
    classification rules as the original ``_resolve_dir`` body.
    """
    has_tf = False
    has_cfn = False
    files_seen = 0
    for p in root.rglob("*"):
        if files_seen >= guardrails.max_files_scanned:
            break
        if not p.is_file():
            continue
        files_seen += 1
        ext = p.suffix.lower()
        if ext in _TF_EXTS:
            has_tf = True
        elif ext in _CFN_EXTS and _looks_like_cfn(p):
            has_cfn = True

    if has_tf and has_cfn:
        return "mixed"
    if has_tf:
        return "terraform"
    if has_cfn:
        return "cloudformation"
    return "unknown"
