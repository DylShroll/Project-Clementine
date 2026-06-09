#!/bin/sh
# iac_collect.sh — collect Terraform / CloudFormation artefacts into a
# tamper-evident bundle that Clementine's `bundle` source path can
# ingest offline.
#
# Use this when the user can't or won't give Clementine direct access
# to their infra repo or remote state, but can run shell scripts on a
# trusted workstation. The bundle is plain tar.gz with a manifest.json
# containing SHA-256 hashes per file plus collection metadata.
#
# Pure POSIX sh — works on any modern Linux/macOS with standard tools
# (tar, find, sha256sum or shasum, terraform optional).
#
# Usage:
#     scripts/iac_collect.sh \
#         --root ./infra \
#         --output ./iac-bundle.tar.gz \
#         [--include-state]   # opt-in: include .tfstate files
#
# Exit codes:
#     0 — success
#     1 — usage error
#     2 — missing required tool
#     3 — `terraform init` or `terraform show` failed for one or more modules

set -eu

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

ROOT=""
OUTPUT=""
INCLUDE_STATE=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --root)
            ROOT="$2"; shift 2 ;;
        --output)
            OUTPUT="$2"; shift 2 ;;
        --include-state)
            INCLUDE_STATE=1; shift ;;
        -h|--help)
            sed -n '4,28p' "$0"; exit 0 ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            exit 1 ;;
    esac
done

if [ -z "$ROOT" ] || [ -z "$OUTPUT" ]; then
    printf 'Usage: %s --root <path> --output <bundle.tar.gz> [--include-state]\n' "$0" >&2
    exit 1
fi
if [ ! -d "$ROOT" ]; then
    printf 'Root directory not found: %s\n' "$ROOT" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Tooling probes
# ---------------------------------------------------------------------------

# sha256: prefer sha256sum (Linux), fall back to `shasum -a 256` (macOS).
if command -v sha256sum >/dev/null 2>&1; then
    SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA="shasum -a 256"
else
    printf 'Neither sha256sum nor shasum found on PATH.\n' >&2
    exit 2
fi

# terraform is optional — when absent we still collect raw .tf files,
# we just don't render canonical JSON plans. This makes the bundle
# usable on workstations that haven't been set up with terraform.
HAS_TF=0
if command -v terraform >/dev/null 2>&1; then HAS_TF=1; fi

# ---------------------------------------------------------------------------
# Build a staging directory
# ---------------------------------------------------------------------------

STAGE=$(mktemp -d -t clementine-iac-bundle.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

# The bundle layout is intentionally flat — manifest.json sits at the
# tarball root so the resolver can find it without descending. modules/
# and cfn-templates/ are siblings, not children, of manifest.json.
mkdir -p "$STAGE/modules" "$STAGE/cfn-templates"

# Collect Terraform JSON plans per module (one ".tf"-bearing dir per module).
# Modules that fail `terraform init -backend=false` are skipped with a
# warning, the rest of the run continues. This matches the Phase 0
# failure-tolerant principle from the roadmap.
TF_RC=0
if [ "$HAS_TF" -eq 1 ]; then
    find "$ROOT" -type f -name '*.tf' \
        | sed 's|/[^/]*$||' \
        | sort -u \
        | while IFS= read -r module; do
            slug=$(printf '%s' "$module" | sed 's|[^a-zA-Z0-9_]|_|g')
            module_out="$STAGE/modules/$slug"
            mkdir -p "$module_out"
            (
                cd "$module" || exit 1
                terraform init -backend=false -input=false -no-color \
                    > "$module_out/init.log" 2>&1 || exit 10
                terraform plan -refresh=false -input=false -no-color \
                    -out="$module_out/plan.binary" \
                    > "$module_out/plan.log" 2>&1 || exit 11
                terraform show -json "$module_out/plan.binary" \
                    > "$module_out/plan.json" 2>"$module_out/show.log" || exit 12
            ) || {
                rc=$?
                printf 'WARN: terraform pipeline failed for %s (rc=%s) — skipping\n' \
                    "$module" "$rc" >&2
                # Non-fatal at the top level; record one bad module and
                # carry on. The exit status is OR'd so the script's
                # final exit code reflects "some module failed".
                TF_RC=3
            }
        done
fi

# Collect CFN templates by file extension + content sniff.
# (Keeping the sniff loose; cfn-nag will reject non-CFN YAML downstream
# anyway, and missing one template is worse than carrying an extra one.)
find "$ROOT" \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) -type f | while IFS= read -r f; do
    if grep -qE '^(AWSTemplateFormatVersion|Resources:)' "$f" 2>/dev/null; then
        rel="${f#"$ROOT"/}"
        slug=$(printf '%s' "$rel" | sed 's|[^a-zA-Z0-9_.]|_|g')
        cp "$f" "$STAGE/cfn-templates/$slug"
    fi
done

# Optionally include .tfstate files (off by default — they routinely
# contain plaintext secrets). The bundle resolver in Clementine also
# refuses to read them unless guardrails.include_state_files=true.
if [ "$INCLUDE_STATE" -eq 1 ]; then
    mkdir -p "$STAGE/state"
    find "$ROOT" -type f -name '*.tfstate' | while IFS= read -r f; do
        rel="${f#"$ROOT"/}"
        slug=$(printf '%s' "$rel" | sed 's|[^a-zA-Z0-9_.]|_|g')
        cp "$f" "$STAGE/state/$slug"
    done
fi

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

# manifest.json carries collection metadata + per-file SHA-256 so a
# tampered bundle is detectable. Format intentionally minimal:
#   { "version": 1,
#     "collected_at": "ISO 8601",
#     "tool_versions": { "terraform": "...", "shell": "..." },
#     "files": [ { "path": "modules/.../plan.json", "sha256": "..." }, ... ] }

now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
tf_version=$(terraform -version 2>/dev/null | head -n1 | sed 's/^Terraform //' || true)

{
    printf '{\n'
    printf '  "version": 1,\n'
    printf '  "collected_at": "%s",\n' "$now"
    printf '  "tool_versions": {\n'
    printf '    "terraform": "%s",\n' "${tf_version:-absent}"
    printf '    "shell":     "%s"\n' "$(uname -srm 2>/dev/null || printf 'unknown')"
    printf '  },\n'
    printf '  "include_state": %s,\n' "$( [ "$INCLUDE_STATE" -eq 1 ] && printf 'true' || printf 'false' )"
    printf '  "files": [\n'

    first=1
    find "$STAGE" -type f ! -name 'manifest.json' | sort | while IFS= read -r f; do
        rel="${f#"$STAGE/"}"
        sum=$($SHA "$f" | awk '{print $1}')
        if [ "$first" -eq 1 ]; then
            first=0
        else
            printf ',\n'
        fi
        printf '    {"path": "%s", "sha256": "%s"}' "$rel" "$sum"
    done
    printf '\n  ]\n'
    printf '}\n'
} > "$STAGE/manifest.json"

# ---------------------------------------------------------------------------
# Tar everything up
# ---------------------------------------------------------------------------

(cd "$STAGE" && tar -czf "$OUTPUT" .)
printf 'Wrote bundle: %s\n' "$OUTPUT"
exit "$TF_RC"
