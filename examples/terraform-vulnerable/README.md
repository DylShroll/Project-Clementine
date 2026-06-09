# `terraform-vulnerable` — Phase 0 acceptance fixture

A deliberately-insecure Terraform module used by Clementine's CI to
verify that `clementine iac` produces a deterministic, non-empty
finding set across the M1–M5 scanner stack.

**Do not deploy.** Every resource here is unsafe by design.

## Expected coverage

Running:

```sh
clementine iac \
    --config tests/fixtures/iac/clementine.yaml \
    --source dir:./examples/terraform-vulnerable \
    --format sarif \
    --output ./reports
```

is expected to produce:

* ≥ 12 findings across all five scanners
* ≥ 4 severity levels (CRITICAL + HIGH + MEDIUM + LOW)
* Hardcoded `AKIA…` keys flagged by both gitleaks and trufflehog
* Wide-open security group, public S3 bucket, wildcard IAM role
  flagged by tfsec / checkov
* Two of the three IaC patterns under `patterns/iac/` should fire
  (`hardcoded_credential_in_planned_resource` and
  `planned_public_bucket_overpermissive_role`)

When `--max-severity HIGH` is passed, the command exits 1.
