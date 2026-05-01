# Azure Application Probes — Phase 3 Guidance

## Overview

Phase 3 adds Azure-specific probes after the standard AutoPentest WSTG Phases 2–5. All probes are opt-in via guardrails in `engagement.azure.guardrails`. Read the guardrail values before executing any probe — do NOT proceed if the guardrail is `false`.

---

## IMDS Probe (requires `allow_imds_probe: true`)

**Endpoint**: `http://169.254.169.254/metadata/identity/oauth2/token`

Probe each audience in sequence:
- `management.azure.com`
- `vault.azure.net`
- `storage.azure.com`
- `graph.microsoft.com`
- `database.windows.net`
- `cosmos.azure.com`

**Request**:
```
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://<audience>
Metadata: true
```

**If 200 returned**:
- Extract `access_token` from JSON body
- Split on `.` → keep only `header.payload` (strip signature)
- Decode payload (base64url) and extract: `xms_mirid`, `aud`, `oid`, `tid`, `exp`
- Log as **CRITICAL** finding: `category='azure:imds_exposed'`
- Store safe token (header.payload only) in evidence
- **DO NOT** use the token to call any downstream service

**If connection refused to 169.254.169.254**:
- This is expected in App Service sandbox environments
- Log as `category='IMDS_SANDBOX_RESTRICTED'` (INFO severity, not a vulnerability)
- Do NOT count as IMDS failure — use App Service identity endpoint instead

---

## App Service Identity Endpoint Probe (requires `allow_imds_probe: true`)

Only available inside an App Service sandbox. Check for the environment variables `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` before attempting.

**Request**:
```
GET ${IDENTITY_ENDPOINT}?resource=https://<audience>&api-version=2019-08-01
X-IDENTITY-HEADER: ${IDENTITY_HEADER}
```

If these env vars are not set, skip silently — this probe is a no-op when running outside an App Service context.

---

## WireServer Probe (no guardrail required)

**Endpoint**: `http://168.63.129.16/`

A successful HTTP response (any 2xx or 3xx) confirms execution inside an Azure VM context.

- Log as **INFO** finding: `category='azure:wireserver_reachable'`
- Do NOT enumerate WireServer endpoints or request extension data
- This is a VM context confirmation only

---

## SAS Token Detection (requires `allow_sas_token_extraction: true`)

Scan all accumulated HTTP evidence (from WSTG phases 1–5) for SAS token patterns:

Pattern: `?sv=<version>&...&sig=<signature>&se=<expiry>`

For each match, record:
- `sv` (signed version)
- `se` (signed expiry) → calculate `expiry_days`
- `permissions` (sp parameter)
- `signed_resource_type` (srt/sr parameter)
- Whether scope is account-level (srt= or sr=account)

**Severity classification**:
- `expiry_days > 7` OR account-scope → **HIGH**
- Otherwise → **MEDIUM**

Log as `category='SAS_TOKEN'` with the token parameters in evidence. Do NOT log the `sig=` signature value itself.

---

## Evidence Handling Rules

1. **Never persist full JWT tokens** — store `header.payload` only (2 of 3 parts)
2. **Never log SAS signatures** — store token parameters but not the `sig=` value
3. **Never use obtained credentials** to access downstream resources — report reachability only
4. All Azure evidence is automatically tagged `provider='azure'` in the findings table
