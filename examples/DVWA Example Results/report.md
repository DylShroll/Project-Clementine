# Project Clementine — Security Assessment Report

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 3 |
| HIGH | 53 |
| MEDIUM | 48 |
| LOW | 22 |
| INFO | 2 |

**Attack Chains Identified:** 4

## Attack Chains

### exposed-config-to-db-compromise (CRITICAL)

An unauthenticated attacker retrieves /config/config.inc.php and its .bak sibling on the DVWA host (ec2-18-188-101-84), which the WSTG-CONF-03 finding confirms leaks plaintext database credentials. Because the site is served exclusively over HTTP (WSTG-CONF-07), the attacker can also sniff traffic, but the backup file alone provides direct DB creds usable to pivot into the backing MySQL and exfiltrate/modify application data.

### setup-reinit-to-admin-takeover (HIGH)

The setup.php page is reachable unauthenticated (WSTG-ATHZ-02) and discloses default credentials plus internal paths (WSTG-CONF-02). An attacker can trigger DB reinitialization to restore the known default admin/password pair (WSTG-ATHN-02) and then log in as admin, giving full application control.

### security-cookie-bypass-to-exploit-chain (HIGH)

The application trusts a client-supplied 'security=low' cookie server-side (WSTG-ATHZ-03 / WSTG-SESS-11), letting an attacker downgrade all vulnerability modules to their most vulnerable variants. From the low-security SSRF/file-include modules, the attacker can then target the reachable IMDS endpoint (WSTG-CONF-11) on the hosting EC2 instance to steal instance role credentials — amplifying a web flaw into AWS credential theft.

### xss-csrf-password-takeover (HIGH)

Session cookies lack HttpOnly (WSTG-SESS-02), so any reflected/stored XSS in DVWA (which is rife with them) can steal PHPSESSID. Combined with the unprotected password-change endpoint that requires neither CSRF token nor current password (WSTG-ATHN-09 / WSTG-SESS-05), an attacker can also simply force a victim browser to change the victim's password via a drive-by request, achieving account takeover without needing to steal the cookie.

## Findings

### [CRITICAL] Attached AWS-managed IAM policy does not allow '*:*' administrative privileges
- **Category:** iam_aws_attached_policy_no_administrative_privileges
- **Resource:** arn:aws:iam::aws:policy/AdministratorAccess

**IAM AWS-managed policies** attached to identities are inspected for statements that allow `Action:'*'` on `Resource:'*'`-i.e., full administrative `*:*` permissions

**Remediation:** Apply **least privilege**: avoid attaching AWS-managed policies that grant `*:*`.
- Use **customer-managed, scoped policies** per role
- Enforce **separation of duties** and **permissions boundaries**
- Prefer **temporary, time-bound elevation** for emergencies with MFA
- Regularly review access and use conditions to constrain context

### [CRITICAL] Root account has no active access keys
- **Category:** iam_no_root_access_key
- **Resource:** arn:aws:iam::760689105616:root

**AWS root user** is evaluated for **active access keys**. It identifies whether the root identity has one or two programmatic credentials and notes when organization-level root credential management is present.

**Remediation:** Delete and prohibit **root access keys**. Use **IAM roles** and temporary credentials with **least privilege** for all automation. Enable **MFA on root**, limit root to break-glass use, and continuously monitor for any new root keys. *Where applicable*, apply organization-wide controls to enforce this.

### [CRITICAL] Database Credentials Exposed via Backup Config File (config.inc.php.bak)
- **Category:** WSTG-CONF-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/config/config.inc.php.bak

The file /config/config.inc.php.bak is publicly accessible via HTTP and contains the full PHP source code of the application's database configuration, including plaintext database credentials. The file reveals: database server (127.0.0.1), database name (dvwa), database username (app), and database password (vulnerables). The file is served as application/x-trash (a backup extension) rather than being blocked or restricted. This allows any unauthenticated attacker to retrieve the database credentials and potentially access the database directly (port 3306 is currently filtered but this could change) or use these credentials for further attacks.

**Remediation:** 1. Immediately delete the backup file /config/config.inc.php.bak from the web server. 2. Rotate the exposed database credentials (change password for the 'app' database user). 3. Configure Apache to deny access to .bak, .old, .tmp, .swp and other backup file extensions using a Deny directive or FilesMatch rule in httpd.conf or .htaccess. 4. Move configuration files containing credentials outside the web root. 5. Implement a pre-deployment checklist that removes all backup/temp files before going live.

### [HIGH] No HTTPS - All Traffic Transmitted in Cleartext
- **Category:** WSTG-CONF-07
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

The application does not support HTTPS (port 443 is filtered). All application traffic including login credentials, session cookies, and sensitive data is transmitted in plaintext over HTTP. This exposes all user data to network-level eavesdropping and man-in-the-middle attacks. Verified via nmap: port 443 is filtered, port 80 is open running Apache.

**Remediation:** Implement TLS/SSL on port 443, redirect all HTTP traffic to HTTPS using a 301 redirect, and configure HTTP Strict Transport Security (HSTS) with a minimum 1-year max-age. Use a valid TLS certificate from a trusted CA.

### [HIGH] Session Cookie Missing HttpOnly Flag
- **Category:** WSTG-SESS-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/login.php

The PHPSESSID session cookie is set without the HttpOnly flag. This allows client-side JavaScript to access the session cookie via document.cookie, enabling session token theft via Cross-Site Scripting (XSS) attacks. An attacker exploiting an XSS vulnerability could steal the session cookie and hijack authenticated sessions.

**Remediation:** Set HttpOnly flag on all session cookies (session.cookie_httponly = 1 in php.ini). Also set the Secure flag once HTTPS is implemented (FINDING-003). CHAINING NOTE: This finding chains with FINDING-003 (No HTTPS): without HTTPS, the PHPSESSID session cookie is visible to any network observer; without HttpOnly, it is also accessible to client-side JavaScript via XSS. Together these create a dual session-theft attack surface — fix both to break the chain. Priority: Implement HTTPS (FINDING-003) first, then enforce Secure+HttpOnly cookie flags.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-northeast-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-northeast-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-northeast-3:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-south-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-southeast-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-southeast-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ca-central-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-central-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-north-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-west-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-west-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-west-3:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:sa-east-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-east-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-east-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-west-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-west-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] EBS volume is encrypted
- **Category:** ec2_ebs_volume_encryption
- **Resource:** arn:aws:ec2:us-east-1:760689105616:volume/vol-0dd3edf557765d016

**EBS volumes** are assessed for **encryption at rest** using **AWS KMS**.

The finding identifies volumes whose `encrypted` state is disabled, meaning data is stored unencrypted on block storage.

**Remediation:** Encrypt all EBS volumes and enable `encryption by default` for new volumes and snapshot copies.

Apply **least privilege** to KMS keys, restrict snapshot sharing, and enforce **defense in depth** with policies and templates that prevent creation of unencrypted storage.

### [HIGH] EBS volume is encrypted
- **Category:** ec2_ebs_volume_encryption
- **Resource:** arn:aws:ec2:us-east-2:760689105616:volume/vol-009b3842ab0bb2079

**EBS volumes** are assessed for **encryption at rest** using **AWS KMS**.

The finding identifies volumes whose `encrypted` state is disabled, meaning data is stored unencrypted on block storage.

**Remediation:** Encrypt all EBS volumes and enable `encryption by default` for new volumes and snapshot copies.

Apply **least privilege** to KMS keys, restrict snapshot sharing, and enforce **defense in depth** with policies and templates that prevent creation of unencrypted storage.

### [HIGH] IMDSv2 is required by default for EC2 instances at the account level
- **Category:** ec2_instance_account_imdsv2_enabled
- **Resource:** arn:aws:ec2:us-east-2:760689105616:account

**EC2 account IMDS defaults** with `http_tokens`=`required` ensure new instances in the Region use **IMDSv2** by default and disable IMDSv1. *Existing instances keep their current setting.*

**Remediation:** Enforce **IMDSv2** at the account level in every Region by setting `http_tokens` to `required`. Add guardrails with **SCP/IAM conditions**. Standardize AMIs and launch templates to require tokens, validate workload compatibility, and apply **least privilege** to instance roles for defense in depth. *For containers*, prefer hop limit `2`.

### [HIGH] EC2 instance requires IMDSv2 or has the instance metadata service disabled
- **Category:** ec2_instance_imdsv2_enabled
- **Resource:** arn:aws:ec2:us-east-1:760689105616:instance/i-015e30174e704c766

**EC2 instances** are evaluated for **IMDSv2 enforcement**: metadata endpoint enabled with `http_tokens: required`, or metadata service fully disabled (`http_endpoint: disabled`).

**Remediation:** Apply defense in depth:
- Require **IMDSv2** tokens on all instances (`http_tokens: required`)
- Disable metadata where not needed (`http_endpoint: disabled`)
- Minimize hop limit to `1` when feasible
- Update SDKs/apps for IMDSv2
- Restrict instance profile permissions (least privilege)
- Block metadata access from untrusted workloads

### [HIGH] EC2 instance requires IMDSv2 or has the instance metadata service disabled
- **Category:** ec2_instance_imdsv2_enabled
- **Resource:** arn:aws:ec2:us-east-2:760689105616:instance/i-05fb02cc8e210b567

**EC2 instances** are evaluated for **IMDSv2 enforcement**: metadata endpoint enabled with `http_tokens: required`, or metadata service fully disabled (`http_endpoint: disabled`).

**Remediation:** Apply defense in depth:
- Require **IMDSv2** tokens on all instances (`http_tokens: required`)
- Disable metadata where not needed (`http_endpoint: disabled`)
- Minimize hop limit to `1` when feasible
- Update SDKs/apps for IMDSv2
- Restrict instance profile permissions (least privilege)
- Block metadata access from untrusted workloads

### [HIGH] Network ACL does not allow ingress from 0.0.0.0/0 to any port
- **Category:** ec2_networkacl_allow_ingress_any_port
- **Resource:** arn:aws:ec2:us-east-1:760689105616:network-acl/acl-0394c0b0123ced9aa

**VPC network ACLs** with **inbound entries** that permit traffic from `0.0.0.0/0` to any port (any protocol) are identified at the subnet boundary.

**Remediation:** Adopt a **deny-by-default** NACL posture: block `0.0.0.0/0` and allow only required ports from trusted CIDRs. Apply **least privilege** using security groups for fine-grained access, with NACLs as coarse stateless filters. Review and prune rules regularly, and employ **defense in depth** with monitoring and alerting.

### [HIGH] Network ACL does not allow ingress from 0.0.0.0/0 to any port
- **Category:** ec2_networkacl_allow_ingress_any_port
- **Resource:** arn:aws:ec2:us-east-2:760689105616:network-acl/acl-0f4a0905d0267aff1

**VPC network ACLs** with **inbound entries** that permit traffic from `0.0.0.0/0` to any port (any protocol) are identified at the subnet boundary.

**Remediation:** Adopt a **deny-by-default** NACL posture: block `0.0.0.0/0` and allow only required ports from trusted CIDRs. Apply **least privilege** using security groups for fine-grained access, with NACLs as coarse stateless filters. Review and prune rules regularly, and employ **defense in depth** with monitoring and alerting.

### [HIGH] Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)
- **Category:** ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22
- **Resource:** arn:aws:ec2:us-east-1:760689105616:security-group/sg-0d1a54870164827f1

**EC2 security groups** are assessed for **inbound SSH exposure** by locating ingress rules that allow `TCP 22` from the Internet (`0.0.0.0/0` or `::/0`).

Only groups in use are considered; sets already flagged for all-port exposure are not repeated.

**Remediation:** Apply **least privilege** to SSH:
- Disallow `0.0.0.0/0` and `::/0`; allow only trusted IPs or VPN ranges
- Prefer **private access** via bastion hosts or AWS Systems Manager Session Manager
- Enforce **key-based auth**, disable passwords, rotate keys
- Add **network segmentation** and monitoring for **defense in depth**

### [HIGH] Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)
- **Category:** ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22
- **Resource:** arn:aws:ec2:us-east-2:760689105616:security-group/sg-009fdda81d0780e3d

**EC2 security groups** are assessed for **inbound SSH exposure** by locating ingress rules that allow `TCP 22` from the Internet (`0.0.0.0/0` or `::/0`).

Only groups in use are considered; sets already flagged for all-port exposure are not repeated.

**Remediation:** Apply **least privilege** to SSH:
- Disallow `0.0.0.0/0` and `::/0`; allow only trusted IPs or VPN ranges
- Prefer **private access** via bastion hosts or AWS Systems Manager Session Manager
- Enforce **key-based auth**, disable passwords, rotate keys
- Add **network segmentation** and monitoring for **defense in depth**

### [HIGH] AWS account root user has not been used in the last day
- **Category:** iam_avoid_root_usage
- **Resource:** arn:aws:iam::760689105616:root

**AWS IAM root user** activity is assessed by inspecting `last-used` timestamps for the root password and access keys. The finding indicates when the root identity has been used recently for console or programmatic access.

**Remediation:** Minimize `root` usage by applying **least privilege** with admin roles or federated SSO and temporary credentials.
- Enforce **MFA** on root
- Avoid or remove root access keys
- Require multi-person approval
- **Monitor and alert** on any root sign-in
- Use org guardrails for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ap-northeast-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ap-northeast-2:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ap-northeast-3:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ap-south-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ap-southeast-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ap-southeast-2:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:ca-central-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:eu-central-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:eu-north-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:eu-west-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:eu-west-2:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:eu-west-3:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:sa-east-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:us-east-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:us-east-2:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:us-west-1:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Security Hub is enabled with standards or integrations configured
- **Category:** securityhub_enabled
- **Resource:** arn:aws:securityhub:us-west-2:760689105616:hub/unknown

**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.

**Remediation:** - Enable in all required accounts/Regions
- Turn on relevant **standards** (`AWS FSBP`, `CIS`)
- Connect AWS and third-party **integrations**
- Use **central configuration** and **least privilege**
- Automate triage and monitor continuously for **defense in depth**

### [HIGH] Application Configuration File Publicly Accessible (/config/config.inc.php)
- **Category:** WSTG-CONF-04
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/config/config.inc.php

The file /config/config.inc.php is publicly accessible over HTTP without authentication (HTTP 200). The file contains repeated AWS credential placeholder comments (# aws_access_key_id = AKIA&lt;YOUR_KEY_ID_HERE&gt; / # aws_secret_access_key = &lt;YOUR_SECRET_HERE&gt;) and an EOFaws heredoc terminator, indicating this file is the designated location for real AWS credentials in deployment. While the current deployment uses placeholders, the file is entirely unprotected by Apache access controls, meaning any real credentials placed here would be immediately exfiltrated. Additionally, .gitignore (HTTP 200) is publicly accessible and reveals internal path structure. Cross-referenced with WSTG-CONF-04 and WSTG-CONF-09 (consolidated finding — same root cause and URL).

**Remediation:** 1. Deny HTTP access to /config/ directory via Apache .htaccess or server config: Deny from all. 2. Remove /config/config.inc.php from the web root entirely — config files should not be in the document root. 3. Remove .gitignore from the web root. 4. Audit all files in the document root for inadvertent information disclosure. 5. Ensure real AWS credentials are never placed in web-accessible files; use IAM instance roles or AWS Secrets Manager instead.

### [HIGH] Unauthenticated Access to Administrative Setup Page (setup.php)
- **Category:** WSTG-ATHZ-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/setup.php

The DVWA setup page (setup.php) is accessible without authentication. This page exposes sensitive server configuration details including: PHP version (7.0.30-0+deb9u1), database backend (MySQL), database name (dvwa), database host (127.0.0.1), database username (app), operating system (*nix), and web server hostname. The page also reveals whether URL inclusion is enabled and provides a "Create / Reset Database" button that would allow an unauthenticated attacker to reset the entire application database including admin credentials. The authorization check that protects all other DVWA pages does not apply to setup.php. Additionally, about.php and instructions.php are accessible without authentication, though these expose lower-risk information.

**Remediation:** Enforce authentication checks on setup.php consistent with all other authenticated pages. Move setup functionality behind admin-level access controls. Consider removing or disabling setup.php entirely in production deployments. The page should check for a valid authenticated session before rendering any content or accepting POST requests.

### [HIGH] Security Level Bypass via Client-Controlled Cookie (security=low)
- **Category:** WSTG-ATHZ-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/security.php

DVWA's security level (low/medium/high/impossible) is stored in a client-controlled cookie named "security" rather than server-side session state. Any authenticated user can freely modify this cookie value to change the application's security posture without server-side validation. This means:
1. An admin who sets security=high (intending to restrict exploitation) can have their setting overridden by any authenticated user simply setting security=low in their browser.
2. The security cookie is trusted entirely client-side — the server applies whichever level the client presents.

Proof: With the same valid session (PHPSESSID), changing the security cookie from "low" to "high" changes which SQL injection code path executes. Setting it back to "low" immediately re-enables the vulnerable code path, confirming the server applies no independent server-side security level per session.

This means all security hardening intended by the administrator can be trivially bypassed by any authenticated user, rendering the "high" and "impossible" security levels ineffective as access controls.

**Remediation:** Store the security level in server-side session state rather than a client-controlled cookie. The security level should be set once by an administrator and stored in the PHP session ($_SESSION['security']), not read from $_COOKIE['security'] on each request. Users should not be able to influence their own security level.

### [HIGH] Session Fixation - PHPSESSID Not Rotated After Authentication
- **Category:** WSTG-SESS-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/login.php

DVWA does not issue a new session identifier upon successful user authentication. The PHPSESSID assigned before login remains unchanged after the user authenticates, enabling session fixation attacks. An attacker who can fix a victim's session token (e.g., via a URL parameter if trans_sid were enabled, or via subdomain cookie injection) would be able to hijack the authenticated session without knowing the victim's credentials.

Evidence: Pre-login PHPSESSID `0hd80hcaic4514t1kcbm1q32f2` remained identical post-login (cookie jar comparison). The server issued a 302 redirect to index.php on successful login but did NOT issue a new Set-Cookie: PHPSESSID header, confirming the session ID was reused.

**Remediation:** Call session_regenerate_id(true) immediately after successful authentication in login.php. The 'true' parameter deletes the old session file. Example: if (valid_credentials) { session_regenerate_id(true); $_SESSION['user'] = $username; }

### [HIGH] Multiple Default/Weak Credentials Active on All DVWA User Accounts
- **Category:** WSTG-ATHN-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/login.php

All five DVWA user accounts use well-known default or trivially weak passwords that are publicly documented. All credentials were verified as valid: gordonb/abc123, 1337/charley, pablo/letmein, smithy/password (admin password also confirmed working). These credentials are the factory defaults for DVWA and are known to any attacker familiar with the platform. The admin account username is "Admin" (capital A) while the login form is case-sensitive.

**Remediation:** Change all default passwords to strong, unique passwords. Implement a password policy enforcing minimum length (12+ chars), complexity, and preventing use of well-known default passwords. Disable or remove demo/test accounts not needed in production.

### [HIGH] Cross-Site Request Forgery (CSRF) on Password Change Endpoint
- **Category:** WSTG-SESS-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/csrf/

The password change functionality at /vulnerabilities/csrf/ accepts GET requests with no CSRF token validation. An authenticated user can have their password changed by visiting a malicious link or loading a page containing a crafted URL. No CSRF token, Referer check, or any anti-forgery mechanism is present. Additionally, the form does not require the current/old password before accepting a new one, making account takeover trivial — an attacker with a valid session (e.g., via session hijacking or XSS) can change the password without knowing the original. Password change was confirmed successful via direct unauthenticated GET request with only session cookie. This vulnerability was also confirmed under WSTG-ATHN-09.

**Remediation:** 1. Switch the form method from GET to POST to prevent URL-based attacks. 2. Implement synchronizer token pattern: generate a per-session CSRF token, embed it in the form as a hidden field, validate it server-side on every state-changing request. 3. Consider adding SameSite=Strict to session cookies to block cross-site requests. 4. Require the current password to be entered when changing the password (defense-in-depth).

### [HIGH] Password Change Function Has No CSRF Protection and No Current Password Verification
- **Category:** WSTG-ATHN-09
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/csrf/

The password change functionality at /vulnerabilities/csrf/ uses the HTTP GET method and requires no CSRF token. An authenticated user's password can be changed by any webpage they visit while logged in — a classic CSRF attack. Additionally, the form does not require the user's current password to be entered before setting a new one, making account takeover trivial once CSRF is exploited. The change was confirmed successful via direct GET request with only the new password parameters.

**Remediation:** 1. Change password change functionality to use POST method. 2. Implement a synchronizer CSRF token on the form. 3. Require the user's current password before accepting a new password. 4. Implement SameSite=Strict or SameSite=Lax on session cookies. Note: This is an intentional vulnerability in DVWA for training purposes.

### [INFO] AWS Instance Metadata Service (IMDS) Accessible — SSRF Impact Amplified
- **Category:** WSTG-CONF-11
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com

The target is running on AWS EC2. The AWS Instance Metadata Service (IMDSv1) at http://169.254.169.254/latest/meta-data/ is not directly reachable from the testing tool container (timeout), which is expected since it is a link-local address only accessible from within the EC2 instance itself. However, this is highly relevant to SSRF testing in Phase 4: any Server-Side Request Forgery vulnerability in the application would allow an attacker to query the IMDS endpoint and potentially retrieve: IAM role credentials (access key, secret key, session token), instance identity documents, AMI IDs, security group information, and other sensitive metadata. No real AWS credentials were observed in phpinfo.php environment variables or in /config/config.inc.php (only placeholder comments). No S3 bucket references were found in page source or JavaScript files.

**Remediation:** 1. Enforce IMDSv2 (token-required mode) on the EC2 instance to prevent SSRF-based credential theft: aws ec2 modify-instance-metadata-options --instance-id i-xxxx --http-tokens required --http-endpoint enabled. 2. Restrict the IAM instance role to minimum required permissions. 3. Monitor CloudTrail for unexpected metadata service calls. 4. When Phase 4 SSRF testing occurs, prioritize testing http://169.254.169.254/latest/meta-data/iam/security-credentials/ as the primary SSRF target to assess real credential exposure risk.

### [INFO] Security Level Controlled Entirely by Client-Supplied Cookie (security= cookie trusted without server-side validation)
- **Category:** WSTG-SESS-11
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/security.php

DUPLICATE — consolidated into FINDING-016. Both FINDING-016 (WSTG-ATHZ-03) and this finding (WSTG-SESS-11) document the same root cause: the `security` cookie is trusted client-side without server-side validation, allowing any authenticated user to set any security level. See FINDING-016 for full evidence and remediation.

**Remediation:** Store the security level server-side in the PHP session ($_SESSION['security_level']) rather than reading it from a client cookie. Never trust client-supplied security configuration parameters. The security level should only be changeable by an authenticated administrator via a verified server-side mechanism.

### [LOW] Directory Listing Enabled on Multiple Directories
- **Category:** WSTG-CONF-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/hackable/

Apache directory listing (autoindex) is enabled on multiple directories, exposing the directory tree structure and file contents to any user. Exposed directories include /hackable/, /hackable/uploads/, /hackable/users/, /hackable/flags/, and /docs/. The /hackable/users/ directory contains user avatar images that reveal valid usernames (admin, gordonb, pablo, smithy, 1337). The /hackable/flags/ directory contains fi.php used by the file inclusion challenge.

**Remediation:** Disable Apache autoindex for all directories by adding "Options -Indexes" in the Apache configuration or .htaccess files. Alternatively, place an index.html in each directory to prevent directory listing.

### [LOW] Shell Script Output Leaked in All HTTP Responses
- **Category:** WSTG-INFO-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

Every HTTP response from the application includes commented-out shell script content containing AWS credential placeholder comments and an "EOFaws" heredoc terminator. This content appears at the start of every response body, before the HTML. This indicates a shell script (likely part of the Docker/deployment setup) is being included or executed and its stdout is being captured into the PHP output buffer. While the credentials shown are placeholders (AKIA&lt;YOUR_KEY_ID_HERE&gt;), this reveals deployment implementation details and indicates a misconfigured initialization script.

**Remediation:** Investigate and remove the shell script or initialization code that outputs this content. Remove any scripts that capture and include shell heredoc output in PHP responses. Ensure no deployment scripts are included in the PHP execution path.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-northeast-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-northeast-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-northeast-3:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-south-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-southeast-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-southeast-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ca-central-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-central-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-north-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-west-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-west-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-west-3:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:sa-east-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-east-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-east-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-west-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-west-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM SAML provider exists in the account
- **Category:** iam_check_saml_providers_sts
- **Resource:** arn:aws:iam::760689105616:root

**IAM SAML providers** enable **federated role assumption** via STS `AssumeRoleWithSAML`.

This evaluates whether such providers exist in the account.

**Remediation:** Adopt **SAML federation** to issue **short-lived STS credentials**. Map users to roles with **least privilege**, enforce **MFA** at the IdP, and set conservative session durations. Retire IAM user access keys for interactive use and monitor role sessions as **defense in depth**. *If federation isn't possible*, tightly scope, rotate, and audit keys.

### [LOW] At least one IAM role has the AWSSupportAccess managed policy attached
- **Category:** iam_support_role_created
- **Resource:** arn:aws:iam::aws:policy/AWSSupportAccess

Presence of an **IAM role** that has the AWS managed `AWSSupportAccess` policy attached, designating a support role for interacting with **AWS Support Center** and related tooling.

**Remediation:** Create a dedicated IAM role for AWS Support with `AWSSupportAccess` and:
- Restrict who can assume it; require MFA and time-bound access
- Enforce **least privilege** and **separation of duties**
- Monitor usage via audit logs and review assignments regularly

### [LOW] Multiple Security Headers Missing (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- **Category:** WSTG-CONF-14
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

The application does not set any of the recommended HTTP security response headers on its pages. The following headers are entirely absent across all tested pages (/login.php, /index.php, /):

- X-Frame-Options: Missing — allows the application to be embedded in iframes, enabling clickjacking attacks (no frame-ancestors CSP either).
- X-Content-Type-Options: nosniff — Missing — allows MIME-type sniffing which can lead to content injection (e.g., serving a JS file as image/gif and having the browser execute it).
- X-XSS-Protection: Missing — legacy IE/Chrome header, absence is low risk on modern browsers but indicates no security header hygiene.
- Referrer-Policy: Missing — full URL referrer leaked to third parties on navigation, which can expose session context in URLs.
- Permissions-Policy (Feature-Policy): Missing — no restrictions on browser feature access (camera, microphone, geolocation).
- Strict-Transport-Security: N/A — site runs on HTTP only (no HTTPS), so HSTS cannot be set (already logged as FINDING-003).
- Content-Security-Policy: Absent (logged separately as FINDING-013).

The most impactful missing headers in this context are X-Frame-Options (clickjacking) and X-Content-Type-Options (MIME sniffing).

**Remediation:** Add the following headers to Apache configuration (httpd.conf or .htaccess):
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Additionally, enable mod_headers in Apache and ensure the Header directive is in a context that applies to all responses. Long-term, migrate to HTTPS and add Strict-Transport-Security with includeSubDomains and preload.

### [MEDIUM] phpinfo.php Publicly Accessible
- **Category:** WSTG-CONF-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/phpinfo.php

The PHP information page (phpinfo.php) is publicly accessible to authenticated users without restriction. This page reveals sensitive server configuration details including PHP version (7.0.30-0+deb9u1), installed extensions, environment variables, server paths, and system details (Linux Amazon Linux 2023 kernel). phpinfo.php is intended for debugging only and should never be accessible in production.

**Remediation:** Remove or restrict access to phpinfo.php. If required for debugging, restrict access by IP address via Apache configuration or remove the file entirely from production deployments.

### [MEDIUM] Verbose Server Error Messages Reveal Database Type and Version
- **Category:** WSTG-INFO-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/sqli/

The application returns verbose database error messages that expose the underlying database technology. When a SQL injection probe is submitted to the /vulnerabilities/sqli/ endpoint, the response reveals that the database is MariaDB and includes the exact SQL syntax error. Additionally, 404 error pages expose the Apache version and operating system. This information aids attackers in crafting targeted exploits.

**Remediation:** Configure PHP to suppress database error messages in production (display_errors = Off, log_errors = On). Implement custom error pages that do not reveal server internals. Use PDO exceptions and catch them to display generic error messages.

### [MEDIUM] CloudWatch log metric filter and alarm exist for Network ACL (NACL) change events
- **Category:** cloudwatch_changes_to_network_acls_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudTrail records for **Network ACL changes** are matched by a CloudWatch Logs metric filter with an associated alarm for events like `CreateNetworkAcl`, `CreateNetworkAclEntry`, `DeleteNetworkAcl`, `DeleteNetworkAclEntry`, `ReplaceNetworkAclEntry`, and `ReplaceNetworkAclAssociation`.

**Remediation:** Implement a CloudWatch Logs metric filter and alarm for NACL change events from CloudTrail and route alerts to responders. Enforce **least privilege** on NACL management, require **change control**, and use **defense in depth** with configuration monitoring and flow logs to validate and monitor network posture.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for changes to network gateways
- **Category:** cloudwatch_changes_to_network_gateways_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudWatch log metric filters and alarms for **network gateway changes** are identified by matching CloudTrail events such as `CreateCustomerGateway`, `DeleteCustomerGateway`, `AttachInternetGateway`, `CreateInternetGateway`, `DeleteInternetGateway`, and `DetachInternetGateway` in log groups that receive trail logs.

**Remediation:** Send CloudTrail to CloudWatch Logs and create a metric filter for the listed gateway events with an alarm that notifies responders. Enforce **least privilege** for gateway modifications, require change approvals, and route alerts to monitored channels as part of **defense in depth**.

### [MEDIUM] Account monitors VPC route table changes with a CloudWatch Logs metric filter and alarm
- **Category:** cloudwatch_changes_to_network_route_tables_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**VPC route table changes** are captured from **CloudTrail logs** by a **CloudWatch Logs metric filter** with an associated **alarm** for events like `CreateRoute`, `CreateRouteTable`, `ReplaceRoute`, `ReplaceRouteTableAssociation`, `DeleteRoute`, `DeleteRouteTable`, and `DisassociateRouteTable`.

**Remediation:** Implement a **CloudWatch Logs metric filter and alarm** on CloudTrail for these route table events and notify responders. Enforce **least privilege** for route modifications, require **change control**, and apply **defense in depth** with VPC Flow Logs and guardrails to prevent and quickly contain unsafe routing changes.

### [MEDIUM] AWS account has a CloudWatch Logs metric filter and alarm for VPC changes
- **Category:** cloudwatch_changes_to_vpcs_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail events** for **VPC configuration changes** are captured in CloudWatch Logs with a metric filter and an associated alarm. The filter targets actions like `CreateVpc`, `DeleteVpc`, `ModifyVpcAttribute`, and VPC peering operations to surface when network topology is altered.

**Remediation:** Create a CloudWatch Logs metric filter and alarm on CloudTrail for critical **VPC change events**, and notify responders. Apply **least privilege** to network changes, require change approvals, and use **defense in depth** (segmentation, route controls) to prevent and contain unauthorized modifications.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for AWS Config configuration changes
- **Category:** cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudTrail logs in **CloudWatch Logs** are inspected for a metric filter and alarm that track **AWS Config configuration changes**, specifically `StopConfigurationRecorder`, `DeleteDeliveryChannel`, `PutDeliveryChannel`, and `PutConfigurationRecorder` events from `config.amazonaws.com`.

**Remediation:** Create a **CloudWatch Logs metric filter and alarm** for `config.amazonaws.com` events (`StopConfigurationRecorder`, `DeleteDeliveryChannel`, `PutDeliveryChannel`, `PutConfigurationRecorder`). Route CloudTrail to Logs, notify responders, and enforce **least privilege** and **separation of duties** on Config changes to prevent abuse.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for CloudTrail configuration changes
- **Category:** cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail logs** include a **metric filter** for trail configuration events (`CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, `StopLogging`) with an associated **CloudWatch alarm** to alert on matches.

Evaluates the presence of this filter-and-alarm monitoring.

**Remediation:** Implement a **metric filter** for trail configuration events and a linked **alarm** that notifies response channels.

Apply **least privilege** and **separation of duties** for trail changes, add **defense in depth** with centralized logging and validation, and regularly test that alerts fire.

### [MEDIUM] Account has a CloudWatch Logs metric filter and alarm for AWS Management Console authentication failures
- **Category:** cloudwatch_log_metric_filter_authentication_failures
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudWatch Logs metric filter and alarm for **AWS Management Console authentication failures**, sourced from CloudTrail (`eventName=ConsoleLogin`, `errorMessage="Failed authentication"`).

Identifies whether these failures are converted into a metric and actively monitored by an alarm.

**Remediation:** Implement a log metric filter for `ConsoleLogin` failures and attach a **CloudWatch alarm** with actionable notifications. Tune thresholds to reduce noise and route alerts to incident response.

Apply **least privilege** and enforce **MFA** to limit impact, and correlate alerts with source IP and user context.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for AWS Organizations changes
- **Category:** cloudwatch_log_metric_filter_aws_organizations_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudWatch Logs** metric filters and alarms monitor **AWS Organizations** change events recorded by CloudTrail, including actions like `CreateAccount`, `AttachPolicy`, `MoveAccount`, and `UpdateOrganizationalUnit`.

The evaluation looks for a filter on the trail log group matching `organizations.amazonaws.com` events and an alarm linked to that metric.

**Remediation:** Send CloudTrail events to **CloudWatch Logs**, add a metric filter for `organizations.amazonaws.com` change events, and attach an alarm that notifies responders. Enforce **least privilege** and **separation of duties** for org admins, require MFA and approvals, and regularly test alerts to ensure timely detection and response.

### [MEDIUM] Account has a CloudWatch log metric filter and alarm for disabling or scheduled deletion of customer-managed KMS keys
- **Category:** cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudTrail events delivered to CloudWatch are evaluated for a **metric filter and alarm** that monitor **KMS CMK state changes**, specifically `DisableKey` and `ScheduleKeyDeletion` from `kms.amazonaws.com`.

**Remediation:** Establish **CloudWatch metric filters and alarms** for `DisableKey` and `ScheduleKeyDeletion` CloudTrail events to enable rapid response.
- Apply **least privilege** to KMS administration
- Enforce **change control** and separation of duties
- Use deletion waiting periods and monitor all regions

### [MEDIUM] CloudWatch log metric filter and alarm exist for S3 bucket policy changes
- **Category:** cloudwatch_log_metric_filter_for_s3_bucket_policy_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail** logs are assessed for a **CloudWatch metric filter** matching S3 bucket configuration changes (ACL, policy, CORS, lifecycle, replication; e.g., `PutBucketPolicy`, `DeleteBucketPolicy`) and for an associated **CloudWatch alarm**.

**Remediation:** Establish and maintain **metric filters** and **alarms** for S3 bucket policy, ACL, CORS, lifecycle, and replication changes. Route alerts to monitored channels and integrate with SIEM. Enforce **least privilege**, require change reviews, and use **defense in depth** to prevent and quickly detect unsafe bucket policy changes.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for IAM policy changes
- **Category:** cloudwatch_log_metric_filter_policy_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudWatch uses a metric filter and alarm to track **IAM policy changes** recorded by CloudTrail (e.g., `CreatePolicy`, `DeletePolicy`, version changes, inline policy edits, policy attach/detach). This finding reflects whether that filter and an associated alarm are present on the trail's log group.

**Remediation:** Create a metric filter for IAM policy create/update/delete and attach/detach events with an **alarm** to notify responders.
- Enforce **least privilege** and separation of duties for policy changes
- Require approvals and central logging across Regions/accounts
- Integrate alerts with incident response

### [MEDIUM] Account has a CloudWatch Logs metric filter and alarm for root account usage
- **Category:** cloudwatch_log_metric_filter_root_usage
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail** logs in CloudWatch include a metric filter for **root account activity** (`{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`) and a linked CloudWatch alarm that triggers when the filter matches.

**Remediation:** Enable real-time alerts for **root activity** using a log metric filter and a high-priority alarm with notifications.

Reduce exposure: enforce **least privilege**, keep root for *break-glass* with MFA, disable root access keys, and route alerts into incident response for **defense in depth**.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for security group changes
- **Category:** cloudwatch_log_metric_filter_security_group_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail** events for **security group configuration changes** are monitored using a **CloudWatch Logs metric filter** with an associated **alarm**. The filter targets actions like `AuthorizeSecurityGroupIngress/Egress`, `RevokeSecurityGroupIngress/Egress`, `CreateSecurityGroup`, and `DeleteSecurityGroup` to surface any security group modifications.

**Remediation:** Establish real-time alerts for **security group modifications** by sending CloudTrail to CloudWatch, creating metric filters and alarms, and notifying responders.
- Enforce **least privilege** on SG changes
- Use change management and tagging
- Centralize logs, test alarms, and maintain runbooks
- Layer with NACLs and WAF for **defense in depth**

### [MEDIUM] CloudWatch log metric filter and alarm exist for Management Console sign-in without MFA
- **Category:** cloudwatch_log_metric_filter_sign_in_without_mfa
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail logs** in CloudWatch are assessed for a metric filter and alarm that detect console logins where `$.eventName = ConsoleLogin` and `$.additionalEventData.MFAUsed != \"Yes\"`.

This reflects whether alerting exists for sign-ins that occur without **MFA**.

**Remediation:** Enforce **MFA** for all console-capable identities and maintain alerts for `ConsoleLogin` with `MFAUsed != \"Yes\"`.

Apply **least privilege**, route alarms to monitored channels, and tune for SSO to reduce noise. Test alarms regularly and review coverage as part of **defense in depth**.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for unauthorized API calls
- **Category:** cloudwatch_log_metric_filter_unauthorized_api_calls
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudWatch Logs** for CloudTrail include a metric filter that matches unauthorized API errors (`$.errorCode="*UnauthorizedOperation"` or `$.errorCode="AccessDenied*"`) and a linked alarm that triggers when events match the filter.

**Remediation:** Enable real-time **alerting** by adding a CloudWatch Logs metric filter for unauthorized errors (`*UnauthorizedOperation`, `AccessDenied*`) and associating it with an alarm that notifies responders.
- Enforce **least privilege** to reduce noise
- Integrate with IR tooling for **defense in depth**

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-northeast-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-northeast-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-northeast-3:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-south-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-southeast-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-southeast-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ca-central-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-central-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-north-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-west-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-west-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-west-3:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:sa-east-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-east-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-east-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-west-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-west-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] Network ACL does not allow ingress from the Internet to TCP port 22 (SSH)
- **Category:** ec2_networkacl_allow_ingress_tcp_port_22
- **Resource:** arn:aws:ec2:us-east-1:760689105616:network-acl/acl-0394c0b0123ced9aa

**VPC network ACLs** are evaluated for inbound rules that permit `0.0.0.0/0` to access **SSH** on `TCP 22` at the subnet boundary.

**Remediation:** Apply **least privilege** at the subnet layer:
- Do not allow `0.0.0.0/0` to `TCP 22`
- Restrict SSH to trusted sources, or avoid direct SSH via **Session Manager** or a bastion behind **VPN**

Pair tight **security groups** with periodic rule reviews and change control to maintain **defense in depth**.

### [MEDIUM] Network ACL does not allow ingress from the Internet to TCP port 22 (SSH)
- **Category:** ec2_networkacl_allow_ingress_tcp_port_22
- **Resource:** arn:aws:ec2:us-east-2:760689105616:network-acl/acl-0f4a0905d0267aff1

**VPC network ACLs** are evaluated for inbound rules that permit `0.0.0.0/0` to access **SSH** on `TCP 22` at the subnet boundary.

**Remediation:** Apply **least privilege** at the subnet layer:
- Do not allow `0.0.0.0/0` to `TCP 22`
- Restrict SSH to trusted sources, or avoid direct SSH via **Session Manager** or a bastion behind **VPN**

Pair tight **security groups** with periodic rule reviews and change control to maintain **defense in depth**.

### [MEDIUM] Network ACL does not allow ingress from the Internet to TCP port 3389 (RDP)
- **Category:** ec2_networkacl_allow_ingress_tcp_port_3389
- **Resource:** arn:aws:ec2:us-east-1:760689105616:network-acl/acl-0394c0b0123ced9aa

**VPC network ACLs** with inbound rules allowing **RDP** on `TCP 3389` from `0.0.0.0/0` are identified.

Assessment focuses on subnet-level ACL entries that permit this traffic.

**Remediation:** Enforce **least privilege**: do not allow `TCP 3389` from `0.0.0.0/0` in network ACLs.

- Restrict RDP to specific admin IP ranges
- Prefer **bastion hosts** or **Session Manager** over direct RDP
- Use private subnets and layer controls for **defense in depth**

### [MEDIUM] Network ACL does not allow ingress from the Internet to TCP port 3389 (RDP)
- **Category:** ec2_networkacl_allow_ingress_tcp_port_3389
- **Resource:** arn:aws:ec2:us-east-2:760689105616:network-acl/acl-0f4a0905d0267aff1

**VPC network ACLs** with inbound rules allowing **RDP** on `TCP 3389` from `0.0.0.0/0` are identified.

Assessment focuses on subnet-level ACL entries that permit this traffic.

**Remediation:** Enforce **least privilege**: do not allow `TCP 3389` from `0.0.0.0/0` in network ACLs.

- Restrict RDP to specific admin IP ranges
- Prefer **bastion hosts** or **Session Manager** over direct RDP
- Use private subnets and layer controls for **defense in depth**

### [MEDIUM] IAM password policy requires passwords to be at least 14 characters long
- **Category:** iam_password_policy_minimum_length_14
- **Resource:** arn:aws:iam:us-east-2:760689105616:password-policy

**IAM password policy** is assessed for the **minimum password length** setting, confirming it meets `>= 14` characters for IAM console users.

**Remediation:** Set the **minimum password length** to `>= 14` (prefer `16+`).
- Require mixed character types and prevent reuse
- Enforce **MFA** for all console users
- Prefer SSO over local IAM users
- Apply least privilege and monitor authentication events

### [MEDIUM] IAM password policy prevents reuse of the last 24 passwords
- **Category:** iam_password_policy_reuse_24
- **Resource:** arn:aws:iam:us-east-2:760689105616:password-policy

**IAM account password policy** uses **password reuse prevention** set to `24` remembered passwords (maximum history) for IAM users

**Remediation:** Set the password policy to remember `24` previous passwords to block reuse. Combine with **MFA**, strong length and complexity, and avoid rotation practices that encourage predictable patterns. Apply **least privilege** and monitor authentication events as part of **defense in depth**.

### [MEDIUM] VPC flow logs are enabled
- **Category:** vpc_flow_logs_enabled
- **Resource:** arn:aws:ec2:us-east-1:760689105616:vpc/vpc-03d1632e1404b5ec3

**AWS VPCs** have **Flow Logs** configured to capture IP traffic for their network interfaces and deliver records to a logging destination.

VPCs lacking an active flow log configuration are highlighted.

**Remediation:** Enable **VPC Flow Logs** for all VPCs to provide baseline telemetry.
Prefer capturing at least `REJECT` and, for sensitive networks, `ALL`. Send logs to a centralized, access-controlled destination with retention. Apply **least privilege** to writers/readers and integrate with monitoring for **defense in depth**.

### [MEDIUM] VPC flow logs are enabled
- **Category:** vpc_flow_logs_enabled
- **Resource:** arn:aws:ec2:us-east-2:760689105616:vpc/vpc-00eb51332cc39cea6

**AWS VPCs** have **Flow Logs** configured to capture IP traffic for their network interfaces and deliver records to a logging destination.

VPCs lacking an active flow log configuration are highlighted.

**Remediation:** Enable **VPC Flow Logs** for all VPCs to provide baseline telemetry.
Prefer capturing at least `REJECT` and, for sensitive networks, `ALL`. Send logs to a centralized, access-controlled destination with retention. Apply **least privilege** to writers/readers and integrate with monitoring for **defense in depth**.

### [MEDIUM] Sensitive Configuration File Publicly Accessible (/config/config.inc.php)
- **Category:** WSTG-CONF-09
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/config/config.inc.php

The application configuration file /config/config.inc.php is publicly readable over HTTP without authentication. The file contains commented-out AWS credential templates (AKIA key ID and secret access key placeholders). While the current values are placeholders ("YOUR_KEY_ID_HERE"), the file structure confirms this path is intended for storing real AWS credentials, and the file is not protected by Apache access controls or authentication. If real credentials were inserted (or were previously present and cached), they would be fully exposed. The file is served with Content-Type text/html and returns HTTP 200 regardless of authentication status.

**Remediation:** 1. Immediately restrict access to /config/ directory via Apache .htaccess or main config: Deny from all / Require all denied. 2. Remove any real credentials from this file if they were ever present. 3. Move configuration files outside the webroot entirely (above the DocumentRoot). 4. Use environment variables or a secrets manager (AWS Secrets Manager, Parameter Store) for AWS credentials instead of flat files. 5. Audit git history to verify real credentials were never committed.

### [MEDIUM] DVWA Setup Page Exposes Default Credentials and Internal Paths
- **Category:** WSTG-CONF-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/setup.php

The DVWA setup page at /setup.php is accessible without restriction (HTTP 200) and discloses: (1) Default administrator credentials ("admin" // "password"), (2) The full filesystem path to the config file (/var/www/html/config/config.inc.php), (3) Whether the config directory is writable by the web server (Yes - www-data), (4) The database password (masked as ******). Additionally, Apache's server-status page (/server-status) returns HTTP 403 with the server version in the error page footer ("Apache/2.4.25 (Debian) Server at... Port 80"). The server version Apache/2.4.25 is significantly outdated (released 2017) and has known vulnerabilities. No /server-info page was found (404).

**Remediation:** 1. Restrict access to /setup.php via IP allowlist or authentication, or remove it from production. 2. Upgrade Apache from 2.4.25 to current stable version (2.4.62+) — version 2.4.25 has multiple known CVEs. 3. Configure Apache ServerTokens to 'Prod' to suppress version disclosure. 4. Ensure the config directory is not world-writable by the web server.

### [MEDIUM] Outdated Apache Web Server Version Disclosed (Apache/2.4.25 Debian)
- **Category:** WSTG-CONF-01
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

The server discloses its exact version in the Server response header on every HTTP response: "Apache/2.4.25 (Debian)". Apache 2.4.25 was released in December 2016 and has numerous known CVEs. Open ports per nmap: TCP/22 (SSH - OpenSSH 8.7), TCP/80 (HTTP - Apache 2.4.25). Ports 443, 3306, 8080, 8443, 21 are filtered. The SSH service (OpenSSH 8.7) is also accessible, representing an additional attack surface if weak credentials are in use. No reverse proxy or CDN headers detected (no Via, CF-RAY, X-Cache, etc.).

**Remediation:** 1. Upgrade Apache to the current stable release (2.4.62+). 2. Set ServerTokens to 'Prod' in Apache config to suppress version info from headers. 3. Set ServerSignature to 'Off' to suppress version from error pages. 4. Apply all Debian security patches for the installed Apache version. 5. Consider restricting SSH access (port 22) to known IP ranges.

### [MEDIUM] Content Security Policy Missing or Critically Weak Across Application
- **Category:** WSTG-CONF-12
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

No Content-Security-Policy header is present on any standard application page (/login.php, /index.php, /). The only CSP present is on /vulnerabilities/csp/ (an intentional DVWA challenge page), and that CSP is itself critically weak: it allows scripts from external domains including pastebin.com and the bare domain example.com (without HTTPS). The absence of CSP across the application means there is no browser-enforced mitigation against XSS attacks. Any reflected or stored XSS payload (which DVWA is intentionally vulnerable to) will execute without browser-level defense. This is especially significant given that FINDING-004 confirmed the session cookie lacks HttpOnly, making XSS-to-session-theft a complete attack chain.

**Remediation:** 1. Implement a Content-Security-Policy header on all application pages, starting with a restrictive default: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'. 2. Remove external domains from script-src unless strictly necessary. 3. Never allow pastebin.com or other user-content-hosting domains in script-src. 4. Use CSP nonces or hashes instead of 'unsafe-inline' for any inline scripts required. 5. Test CSP coverage using a CSP evaluator tool before deployment.

### [MEDIUM] Insecure Direct Object Reference — User Data Accessible by Arbitrary ID
- **Category:** WSTG-ATHZ-04
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/sqli/

The SQL Injection vulnerability module at /vulnerabilities/sqli/ exposes all application user records via an IDOR vulnerability. Any authenticated user can retrieve the first name and surname of any other user account by manipulating the "id" GET parameter. No authorization check verifies that the requesting user owns the requested record. All 5 user accounts (IDs 1-5) were enumerated successfully, including the admin account (ID=1). While this specific endpoint is the SQL Injection demonstration module in DVWA, the IDOR pattern demonstrates the absence of object-level authorization throughout the application.

Users exposed: admin/admin (ID 1), Gordon Brown (ID 2), Hack Me (ID 3), Pablo Picasso (ID 4), Bob Smith (ID 5).

**Remediation:** Implement object-level authorization checks: verify that the authenticated user has permission to access the requested record before returning data. For user-specific data, confirm that the session user ID matches the requested object ID (or the user has an admin role). Use parameterized queries and enforce row-level access controls at the database or application layer.

### [MEDIUM] No Account Lockout Mechanism on Login Form
- **Category:** WSTG-ATHN-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/login.php

The DVWA login form does not implement any account lockout, rate limiting, or brute-force protection. Ten consecutive failed login attempts for the admin account all returned the same generic "Login failed" response with HTTP 302 redirect to login.php. No CAPTCHA was presented, no lockout occurred, and no delay was introduced between attempts. This enables unlimited brute-force attacks against any account.

**Remediation:** Implement account lockout after 5 failed attempts (temporary lockout of 15-30 minutes). Add progressive delays between attempts. Consider implementing CAPTCHA after 3 failed attempts. Log and alert on repeated failed login attempts from same IP. Implement IP-based rate limiting.
