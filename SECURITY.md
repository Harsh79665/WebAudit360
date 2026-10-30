# WebAudit 360 — Security Policy & Responsible Disclosure

**Platform:** WebAudit 360  
**Creator:** Harsh Patel  
**Last Updated:** October 30, 2026  

---

## 1. Security Commitment

WebAudit 360 is built with security as a foundational principle. Because WebAudit 360 inspects external websites and applications, we hold ourselves to the highest standards of system integrity, privacy protection, and responsible security assessment.

---

## 2. Reporting a Vulnerability

If you discover a potential security vulnerability within WebAudit 360, we encourage you to disclose it responsibly. We treat security reports with urgency and confidentiality.

### How to Report:
* **Email:** Send a detailed report to `security@webaudit360.io` (or directly contact Harsh Patel).
* **Information to Include:**
  * Type of issue (e.g., SSRF, IDOR, SQL Injection, Authentication Bypass, XSS).
  * Clear step-by-step reproduction instructions or a minimal proof of concept (PoC).
  * Affected endpoints, parameters, or components.
  * Potential impact assessment.
* **PGP Encryption:** Please request our PGP public key if transmitting sensitive vulnerability details.

### What NOT to Do:
* **No Denial of Service:** Do not perform attacks that degrade platform availability for other users.
* **No Data Destruction:** Do not delete or corrupt existing data.
* **No Privacy Violations:** Do not view, exfiltrate, or alter data belonging to other accounts.
* **No Social Engineering:** Do not attempt phishing or social engineering attacks against team members or operators.

---

## 3. Scope & Active Security Boundaries

WebAudit 360 provides active security testing capabilities based on the OWASP Web Security Testing Guide (WSTG). To protect third parties:

1. **Authorization Required:** Active vulnerability testing is **strictly prohibited** against any domain or IP address without verified proof of ownership or written authorization.
2. **Verification Protocol:** WebAudit 360 requires users to verify ownership via a DNS TXT challenge or a well-known HTTP file challenge before unlocking active testing features.
3. **Non-Destructive Payloads Only:** Scans are engineered to be non-destructive. WebAudit 360 does not execute exploit payloads, attempt denial of service, perform credential stuffing, or extract database records.

---

## 4. Server-Side Request Forgery (SSRF) Policy

WebAudit 360 enforces an uncompromising outbound network policy:
* Outbound requests to RFC 1918 private subnets, loopback interfaces (`127.0.0.0/8`, `::1`), link-local IPs (`169.254.0.0/16`), and cloud provider metadata services are strictly blocked at both the application and network layers.
* DNS rebinding attacks are mitigated through socket-level IP pinning and recursive redirect validation.
* Any bypass of our SSRF controls is considered a critical security vulnerability and should be reported immediately.

---

## 5. Security Updates & Remediation Timelines

* **Initial Response:** Within 24 hours of receiving a vulnerability report.
* **Triage & Validation:** Within 72 hours.
* **Remediation & Patch Deployment:** Critical issues are prioritized for emergency patch deployment within 5 business days; high and medium issues within 14 business days.
* **Public Attribution:** Security researchers who report valid vulnerabilities following responsible disclosure guidelines will be credited in our release notes.

