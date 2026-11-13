# Web Application Penetration Testing & Vulnerability Assessment Lab

[![Testing Standard](https://img.shields.io/badge/Standard-OWASP%20WSTG%20v4.2-blue.svg)](#methodology)
[![Scoring](https://img.shields.io/badge/CVSS-v3.1%20Specification-green.svg)](#cvss-calculator)
[![Testing Type](https://img.shields.io/badge/Scope-Authorized%20Grey--Box-red.svg)](#rules-of-engagement)

A modern, defensive web security analysis and penetration testing management laboratory designed for authorized security assessments, vulnerability tracking, HTTP defensive posture auditing, and executive audit reporting.

---

## 🎯 Project Overview & Objective

This project documents and simulates the deliverables of an **authorized grey-box web application penetration test** conducted against a financial portal environment (`Apex Financial Services`). It bridges technical vulnerability verification with executive risk reporting, providing security engineers and stakeholders with an interactive, auditable matrix of security findings.

### Core Modules & Capabilities

1. **Engagement Overview & Scope Boundaries**:
   - Complete Rules of Engagement (RoE) definition, test window schedules, and authorized testing credentials.
   - Attack surface distribution mapped directly to the **OWASP Top 10 (2021)** framework.
   - High-level risk dashboard calculating verified vs. remediated finding ratios.

2. **Vulnerability Assessment Matrix**:
   - Comprehensive technical finding registry containing severity ratings, verified CVSS v3.1 vector strings, audited endpoints, root-cause descriptions, business impact analyses, and code-level remediation blueprints.
   - Real-time search and multi-tiered severity filtering (`High`, `Medium`, `Low`, `Informational`).
   - Dynamic modal to record, qualify, and track new assessment discoveries into the audit register.

3. **HTTP Security Headers & Defense Baseline Auditor**:
   - Interactive response-header evaluator checking for essential browser defenses:
     - `Strict-Transport-Security` (HSTS) with preloading & subdomain coverage
     - `Content-Security-Policy` (CSP) script execution sandboxing and frame restrictions
     - `X-Frame-Options` & `frame-ancestors` clickjacking mitigations
     - `X-Content-Type-Options` MIME-sniffing prevention
     - `Referrer-Policy` token leak containment
     - `Permissions-Policy` hardware API lockdown
   - Automated detection of information leakage banners (`Server`, `X-Powered-By`).
   - Copyable hardening configurations for **Nginx**, **Apache 2.4**, and **Node.js (Helmet)**.

4. **Interactive CVSS v3.1 Calculator**:
   - Fully compliant implementation of the FIRST.org CVSS v3.1 base scoring specification.
   - Live metric toggles across Exploitability (`AV`, `AC`, `PR`, `UI`) and Impact (`S`, `C`, `I`, `A`) with instant vector string synthesis and one-click clipboard copying.

5. **JSON Web Token (JWT) & Authentication Inspector**:
   - Decodes JOSE headers and claims payloads.
   - Flags critical session flaws: `alg: "none"` verification bypasses, missing expiration timestamps (`exp`), and sensitive data leaks in unencrypted token claims.

6. **Formal Audit Report Generator**:
   - Built-in, clean print media stylesheet (`window.print()`) that renders a formal penetration testing report suitable for executive review and compliance documentation.

---

## 🛡️ Assessment Methodology & Compliance

The assessment workflow adheres strictly to industry standards:
- **OWASP Web Security Testing Guide (WSTG v4.2)**
- **Penetration Testing Execution Standard (PTES)**
- **NIST SP 800-115** (Technical Guide to Information Security Testing and Assessment)

### Identified Audit Findings Summary

| Ref ID | Vulnerability Title | OWASP Category | Severity | CVSS v3.1 | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **SEC-001** | Broken Object Level Authorization (BOLA) in Statements | A01 Broken Access Control | **High** | 7.5 | Verified |
| **SEC-002** | Missing Strict-Transport-Security (HSTS) | A05 Security Misconfiguration | **Medium** | 5.3 | In Progress |
| **SEC-003** | Permissive Cross-Origin Resource Sharing (CORS) | A05 Security Misconfiguration | **Medium** | 6.5 | Pending Retest |
| **SEC-004** | Session Token Persisting Across Password Reset | A07 Identification Failures | **Medium** | 6.8 | Resolved |
| **SEC-005** | Insufficient Rate Limiting on 2FA OTP | A07 Identification Failures | **High** | 7.3 | Resolved |
| **SEC-006** | Absence of CSP Frame Ancestors / XFO | A05 Security Misconfiguration | **Low** | 4.3 | In Progress |
| **SEC-007** | Information Disclosure via Server Headers | A05 Security Misconfiguration | **Info** | 2.0 | Resolved |
| **SEC-008** | Reflected Context Lacking Output Encoding | A03 Injection | **Medium** | 6.1 | Resolved |

---

## 🚀 Running the Application

This platform is completely self-contained with **zero external pip dependencies**, operating on standard Python 3.

### 1. Launch the Server

From the project root:

```bash
python server.py
```

### 2. Access the Dashboard

Open your web browser and navigate to:
```
http://127.0.0.1:8080
```

---

## 📂 Project Architecture

```
web-security-lab/
├── server.py                # Native Python HTTP server & REST API endpoints
├── README.md                # Engagement documentation & methodology guide
├── templates/
│   └── index.html           # Single-page security assessment dashboard UI
└── static/
    ├── css/
    │   └── styles.css       # Clean, artisanal dark slate security theme & print styles
    └── js/
        └── app.js           # Client orchestration, CVSS engine, header & token analyzers
```

---

## ⚖️ Legal & Ethical Disclaimer

This application and documentation are provided strictly for **educational, defensive, and authorized audit demonstration purposes**. Penetration testing against web applications without prior explicit written authorization from the system owner is illegal under computer misuse legislation (e.g., Computer Fraud and Abuse Act, UK Computer Misuse Act). Always operate within defined Rules of Engagement.
