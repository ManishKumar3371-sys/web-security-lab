#!/usr/bin/env python3
"""
Web Security Audit & Penetration Testing Dashboard Lab Server
Zero external dependencies - runs on standard Python 3.
"""

import http.server
import json
import os
import posixpath
import sys
import urllib.parse
from http import HTTPStatus

PORT = int(os.environ.get("PORT", 8080))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Mock default database of findings for the authorized audit engagement
AUDIT_PROJECT = {
    "target_name": "Apex Financial Services (Core Web Portal)",
    "target_url": "https://portal.staging.apexfin.internal",
    "scope_type": "Grey-Box Web Application Penetration Test",
    "assessment_dates": "Nov 02, 2026 - Nov 12, 2026",
    "authorization_ref": "AUTH-SEC-2026-08892",
    "lead_analyst": "Authorized Security Assessment Team",
    "status": "Final Audit Review",
    "executive_summary": "An authorized grey-box web application penetration test was conducted against the staging core web portal. The assessment identified 8 distinct security issues across OWASP Top 10 categories, including 1 High severity authorization flaw in transaction review, 3 Medium severity configuration weaknesses, and multiple defensive header oversights. Comprehensive remediation steps have been verified.",
    "findings": [
        {
            "id": "SEC-001",
            "title": "Broken Object Level Authorization (BOLA) in Transaction Statements",
            "severity": "High",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "owasp_category": "A01:2021 - Broken Access Control",
            "status": "Remediation Verified",
            "endpoint": "GET /api/v2/accounts/{account_id}/statement",
            "description": "Authenticated users were able to access financial statements belonging to other tenant accounts by directly tampering with the account_id path parameter without server-side tenancy verification.",
            "impact": "Unauthorized access to confidential banking records, transaction histories, and Personally Identifiable Information (PII).",
            "remediation": "Enforce object-level access controls using context-aware authorization middleware. Validate user session claims against target resource ownership at the data layer."
        },
        {
            "id": "SEC-002",
            "title": "Missing HTTP Strict Transport Security (HSTS) with Long Duration",
            "severity": "Medium",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "status": "In Progress",
            "endpoint": "HTTPS Portal Gateway (All endpoints)",
            "description": "The web server response headers lack the Strict-Transport-Security header, allowing potential SSL-stripping and man-in-the-middle downgrade attacks on insecure Wi-Fi networks.",
            "impact": "Vulnerability to eavesdropping on the initial HTTP redirect prior to TLS negotiation.",
            "remediation": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to all HTTPS responses at the reverse proxy layer."
        },
        {
            "id": "SEC-003",
            "title": "Permissive Cross-Origin Resource Sharing (CORS) Policy",
            "severity": "Medium",
            "cvss_score": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "status": "Pending Retest",
            "endpoint": "/api/v2/profile/me",
            "description": "The API reflects untrusted Origin headers and sets Access-Control-Allow-Credentials to true, allowing arbitrary external domains to read authenticated profile responses.",
            "impact": "Cross-site data exfiltration of user emails, phone numbers, and profile settings via malicious third-party scripts.",
            "remediation": "Maintain a strict whitelist of authorized origins instead of wildcard or echoed origins. Reject credentials on non-whitelisted cross-origin requests."
        },
        {
            "id": "SEC-004",
            "title": "Session Token Persisting Across Password Reset Cycle",
            "severity": "Medium",
            "cvss_score": 6.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "owasp_category": "A07:2021 - Identification and Authentication Failures",
            "status": "Resolved",
            "endpoint": "POST /auth/reset-password",
            "description": "Existing active session JWTs and cookie sessions were not invalidated upon successful password reset, leaving compromised sessions active on other devices.",
            "impact": "Account takeover persistence if an attacker has stolen an older active session token.",
            "remediation": "Revoke all active refresh tokens and increment the user token version / invalidate server-side session stores on password changes."
        },
        {
            "id": "SEC-005",
            "title": "Insufficient Rate Limiting on One-Time Password (OTP) Verification",
            "severity": "High",
            "cvss_score": 7.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
            "owasp_category": "A07:2021 - Identification and Authentication Failures",
            "status": "Resolved",
            "endpoint": "POST /auth/verify-2fa-otp",
            "description": "The multi-factor SMS/email token verification route did not enforce progressive back-off delays or IP/account-level rate locks after repeated invalid attempts.",
            "impact": "Potential brute-force guessing of 6-digit verification codes within the 10-minute expiry window.",
            "remediation": "Enforce sliding window rate-limiting (maximum 5 attempts per code), lockout policies, and shorten code validity to 3 minutes."
        },
        {
            "id": "SEC-006",
            "title": "Absence of Content Security Policy (CSP) Frame Ancestors Directive",
            "severity": "Low",
            "cvss_score": 4.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "status": "In Progress",
            "endpoint": "GET /checkout/confirm",
            "description": "The application lacks frame-ancestors 'none' or 'self' in Content-Security-Policy and does not return X-Frame-Options: DENY, rendering sensitive confirmation pages embeddable.",
            "impact": "UI redressing / clickjacking attack potential where users are tricked into authorizing fund transfers.",
            "remediation": "Implement 'Content-Security-Policy: frame-ancestors 'self'' and 'X-Frame-Options: SAMEORIGIN'."
        },
        {
            "id": "SEC-007",
            "title": "Verbose Server Software Information Disclosure via Server & X-Powered-By",
            "severity": "Informational",
            "cvss_score": 2.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "status": "Resolved",
            "endpoint": "All HTTP endpoints",
            "description": "HTTP response headers expose detailed backend versions ('Server: Apache/2.4.52 (Ubuntu)', 'X-Powered-By: Express/4.18.2').",
            "impact": "Facilitates attacker reconnaissance and targeted CVE exploitation based on specific framework patch levels.",
            "remediation": "Disable 'ServerTokens Prod' in Apache and call app.disable('x-powered-by') in Express."
        },
        {
            "id": "SEC-008",
            "title": "Reflected Context in Search Query Parameter Lacking Contextual Output Encoding",
            "severity": "Medium",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "owasp_category": "A03:2021 - Injection",
            "status": "Resolved",
            "endpoint": "GET /knowledge-base/search?q=",
            "description": "The search query was reflected directly inside an HTML attribute context without attribute-level escaping, allowing payload execution in outdated browsers.",
            "impact": "Execution of arbitrary client-side script in the victim's session context.",
            "remediation": "Apply contextual output encoding (HTML attribute escaping) and adopt a strict Content Security Policy with nonces."
        }
    ]
}

class SecurityLabHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.serve_file(os.path.join(BASE_DIR, "templates", "index.html"), "text/html; charset=utf-8")
            return

        if path == "/api/project":
            self.send_json_response(AUDIT_PROJECT)
            return

        if path == "/api/findings":
            query = urllib.parse.parse_qs(parsed.query)
            severity = query.get("severity", [None])[0]
            status = query.get("status", [None])[0]
            
            results = AUDIT_PROJECT["findings"]
            if severity and severity.lower() != "all":
                results = [f for f in results if f["severity"].lower() == severity.lower()]
            if status and status.lower() != "all":
                results = [f for f in results if f["status"].lower() == status.lower()]
            
            self.send_json_response({"total": len(results), "findings": results})
            return

        # Serve static assets
        if path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            file_path = os.path.join(BASE_DIR, "static", rel_path)
            if os.path.isfile(file_path):
                content_type = self.guess_type(file_path)
                self.serve_file(file_path, content_type)
                return

        # Fallback to standard handler or 404
        self.send_error(HTTPStatus.NOT_FOUND, "Resource not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            payload = {}

        if path == "/api/findings/add":
            title = payload.get("title", "").strip()
            severity = payload.get("severity", "Low")
            category = payload.get("owasp_category", "A05:2021 - Security Misconfiguration")
            endpoint = payload.get("endpoint", "/api/v1/resource")
            description = payload.get("description", "")
            remediation = payload.get("remediation", "")
            cvss_score = float(payload.get("cvss_score", 4.0))

            if not title:
                self.send_json_response({"error": "Title is required"}, status=HTTPStatus.BAD_REQUEST)
                return

            new_id = f"SEC-{len(AUDIT_PROJECT['findings']) + 1:03d}"
            finding = {
                "id": new_id,
                "title": title,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": payload.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                "owasp_category": category,
                "status": "Identified",
                "endpoint": endpoint,
                "description": description or "Verified vulnerability identified during authorized assessment.",
                "impact": payload.get("impact", "Potential unauthorized interaction with target endpoint."),
                "remediation": remediation or "Apply defense-in-depth principles and input validation."
            }
            AUDIT_PROJECT["findings"].insert(0, finding)
            self.send_json_response({"message": "Finding recorded successfully", "finding": finding})
            return

        if path == "/api/analyze-headers":
            raw_headers = payload.get("headers", "")
            analysis = self.analyze_security_headers(raw_headers)
            self.send_json_response(analysis)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Unknown API endpoint")

    def analyze_security_headers(self, raw_text):
        """Analyzes HTTP response headers against OWASP secure header recommendations"""
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        header_map = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                header_map[k.strip().lower()] = v.strip()

        checks = [
            {
                "header": "Strict-Transport-Security",
                "present": "strict-transport-security" in header_map,
                "value": header_map.get("strict-transport-security", None),
                "importance": "High",
                "recommendation": "max-age=31536000; includeSubDomains; preload",
                "summary": "Enforces TLS encryption and prevents protocol downgrade / SSL stripping."
            },
            {
                "header": "Content-Security-Policy",
                "present": "content-security-policy" in header_map,
                "value": header_map.get("content-security-policy", None),
                "importance": "High",
                "recommendation": "default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none';",
                "summary": "Restricts execution of unauthorized inline scripts and prevents XSS/injection."
            },
            {
                "header": "X-Frame-Options",
                "present": "x-frame-options" in header_map or "content-security-policy" in header_map and "frame-ancestors" in header_map.get("content-security-policy", ""),
                "value": header_map.get("x-frame-options", "(via CSP frame-ancestors)" if "frame-ancestors" in header_map.get("content-security-policy", "") else None),
                "importance": "Medium",
                "recommendation": "DENY or SAMEORIGIN",
                "summary": "Mitigates UI redressing and Clickjacking by disallowing cross-origin iframe embedding."
            },
            {
                "header": "X-Content-Type-Options",
                "present": "x-content-type-options" in header_map,
                "value": header_map.get("x-content-type-options", None),
                "importance": "Medium",
                "recommendation": "nosniff",
                "summary": "Prevents MIME-sniffing attacks where browsers execute non-script files as scripts."
            },
            {
                "header": "Referrer-Policy",
                "present": "referrer-policy" in header_map,
                "value": header_map.get("referrer-policy", None),
                "importance": "Low",
                "recommendation": "strict-origin-when-cross-origin",
                "summary": "Protects sensitive URL query tokens from leaking across external web requests."
            },
            {
                "header": "Permissions-Policy",
                "present": "permissions-policy" in header_map,
                "value": header_map.get("permissions-policy", None),
                "importance": "Low",
                "recommendation": "camera=(), microphone=(), geolocation=()",
                "summary": "Controls browser hardware APIs and features accessible in origin context."
            }
        ]

        # Calculate security score
        weights = {"High": 25, "Medium": 15, "Low": 10}
        total_possible = sum(weights[c["importance"]] for c in checks)
        earned = sum(weights[c["importance"]] for c in checks if c["present"])
        score_pct = int((earned / total_possible) * 100)

        # Check for bad header leaks
        leak_headers = []
        for leak in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            if leak in header_map:
                leak_headers.append({"header": leak, "value": header_map[leak]})

        grade = "A" if score_pct >= 90 else "B" if score_pct >= 75 else "C" if score_pct >= 55 else "D" if score_pct >= 35 else "F"

        return {
            "score": score_pct,
            "grade": grade,
            "checks": checks,
            "information_leaks": leak_headers,
            "total_evaluated": len(checks)
        }

    def serve_file(self, file_path, content_type):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def send_json_response(self, data, status=HTTPStatus.OK):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

def main():
    os.chdir(BASE_DIR)
    print(f"[*] Initializing Web Security Audit & Penetration Testing Dashboard Lab")
    print(f"[*] Working Directory: {BASE_DIR}")
    print(f"[*] Target Authorization: Verified (Simulated Lab Environment)")
    print(f"[*] Serving on http://127.0.0.1:{PORT}")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), SecurityLabHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server gracefully.")
        server.server_close()

if __name__ == "__main__":
    main()
