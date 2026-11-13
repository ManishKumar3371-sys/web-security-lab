/**
 * SENTINEL-SEC Web Security Penetration Testing & Audit Lab
 * Client Application Logic
 */

let auditState = {
  project: null,
  findings: [],
  activeFilter: 'all',
  searchQuery: ''
};

// Default bundled audit project state (allows 100% static hosting on GitHub Pages)
const DEFAULT_AUDIT_DATA = {
  target_name: "Apex Financial Services (Core Web Portal)",
  target_url: "https://portal.staging.apexfin.internal",
  scope_type: "Grey-Box Web Application Penetration Test",
  assessment_dates: "Nov 02, 2026 - Nov 12, 2026",
  authorization_ref: "AUTH-SEC-2026-08892",
  lead_analyst: "Authorized Security Assessment Team",
  status: "Final Audit Review",
  executive_summary: "An authorized grey-box web application penetration test was conducted against the staging core web portal. The assessment identified 8 distinct security issues across OWASP Top 10 categories, including 1 High severity authorization flaw in transaction review, 3 Medium severity configuration weaknesses, and multiple defensive header oversights. Comprehensive remediation steps have been verified.",
  findings: [
    {
      id: "SEC-001",
      title: "Broken Object Level Authorization (BOLA) in Transaction Statements",
      severity: "High",
      cvss_score: 7.5,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
      owasp_category: "A01:2021 - Broken Access Control",
      status: "Remediation Verified",
      endpoint: "GET /api/v2/accounts/{account_id}/statement",
      description: "Authenticated users were able to access financial statements belonging to other tenant accounts by directly tampering with the account_id path parameter without server-side tenancy verification.",
      impact: "Unauthorized access to confidential banking records, transaction histories, and Personally Identifiable Information (PII).",
      remediation: "Enforce object-level access controls using context-aware authorization middleware. Validate user session claims against target resource ownership at the data layer."
    },
    {
      id: "SEC-002",
      title: "Missing HTTP Strict Transport Security (HSTS) with Long Duration",
      severity: "Medium",
      cvss_score: 5.3,
      cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
      owasp_category: "A05:2021 - Security Misconfiguration",
      status: "In Progress",
      endpoint: "HTTPS Portal Gateway (All endpoints)",
      description: "The web server response headers lack the Strict-Transport-Security header, allowing potential SSL-stripping and man-in-the-middle downgrade attacks on insecure Wi-Fi networks.",
      impact: "Vulnerability to eavesdropping on the initial HTTP redirect prior to TLS negotiation.",
      remediation: "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to all HTTPS responses at the reverse proxy layer."
    },
    {
      id: "SEC-003",
      title: "Permissive Cross-Origin Resource Sharing (CORS) Policy",
      severity: "Medium",
      cvss_score: 6.5,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
      owasp_category: "A05:2021 - Security Misconfiguration",
      status: "Pending Retest",
      endpoint: "/api/v2/profile/me",
      description: "The API reflects untrusted Origin headers and sets Access-Control-Allow-Credentials to true, allowing arbitrary external domains to read authenticated profile responses.",
      impact: "Cross-site data exfiltration of user emails, phone numbers, and profile settings via malicious third-party scripts.",
      remediation: "Maintain a strict whitelist of authorized origins instead of wildcard or echoed origins. Reject credentials on non-whitelisted cross-origin requests."
    },
    {
      id: "SEC-004",
      title: "Session Token Persisting Across Password Reset Cycle",
      severity: "Medium",
      cvss_score: 6.8,
      cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
      owasp_category: "A07:2021 - Identification and Authentication Failures",
      status: "Resolved",
      endpoint: "POST /auth/reset-password",
      description: "Existing active session JWTs and cookie sessions were not invalidated upon successful password reset, leaving compromised sessions active on other devices.",
      impact: "Account takeover persistence if an attacker has stolen an older active session token.",
      remediation: "Revoke all active refresh tokens and increment the user token version / invalidate server-side session stores on password changes."
    },
    {
      id: "SEC-005",
      title: "Insufficient Rate Limiting on One-Time Password (OTP) Verification",
      severity: "High",
      cvss_score: 7.3,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
      owasp_category: "A07:2021 - Identification and Authentication Failures",
      status: "Resolved",
      endpoint: "POST /auth/verify-2fa-otp",
      description: "The multi-factor SMS/email token verification route did not enforce progressive back-off delays or IP/account-level rate locks after repeated invalid attempts.",
      impact: "Potential brute-force guessing of 6-digit verification codes within the 10-minute expiry window.",
      remediation: "Enforce sliding window rate-limiting (maximum 5 attempts per code), lockout policies, and shorten code validity to 3 minutes."
    },
    {
      id: "SEC-006",
      title: "Absence of Content Security Policy (CSP) Frame Ancestors Directive",
      severity: "Low",
      cvss_score: 4.3,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
      owasp_category: "A05:2021 - Security Misconfiguration",
      status: "In Progress",
      endpoint: "GET /checkout/confirm",
      description: "The application lacks frame-ancestors 'none' or 'self' in Content-Security-Policy and does not return X-Frame-Options: DENY, rendering sensitive confirmation pages embeddable.",
      impact: "UI redressing / clickjacking attack potential where users are tricked into authorizing fund transfers.",
      remediation: "Implement 'Content-Security-Policy: frame-ancestors 'self'' and 'X-Frame-Options: SAMEORIGIN'."
    },
    {
      id: "SEC-007",
      title: "Verbose Server Software Information Disclosure via Server & X-Powered-By",
      severity: "Informational",
      cvss_score: 2.0,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
      owasp_category: "A05:2021 - Security Misconfiguration",
      status: "Resolved",
      endpoint: "All HTTP endpoints",
      description: "HTTP response headers expose detailed backend versions ('Server: Apache/2.4.52 (Ubuntu)', 'X-Powered-By: Express/4.18.2').",
      impact: "Facilitates attacker reconnaissance and targeted CVE exploitation based on specific framework patch levels.",
      remediation: "Disable 'ServerTokens Prod' in Apache and call app.disable('x-powered-by') in Express."
    },
    {
      id: "SEC-008",
      title: "Reflected Context in Search Query Parameter Lacking Contextual Output Encoding",
      severity: "Medium",
      cvss_score: 6.1,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
      owasp_category: "A03:2021 - Injection",
      status: "Resolved",
      endpoint: "GET /knowledge-base/search?q=",
      description: "The search query was reflected directly inside an HTML attribute context without attribute-level escaping, allowing payload execution in outdated browsers.",
      impact: "Execution of arbitrary client-side script in the victim's session context.",
      remediation: "Apply contextual output encoding (HTML attribute escaping) and adopt a strict Content Security Policy with nonces."
    }
  ]
};

// Preset Header Payloads
const HEADER_PRESETS = {
  vulnerable: `HTTP/1.1 200 OK
Date: Sat, 14 Nov 2026 01:15:00 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express/4.18.2
Content-Type: text/html; charset=utf-8
Content-Length: 4892
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Set-Cookie: session_token=s%3A7a9b...; Path=/; HttpOnly`,

  hardened: `HTTP/1.1 200 OK
Date: Sat, 14 Nov 2026 01:15:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 4892
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m'; object-src 'none'; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store, max-age=0
Set-Cookie: __Host-session=s%3A8x9...; Path=/; Secure; HttpOnly; SameSite=Strict`
};

const HARDENING_CONFIGS = {
  nginx: `# Nginx Reverse Proxy Hardening
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
server_tokens off;`,

  apache: `# Apache 2.4 Hardening Configuration (.htaccess or httpd.conf)
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
ServerTokens Prod
ServerSignature Off`,

  express: `// Node.js Express Hardening via Helmet middleware
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');

app.use(helmet({
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));`
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initCVSS();
  initHeadersAuditor();
  initJwtInspector();
  initFindingModal();
  loadProjectData();

  // Print button
  document.getElementById("btnPrintReport")?.addEventListener("click", () => {
    window.print();
  });
});

// Tab Switching
function initTabs() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
  });

  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === `pane-${tabId}`);
  });
}

// Fetch Initial Data
async function loadProjectData() {
  try {
    const res = await fetch("/api/project");
    if (!res.ok) throw new Error("API not available");
    const data = await res.json();
    auditState.project = data;
    auditState.findings = data.findings || [];
  } catch (err) {
    console.log("Serving bundled audit data (offline/static mode)");
    auditState.project = DEFAULT_AUDIT_DATA;
    auditState.findings = DEFAULT_AUDIT_DATA.findings;
  }
  renderOverview();
  renderFindings();
  renderQuickTable();
  updateSidebarCounts();
}

// Render Overview
function renderOverview() {
  const p = auditState.project;
  if (!p) return;

  document.getElementById("topEngagementName").innerText = p.target_name;
  document.getElementById("sideTargetUrl").innerText = p.target_url;
  document.getElementById("sideAuthRef").innerText = p.authorization_ref;
  document.getElementById("specTargetName").innerText = p.target_name;
  document.getElementById("specTargetUrl").innerText = p.target_url;
  document.getElementById("specDates").innerText = p.assessment_dates;
  document.getElementById("summaryText").innerText = p.executive_summary;

  // Stats calculation
  let critHigh = 0, med = 0, lowInfo = 0, resolved = 0;
  auditState.findings.forEach(f => {
    const sev = f.severity.toLowerCase();
    if (sev === "critical" || sev === "high") critHigh++;
    else if (sev === "medium") med++;
    else lowInfo++;

    if (f.status.toLowerCase().includes("resolved") || f.status.toLowerCase().includes("verified")) {
      resolved++;
    }
  });

  document.getElementById("countCriticalHigh").innerText = critHigh;
  document.getElementById("countMedium").innerText = med;
  document.getElementById("countLowInfo").innerText = lowInfo;
  document.getElementById("countResolved").innerText = resolved;
}

function updateSidebarCounts() {
  const badge = document.getElementById("sidebarFindingCount");
  if (badge) badge.innerText = auditState.findings.length;
}

// Render Findings List
function renderFindings() {
  const container = document.getElementById("findingsContainer");
  if (!container) return;

  let filtered = auditState.findings.filter(f => {
    const matchesSev = auditState.activeFilter === 'all' || f.severity.toLowerCase() === auditState.activeFilter.toLowerCase();
    const q = auditState.searchQuery.toLowerCase();
    const matchesSearch = !q || 
      f.title.toLowerCase().includes(q) || 
      f.endpoint.toLowerCase().includes(q) || 
      f.owasp_category.toLowerCase().includes(q) ||
      f.id.toLowerCase().includes(q);
    return matchesSev && matchesSearch;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="card p-4 text-center text-muted">
        <p>No findings matching the selected filters.</p>
      </div>`;
    return;
  }

  container.innerHTML = filtered.map(f => {
    const isResolved = f.status.toLowerCase().includes("resolved") || f.status.toLowerCase().includes("verified");
    return `
      <div class="finding-card" id="card-${f.id}">
        <div class="finding-header" onclick="toggleFinding('${f.id}')">
          <div class="finding-header-left">
            <span class="finding-id">${f.id}</span>
            <span class="sev-badge sev-${f.severity}">${f.severity}</span>
            <span class="finding-title">${escapeHtml(f.title)}</span>
          </div>
          <div class="finding-header-right">
            <span class="finding-cvss-chip">CVSS ${f.cvss_score.toFixed(1)}</span>
            <span class="${isResolved ? 'tag-verified' : 'tag-pending'}">${f.status}</span>
            <svg class="finding-toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </div>
        </div>
        <div class="finding-body">
          <div class="finding-meta-grid">
            <div class="finding-meta-item">
              <span class="label">OWASP Standard Category</span>
              <span class="val">${escapeHtml(f.owasp_category)}</span>
            </div>
            <div class="finding-meta-item">
              <span class="label">Audited Target Endpoint</span>
              <span class="val font-mono">${escapeHtml(f.endpoint)}</span>
            </div>
            <div class="finding-meta-item">
              <span class="label">CVSS v3.1 Vector String</span>
              <span class="val font-mono text-xs">${f.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}</span>
            </div>
          </div>

          <div class="finding-section-title">Technical Description & Observed Flaw</div>
          <p class="finding-desc-text">${escapeHtml(f.description)}</p>

          <div class="finding-section-title">Business & Security Impact</div>
          <p class="finding-desc-text">${escapeHtml(f.impact)}</p>

          <div class="finding-section-title">Verified Remediation & Architectural Fix</div>
          <p class="finding-desc-text text-info">${escapeHtml(f.remediation)}</p>
        </div>
      </div>
    `;
  }).join("");
}

window.toggleFinding = function(id) {
  const card = document.getElementById(`card-${id}`);
  if (card) {
    card.classList.toggle("open");
  }
};

// Render Quick Findings Table on Overview
function renderQuickTable() {
  const tbody = document.getElementById("quickFindingsTable");
  if (!tbody) return;

  const topItems = auditState.findings.slice(0, 5);
  tbody.innerHTML = topItems.map(f => {
    const isResolved = f.status.toLowerCase().includes("resolved") || f.status.toLowerCase().includes("verified");
    return `
      <tr>
        <td class="font-mono">${f.id}</td>
        <td><strong>${escapeHtml(f.title)}</strong></td>
        <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
        <td class="font-mono">${f.cvss_score.toFixed(1)}</td>
        <td class="font-mono text-xs">${escapeHtml(f.endpoint)}</td>
        <td><span class="${isResolved ? 'tag-verified' : 'tag-pending'}">${f.status}</span></td>
      </tr>
    `;
  }).join("");
}

// Filter listeners
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-filter-sev]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-filter-sev]").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      auditState.activeFilter = btn.getAttribute("data-filter-sev");
      renderFindings();
    });
  });

  const searchInput = document.getElementById("findingSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      auditState.searchQuery = e.target.value;
      renderFindings();
    });
  }
});

/* ==========================================================================
   Security Headers Auditor Logic
   ========================================================================== */
function initHeadersAuditor() {
  const btnRun = document.getElementById("btnRunHeaderAnalysis");
  const rawInput = document.getElementById("rawHeadersInput");
  const btnPresetVuln = document.getElementById("btnPresetVulnerable");
  const btnPresetHard = document.getElementById("btnPresetHardened");

  btnPresetVuln?.addEventListener("click", () => {
    rawInput.value = HEADER_PRESETS.vulnerable;
    runHeaderAnalysis();
  });

  btnPresetHard?.addEventListener("click", () => {
    rawInput.value = HEADER_PRESETS.hardened;
    runHeaderAnalysis();
  });

  btnRun?.addEventListener("click", runHeaderAnalysis);

  // Snippet tabs
  document.querySelectorAll(".tab-mini").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab-mini").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const confType = tab.getAttribute("data-conf");
      const snippetEl = document.getElementById("confSnippet");
      if (snippetEl && HARDENING_CONFIGS[confType]) {
        snippetEl.querySelector("code").innerText = HARDENING_CONFIGS[confType];
      }
    });
  });

  // Run initial analysis on page load
  runHeaderAnalysis();
}

async function runHeaderAnalysis() {
  const rawInput = document.getElementById("rawHeadersInput");
  if (!rawInput) return;

  try {
    const res = await fetch("/api/analyze-headers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ headers: rawInput.value })
    });
    if (!res.ok) throw new Error("Backend not reached");
    const result = await res.json();
    renderHeaderResults(result);
  } catch (err) {
    // Client-side fallback analyzer for static deployment (GitHub Pages)
    const clientAnalysis = analyzeHeadersLocally(rawInput.value);
    renderHeaderResults(clientAnalysis);
  }
}

function analyzeHeadersLocally(rawText) {
  const lines = rawText.split("\n").map(l => l.trim()).filter(Boolean);
  const headerMap = {};
  lines.forEach(l => {
    if (l.includes(":")) {
      const idx = l.indexOf(":");
      headerMap[l.slice(0, idx).trim().toLowerCase()] = l.slice(idx + 1).trim();
    }
  });

  const checks = [
    {
      header: "Strict-Transport-Security",
      present: "strict-transport-security" in headerMap,
      value: headerMap["strict-transport-security"] || null,
      importance: "High",
      recommendation: "max-age=31536000; includeSubDomains; preload",
      summary: "Enforces TLS encryption and prevents protocol downgrade / SSL stripping."
    },
    {
      header: "Content-Security-Policy",
      present: "content-security-policy" in headerMap,
      value: headerMap["content-security-policy"] || null,
      importance: "High",
      recommendation: "default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none';",
      summary: "Restricts execution of unauthorized inline scripts and prevents XSS/injection."
    },
    {
      header: "X-Frame-Options",
      present: "x-frame-options" in headerMap || ("content-security-policy" in headerMap && headerMap["content-security-policy"].includes("frame-ancestors")),
      value: headerMap["x-frame-options"] || ("content-security-policy" in headerMap && headerMap["content-security-policy"].includes("frame-ancestors") ? "(via CSP frame-ancestors)" : null),
      importance: "Medium",
      recommendation: "DENY or SAMEORIGIN",
      summary: "Mitigates UI redressing and Clickjacking by disallowing cross-origin iframe embedding."
    },
    {
      header: "X-Content-Type-Options",
      present: "x-content-type-options" in headerMap,
      value: headerMap["x-content-type-options"] || null,
      importance: "Medium",
      recommendation: "nosniff",
      summary: "Prevents MIME-sniffing attacks where browsers execute non-script files as scripts."
    },
    {
      header: "Referrer-Policy",
      present: "referrer-policy" in headerMap,
      value: headerMap["referrer-policy"] || null,
      importance: "Low",
      recommendation: "strict-origin-when-cross-origin",
      summary: "Protects sensitive URL query tokens from leaking across external web requests."
    },
    {
      header: "Permissions-Policy",
      present: "permissions-policy" in headerMap,
      value: headerMap["permissions-policy"] || null,
      importance: "Low",
      recommendation: "camera=(), microphone=(), geolocation=()",
      summary: "Controls browser hardware APIs and features accessible in origin context."
    }
  ];

  const weights = { High: 25, Medium: 15, Low: 10 };
  const totalPossible = checks.reduce((acc, c) => acc + weights[c.importance], 0);
  const earned = checks.filter(c => c.present).reduce((acc, c) => acc + weights[c.importance], 0);
  const scorePct = Math.round((earned / totalPossible) * 100);

  const leakHeaders = [];
  ["server", "x-powered-by", "x-aspnet-version", "x-generator"].forEach(leak => {
    if (leak in headerMap) {
      leakHeaders.push({ header: leak, value: headerMap[leak] });
    }
  });

  const grade = scorePct >= 90 ? "A" : scorePct >= 75 ? "B" : scorePct >= 55 ? "C" : scorePct >= 35 ? "D" : "F";
  return {
    score: scorePct,
    grade: grade,
    checks: checks,
    information_leaks: leakHeaders,
    total_evaluated: checks.length
  };
}

function renderHeaderResults(data) {
  const gradeBadge = document.getElementById("headerGradeBadge");
  const scoreBar = document.getElementById("headerScoreBar");
  const scoreText = document.getElementById("headerScoreText");
  const checklist = document.getElementById("headerChecklist");
  const leaksContainer = document.getElementById("leaksContainer");

  gradeBadge.innerText = `Grade: ${data.grade}`;
  gradeBadge.className = `grade-badge ${data.grade === 'A' ? 'text-success' : data.grade === 'B' ? 'text-info' : data.grade === 'C' ? 'text-warning' : 'text-danger'}`;

  scoreBar.style.width = `${data.score}%`;
  scoreText.innerText = `${data.score}%`;

  // Leaks
  if (data.information_leaks && data.information_leaks.length > 0) {
    leaksContainer.innerHTML = `
      <div class="jwt-warn-item danger">
        <strong>Information Leakage Detected:</strong> Server banners exposed (${data.information_leaks.map(l => `${l.header}: ${escapeHtml(l.value)}`).join(", ")}). Recommend suppressing server identification.
      </div>
    `;
  } else {
    leaksContainer.innerHTML = `
      <div class="jwt-warn-item ok">
        <strong>Clean Server Signature:</strong> No sensitive software version banners detected.
      </div>
    `;
  }

  // Checklist
  checklist.innerHTML = data.checks.map(c => {
    return `
      <div class="checklist-item">
        <div class="check-left">
          <span class="check-name">${c.header}</span>
          <span class="check-desc">${c.summary}</span>
          ${c.present ? `<span class="text-xs text-muted font-mono mt-1">Value: ${escapeHtml(c.value || 'Configured')}</span>` : `<span class="text-xs text-warning mt-1">Recommended: <code>${escapeHtml(c.recommendation)}</code></span>`}
        </div>
        <div class="check-status ${c.present ? 'text-success' : 'text-danger'}">
          ${c.present ? '✓ PROTECTED' : '✗ MISSING'}
        </div>
      </div>
    `;
  }).join("");
}

/* ==========================================================================
   CVSS v3.1 Calculator Logic (Official FIRST Formula)
   ========================================================================== */
const cvssState = {
  AV: "N",
  AC: "L",
  PR: "N",
  UI: "N",
  S: "U",
  C: "H",
  I: "H",
  A: "N"
};

function initCVSS() {
  document.querySelectorAll(".btn-group-toggle").forEach(group => {
    const metric = group.getAttribute("data-metric");
    group.querySelectorAll(".toggle-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        group.querySelectorAll(".toggle-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        cvssState[metric] = btn.getAttribute("data-val");
        calculateCVSS();
      });
    });
  });

  document.getElementById("btnCopyVector")?.addEventListener("click", () => {
    const vec = document.getElementById("cvssVectorStr").innerText;
    navigator.clipboard.writeText(vec);
    const btn = document.getElementById("btnCopyVector");
    btn.innerText = "Copied!";
    setTimeout(() => { btn.innerText = "Copy Vector"; }, 1500);
  });

  calculateCVSS();
}

function calculateCVSS() {
  const { AV, AC, PR, UI, S, C, I, A } = cvssState;

  // Weight constants per FIRST spec
  const weightAV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[AV];
  const weightAC = { L: 0.77, H: 0.44 }[AC];
  
  let weightPR = 0.85;
  if (S === "U") {
    weightPR = { N: 0.85, L: 0.62, H: 0.27 }[PR];
  } else {
    weightPR = { N: 0.85, L: 0.68, H: 0.50 }[PR];
  }

  const weightUI = { N: 0.85, R: 0.62 }[UI];

  const weightC = { H: 0.56, L: 0.22, N: 0.0 }[C];
  const weightI = { H: 0.56, L: 0.22, N: 0.0 }[I];
  const weightA = { H: 0.56, L: 0.22, N: 0.0 }[A];

  const exploitability = 8.22 * weightAV * weightAC * weightPR * weightUI;
  const ISS = 1 - ((1 - weightC) * (1 - weightI) * (1 - weightA));

  let impact = 0;
  if (S === "U") {
    impact = 6.42 * ISS;
  } else {
    impact = 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
  }

  let baseScore = 0;
  if (impact <= 0) {
    baseScore = 0;
  } else if (S === "U") {
    baseScore = Math.min(roundUp1(impact + exploitability), 10.0);
  } else {
    baseScore = Math.min(roundUp1(1.08 * (impact + exploitability)), 10.0);
  }

  // Determine Severity
  let severity = "NONE";
  let sevClass = "text-muted";
  if (baseScore >= 9.0) { severity = "CRITICAL"; sevClass = "sev-Critical"; }
  else if (baseScore >= 7.0) { severity = "HIGH"; sevClass = "sev-High"; }
  else if (baseScore >= 4.0) { severity = "MEDIUM"; sevClass = "sev-Medium"; }
  else if (baseScore >= 0.1) { severity = "LOW"; sevClass = "sev-Low"; }

  const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;

  // Update UI
  document.getElementById("cvssScoreVal").innerText = baseScore.toFixed(1);
  document.getElementById("cvssVectorStr").innerText = vector;
  document.getElementById("baseScoreText").innerText = `${baseScore.toFixed(1)} / 10.0`;
  document.getElementById("impactScoreText").innerText = impact.toFixed(1);
  document.getElementById("exploitScoreText").innerText = exploitability.toFixed(1);

  const badge = document.getElementById("cvssSeverityBadge");
  badge.innerText = severity;
  badge.className = `cvss-badge-result ${sevClass}`;
}

function roundUp1(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/* ==========================================================================
   JWT Security Inspector Logic
   ========================================================================== */
function initJwtInspector() {
  const btnInspect = document.getElementById("btnInspectJwt");
  const btnSample = document.getElementById("btnLoadSampleJwt");
  const btnValid = document.getElementById("btnLoadValidJwt");
  const input = document.getElementById("rawJwtInput");

  // Sample with "none" alg and no expiration
  const sampleVulnerable = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyXzQ5MTAyIiwicm9sZSI6ImFkbWluIiwiaW50ZXJuYWxfZW1haWwiOiJvcHNAYXBleGZpbi5pbnRlcm5hbCJ9.";
  
  // Sample with HS256 and exp
  const sampleHardened = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzgwMjE5Iiwicm9sZSI6ImN1c3RvbWVyX3RpZXIxIiwiZXhwIjoxNzY0MjgwNDAwLCJpc3MiOiJhcGV4ZmluLmlkZW50aXR5In0.3X9FpE6p8L5e-Q9q4gK...";

  input.value = sampleVulnerable;

  btnSample?.addEventListener("click", () => {
    input.value = sampleVulnerable;
    inspectJwtToken();
  });

  btnValid?.addEventListener("click", () => {
    input.value = sampleHardened;
    inspectJwtToken();
  });

  btnInspect?.addEventListener("click", inspectJwtToken);
  inspectJwtToken();
}

function inspectJwtToken() {
  const raw = document.getElementById("rawJwtInput").value.trim();
  const headerCode = document.getElementById("jwtHeaderDecoded");
  const payloadCode = document.getElementById("jwtPayloadDecoded");
  const warningsList = document.getElementById("jwtWarningsList");
  const postureBadge = document.getElementById("jwtPostureBadge");

  const parts = raw.split(".");
  if (parts.length < 2) {
    warningsList.innerHTML = `<div class="jwt-warn-item danger">Invalid JWT format: Requires header, payload, and signature sections.</div>`;
    return;
  }

  let header = {}, payload = {};
  try {
    header = JSON.parse(decodeBase64Url(parts[0]));
    headerCode.innerText = JSON.stringify(header, null, 2);
  } catch (e) {
    headerCode.innerText = "Error decoding JSON header";
  }

  try {
    payload = JSON.parse(decodeBase64Url(parts[1]));
    payloadCode.innerText = JSON.stringify(payload, null, 2);
  } catch (e) {
    payloadCode.innerText = "Error decoding JSON payload";
  }

  // Security evaluation
  const warnings = [];
  let isHighRisk = false;

  if (header.alg === "none" || header.alg === "NONE") {
    warnings.push({ text: "Critical: Algorithm set to 'none' allows signature verification bypass (CVE-2015-9235 pattern).", danger: true });
    isHighRisk = true;
  }

  if (!payload.exp) {
    warnings.push({ text: "High: Missing expiration ('exp') claim. Token never expires, allowing indefinite replay if intercepted.", danger: true });
    isHighRisk = true;
  } else {
    const expDate = new Date(payload.exp * 1000);
    warnings.push({ text: `Validated: Expiration claim ('exp') present (Expires: ${expDate.toUTCString()}).`, danger: false });
  }

  if (payload.password || payload.secret || payload.ssn) {
    warnings.push({ text: "Critical: Sensitive secrets stored directly in unencrypted base64 payload.", danger: true });
    isHighRisk = true;
  }

  if (parts.length === 3 && parts[2] === "") {
    warnings.push({ text: "High: Empty signature section attached to token.", danger: true });
    isHighRisk = true;
  }

  if (header.alg === "HS256") {
    warnings.push({ text: "Notice: Symmetric HMAC-SHA256 in use. Ensure key entropy is >= 256 bits to prevent offline hashcat cracking.", danger: false });
  }

  postureBadge.innerText = isHighRisk ? "High Risk Identified" : "Passed Token Policy";
  postureBadge.className = isHighRisk ? "tag tag-danger" : "tag tag-verified";

  warningsList.innerHTML = warnings.map(w => `
    <div class="jwt-warn-item ${w.danger ? 'danger' : 'ok'}">
      ${w.danger ? '⚠️' : '✓'} ${w.text}
    </div>
  `).join("");
}

function decodeBase64Url(str) {
  let output = str.replace(/-/g, "+").replace(/_/g, "/");
  switch (output.length % 4) {
    case 0: break;
    case 2: output += "=="; break;
    case 3: output += "="; break;
    default: throw new Error("Illegal base64url string");
  }
  return decodeURIComponent(atob(output).split('').map(function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
}

/* ==========================================================================
   Finding Modal Logic
   ========================================================================== */
function initFindingModal() {
  const modal = document.getElementById("addFindingModal");
  const btnOpen = document.getElementById("btnOpenAddModal");
  const btnClose = document.getElementById("btnCloseAddModal");
  const btnCancel = document.getElementById("btnCancelAdd");
  const form = document.getElementById("addFindingForm");

  btnOpen?.addEventListener("click", () => modal.classList.add("active"));
  btnClose?.addEventListener("click", () => modal.classList.remove("active"));
  btnCancel?.addEventListener("click", () => modal.classList.remove("active"));

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      title: document.getElementById("newTitle").value,
      severity: document.getElementById("newSeverity").value,
      cvss_score: parseFloat(document.getElementById("newCvss").value),
      owasp_category: document.getElementById("newOwasp").value,
      endpoint: document.getElementById("newEndpoint").value,
      description: document.getElementById("newDesc").value,
      remediation: document.getElementById("newRemediation").value
    };

    try {
      const res = await fetch("/api/findings/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.finding) {
        auditState.findings.unshift(data.finding);
        modal.classList.remove("active");
        form.reset();
        renderFindings();
        renderOverview();
        renderQuickTable();
        updateSidebarCounts();
        switchTab("findings");
      }
    } catch (err) {
      alert("Failed to save finding");
    }
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return str.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
