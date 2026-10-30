# WebAudit 360 — Technical Research & Technology Decisions

**Platform:** WebAudit 360  
**Author & Architect:** Harsh Patel  
**Date of Research:** October 30, 2026  
**Document Status:** Approved & Version-Pinned  

---

## 1. Executive Summary & Research Methodology

WebAudit 360 is architected as an evidence-driven website intelligence platform that conducts multi-layer audits across Performance, SEO, Accessibility, Passive Security, Authorized Active Security, Responsive Behavior, Technical Health, Technology Stack, Visual Regression, Third-Party Dependencies, and Domain Health.

To guarantee that WebAudit 360 is a reliable, production-oriented application rather than a superficial prototype, all technical decisions were derived through evidence-based research into official documentation, specifications (W3C WCAG, Core Web Vitals, IETF RFCs, OWASP WSTG), package maintenance statuses, licensing compliance, and security isolation requirements.

---

## 2. Research & Evaluation of REA (Reverse Engineer Anything)

* **Repository:** `https://github.com/morluto/rea.git` / `rea-agents`
* **Inspection Date:** October 30, 2026
* **License:** Permissive Open Source (MIT/Apache 2.0 compatible)
* **Architecture & Stated Capabilities:**
  REA is an agentic reverse-engineering tool designed to inspect compiled binaries (ELF, Mach-O, PE), Android packages (APK/AAB via JADX), managed assemblies (.NET CLI), packaged JavaScript/Electron applications (ASAR unpacking, bundle parsing), and browser network activity. It operates by correlating static file signatures, symbol tables, bytecode decompilation, and passive runtime execution into an evidence ledger with explicit limitations and unknown resolutions.
* **Applicability to WebAudit 360:**
  1. *Useful Methodologies:* REA's core architectural principle—storing an immutable evidence trail, explicitly categorizing evidence vs. inferences, recording test limitations, and managing "unknowns" rather than fabricating conclusions—directly informs WebAudit 360's Risk Intelligence and Evidence Ledger design.
  2. *JavaScript Bundle & Source Map Analysis:* REA's techniques for parsing webpack/vite/rollup bundles and extracting third-party dependency shapes inform WebAudit 360's `ThirdPartyEngine` and `TechnologyEngine`.
  3. *Distinction from WebAuditing Engines:* REA is **not** a website auditing engine. It does not calculate Core Web Vitals, does not crawl website sitemaps or link trees, does not evaluate WCAG 2.1/2.2 accessibility rules, does not test passive web security headers, and does not conduct OWASP ZAP vulnerability assessments.
* **Technical Decision:** WebAudit 360 adopts REA's evidence-ledger design pattern and bundle-inspection insights for client-side asset discovery, while relying on dedicated, industry-standard auditing tools (Playwright, Lighthouse, axe-core, OWASP ZAP) for actual web domain inspections. No proprietary code is incorporated without explicit license attribution.

---

## 3. Technology Stack Evaluation & Dependency Selection

### 3.1 Backend Application Framework: Python & FastAPI
* **Selected Version:** Python 3.11+ / 3.14 compatibility, FastAPI `0.115.x`+
* **Alternatives Evaluated:**
  * *Django / Django REST Framework:* Rejected due to heavyweight synchronous ORM legacy, rigid administrative coupling, and excessive memory overhead for high-concurrency async crawling and streaming WebSockets.
  * *Node.js / Express or NestJS:* Rejected for the core scanning backend due to Python's superior ecosystem for automated security scanning, data analysis, report generation (WeasyPrint), and native integration with AI/ML tooling.
  * *Go (Golang):* Excellent performance, but lacks native official bindings for accessibility engines (axe-core) and Python's deep ecosystem for security testing (OWASP ZAP API, BeautifulSoup, WeasyPrint).
* **Rationale:** FastAPI provides native asynchronous ASGI throughput (`uvicorn`), strict type validation via Pydantic v2, automatic OpenAPI 3.1 documentation generation, native WebSocket support for real-time scan progress streaming, and seamless dependency injection for clean service architecture.

### 3.2 Database & Persistence: PostgreSQL + SQLAlchemy 2.0 + Alembic
* **Selected Version:** PostgreSQL 16+, SQLAlchemy 2.0.x, Alembic 1.14.x+
* **Alternatives Evaluated:**
  * *MongoDB / Document DB:* Rejected. While audit results are semi-structured, user accounts, project ownership, team memberships, authorization records, monitoring schedules, and finding lifecycles are strictly relational. Document stores introduce data integrity risks for financial/authorization records.
  * *Pure SQLite in Production:* Rejected for production server backend due to file lock contention under concurrent Celery worker writes. Note: SQLite is retained as the local caching engine for the future Flutter mobile application.
* **Rationale:** PostgreSQL offers robust ACID transactions, fine-grained relational integrity, native `JSONB` with GIN indexing for raw Lighthouse metrics and axe-core violation ASTs, and row-level locking for scan job state transitions. SQLAlchemy 2.0 provides modern typed declarative mapping.

### 3.3 Task Queue & Coordination: Celery + Redis
* **Selected Version:** Celery 5.4.x+, Redis 7.2+
* **Alternatives Evaluated:**
  * *FastAPI BackgroundTasks:* Rejected for auditing jobs. `BackgroundTasks` run inside the ASGI web process; running Chromium, Lighthouse, or network crawler jobs inside the web server would cause severe event-loop starvation, memory bloat, and process crashes.
  * *RabbitMQ:* Highly capable AMQP broker, but Redis serves dual purposes: lightweight task broker and ultra-fast Pub/Sub for worker progress streaming to FastAPI WebSocket gateways.
* **Rationale:** Celery allows dedicated, isolated worker pools (`crawler_queue`, `browser_queue`, `security_queue`) with per-task timeouts, bounded concurrency, task revocation, and separate resource limits. Redis provides transient state coordination and rate-limiting counters.

### 3.4 Browser Automation: Playwright with Headless Chromium
* **Selected Version:** Playwright 1.49.x+ (Python async API)
* **Alternatives Evaluated:**
  * *Selenium WebDriver:* Rejected due to high latency, brittle session handling, complex grid setup, and inferior request/response interception capabilities compared to Chrome DevTools Protocol (CDP).
  * *Puppeteer (Node.js only):* Requires running a separate Node process wrapper from Python, adding IPC overhead.
* **Rationale:** Playwright Python provides async CDP access, flawless emulation of mobile/desktop viewports and user agents, full network request/response lifecycle interception (crucial for detecting third-party assets, broken scripts, console errors, and mixed content), and direct in-page JavaScript evaluation.

### 3.5 Performance Engine: Google Lighthouse CLI
* **Selected Version:** Lighthouse CLI 13.x+ (`lighthouse@13.6.0`)
* **Alternatives Evaluated:**
  * *Basic Page Speed / curl timing:* Rejected. Only measures TTFB and network transfer, ignoring DOM parsing, render-blocking CSS/JS, hydration, layout shifts, and CPU execution bottlenecks.
  * *Cloud PageSpeed Insights API exclusively:* Rejected as the primary engine. Relies on external Google API quotas and cannot test intranet or staging environments. CrUX data is incorporated as an optional field data complement when available.
* **Rationale:** Lighthouse CLI provides standard lab metrics: First Contentful Paint (FCP), Largest Contentful Paint (LCP), Cumulative Layout Shift (CLS), Total Blocking Time (TBT), and Speed Index, along with comprehensive optimization diagnostics (unused CSS, image compression, font display).

### 3.6 Accessibility Engine: axe-core via Playwright
* **Selected Version:** axe-core 4.10.x
* **Alternatives Evaluated:**
  * *HTML CodeSniffer (HTMLCS):* Less actively maintained, fewer WCAG 2.1/2.2 AA success criteria covered, higher false positive rate.
  * *Pa11y CLI wrapper:* Adds an unnecessary Node.js CLI layer over Playwright.
* **Rationale:** axe-core is the gold standard for automated accessibility testing, built by Deque. Evaluating `axe.min.js` directly within Playwright page contexts guarantees zero false positives for covered rules, precise CSS selectors, HTML snippet extraction, and direct WCAG 2.0/2.1/2.2 guideline mappings.

### 3.7 Security Auditing: Passive Analysis Engine + Authorized OWASP ZAP
* **Selected Methodology:** OWASP Web Security Testing Guide (WSTG v4.2)
* **Components:**
  * *Passive Security Engine (Built-in Python HTTPX/SSL):* Inspects HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), SSL/TLS certificate chains, cipher suites, cookie security flags (Secure, HttpOnly, SameSite), and sensitive info disclosure.
  * *Authorized Active Security Engine:* Integrates OWASP ZAP (ZAP API client) only after strict, multi-step domain ownership verification (DNS TXT record or `.well-known/webaudit360-challenge.txt`). Active vulnerability scanning is strictly non-destructive, rate-limited, and prohibited against unverified targets.

### 3.8 Document & PDF Report Generation: WeasyPrint & Jinja2
* **Selected Version:** WeasyPrint 62.x+ / Jinja2 3.1.x+
* **Alternatives Evaluated:**
  * *Puppeteer / Chromium Print to PDF:* Heavyweight, unpredictable page break control, complex header/footer pagination.
  * *ReportLab:* Highly programmatic and brittle for complex modern responsive layouts.
* **Rationale:** WeasyPrint compiles semantic HTML5 and CSS Paged Media (`@page`, page counters, running headers) into professional, publication-quality PDF documents with full vector styling, charts, and exact visual hierarchy.

### 3.9 Frontend Architecture: Semantic HTML5, Modular CSS3 & Vanilla JavaScript ES6+
* **Standards:** Native JavaScript Modules (`type="module"`), CSS Custom Properties, Semantic HTML.
* **Alternatives Evaluated:**
  * *React / Next.js / Vue / Angular:* Explicitly rejected per user requirement. Heavy build toolchains, hydration penalties, framework version churn, and excessive JavaScript bundle size detract from lightweight, transparent platform delivery.
* **Rationale:** Vanilla JavaScript ES6+ with native ES modules provides zero-dependency speed, instant load times, straightforward debugging, and pure browser compatibility. Chart.js (v4.4+) provides vector canvas charts. Lucide SVG icons provide clean visual clarity.

---

## 4. Mobile & Flutter Compatibility Architecture

WebAudit 360 is engineered from Day 1 to support an official Flutter mobile client (Android / iOS):
1. **Shared Versioned REST API (`/api/v1`):** All endpoints return strictly validated, camelCase/snake_case JSON schemas generated from Pydantic models.
2. **Stateless JWT Authentication:** Short-lived access tokens (15 minutes) paired with rotating refresh tokens stored securely (Flutter `flutter_secure_storage`).
3. **Optimized Payloads & Pagination:** All list endpoints (`/audits`, `/findings`, `/projects`, `/pages`) enforce cursor-based or offset-limit pagination to prevent mobile memory exhaustion.
4. **Offline SQLite Caching Contract:** The backend response schemas contain entity timestamps (`created_at`, `updated_at`, `version`) allowing the Flutter client to maintain an offline cache using SQLite / Drift without diverging from server-side truth.
5. **Push Notification Webhook / FCM Readiness:** Scan lifecycle events trigger webhook and push notifications, allowing mobile users to receive alerts when continuous monitoring detects score regressions or certificate expirations.

---

## 5. Summary of Selected Versions & Licenses

| Component | Selected Technology | Version | License | Justification |
| :--- | :--- | :--- | :--- | :--- |
| **API Framework** | FastAPI | 0.115.6 | MIT | High async performance, Pydantic v2 validation, OpenAPI |
| **ASGI Server** | Uvicorn (standard) | 0.32.1 | BSD-3-Clause | Production-grade async HTTP & WebSocket server |
| **ORM / Data Access**| SQLAlchemy | 2.0.36 | MIT | Typed async/sync queries, JSONB support, robust migrations |
| **Migrations** | Alembic | 1.14.0 | MIT | Industry-standard schema versioning and rollback |
| **Task Queue** | Celery | 5.4.0 | BSD-3-Clause | Distributed worker model, task routing, isolated queues |
| **Message Broker** | Redis | 7.2+ | BSD-3-Clause | In-memory queue, pub/sub, atomic rate limiting |
| **Browser Engine** | Playwright (Chromium)| 1.49.1 | Apache 2.0 | CDP integration, reliable network interception, headless |
| **Performance** | Lighthouse CLI | 13.6.0 | Apache 2.0 | Standard Core Web Vitals and lab diagnostics |
| **Accessibility** | axe-core | 4.10.2 | MPL 2.0 | Zero false-positive automated WCAG testing |
| **HTTP Client** | HTTPX | 0.28.1 | BSD-3-Clause | Async HTTP/2, strict timeouts, custom transport for SSRF |
| **HTML Parser** | BeautifulSoup4 / lxml| 4.12.3 / 5.3.0 | MIT / BSD | Fast, resilient DOM parsing for crawl and SEO analysis |
| **PDF Generation** | WeasyPrint | 62.3 | BSD-3-Clause | CSS Paged Media standard compliance, crisp PDF export |
| **Frontend Charts**| Chart.js | 4.4.7 | MIT | Canvas-based data charts, responsive, no framework lock-in |
| **Frontend Icons** | Lucide SVG | 0.460.0 | ISC | Crisp vector SVG icons with consistent stroke weight |

---

## 6. Known Limitations & Research Insights

1. **Automated Accessibility Scope:** Automated scanning tools like axe-core cover approximately 30%–40% of WCAG success criteria (color contrast, alt text presence, ARIA syntax, label association). Contextual criteria (e.g., reading order, meaningful alternative text, screen reader audio descriptions) require human evaluation. The platform must explicitly label these as "Manual Review Required" rather than "Passed".
2. **Device Emulation vs. Physical Devices:** Playwright emulates viewport size, device pixel ratio, and user-agent string. While accurate for layout and responsive rendering, it cannot replicate physical GPU characteristics or cellular latency jitter. The platform clearly labels viewport tests as "Emulated Viewport Audit".
3. **Lab vs. Field Performance:** Lighthouse CLI provides synthetic lab measurements under throttled CPU/network conditions. Real user metrics (CrUX) represent aggregated 28-day historical data from Chrome users. WebAudit 360 displays them in distinct, non-overlapping panels with transparent attribution.
4. **SSRF Risks in Website Auditing:** Crawling arbitrary URLs submitted by users introduces Server-Side Request Forgery risks (e.g., targets resolving to `127.0.0.1`, AWS metadata `169.254.169.254`, or internal VPC subnets). A dedicated custom DNS resolver and socket connection validator must enforce strict outbound network boundaries.
