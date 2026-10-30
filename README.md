# WebAudit 360

**Created by:** Harsh Patel  
**Copyright:** © 2026 WebAudit 360. All Rights Reserved. Made by Harsh Patel.  
**License:** [MIT](LICENSE)

[![CI/CD Pipeline](https://github.com/webaudit360/webaudit360/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.14-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Playwright](https://img.shields.io/badge/Playwright-1.48+-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev)
[![Lighthouse](https://img.shields.io/badge/Lighthouse-13.6-F44B21?logo=lighthouse&logoColor=white)](https://github.com/GoogleChrome/lighthouse)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Executive Overview

**WebAudit 360** is an enterprise-grade website intelligence and continuous health monitoring platform architected and developed by **Harsh Patel**. Unlike shallow URL pingers, synthetic vanity dashboards, or static mockups, WebAudit 360 executes verifiable, multi-layered audits of modern web applications. Every metric, audit finding, score, and recommendation is calculated from genuine network measurements, browser execution traces, DOM analyses, or cryptographic challenges.

The platform combines a modular **FastAPI** backend, **SQLAlchemy 2** relational database, **Celery + Redis** distributed worker fleet, **Playwright Chromium** headless browser instrumentation, **Lighthouse CLI 13.x**, and **axe-core 4.10** automated accessibility evaluation with a zero-framework, high-performance frontend crafted in **Vanilla HTML5, CSS3, and modern JavaScript ES6+ modules**.

---

## Core Product Capabilities & Engine Fleet

```mermaid
flowchart TD
    User([User / Flutter Client]) -->|HTTP / REST| API[FastAPI Application Gateway]
    User <-->|WebSocket| WS[Live Audit Progress Stream]
    API --> SSRF[Multi-Layer SSRF Defense]
    SSRF --> DB[(PostgreSQL / SQLite)]
    SSRF --> Queue[Redis Task Broker]
    Queue --> Worker[Celery Background Workers]
    
    subgraph Engine Fleet
        Worker --> CRAWL[Crawler Engine]
        Worker --> PERF[Lighthouse Performance Engine]
        Worker --> A11Y[axe-core Accessibility Engine]
        Worker --> SEO[SEO Intelligence Engine]
        Worker --> SEC_P[Passive Security Engine]
        Worker --> SEC_A[Authorized Active Security Engine]
        Worker --> RESP[Responsive Design Engine]
        Worker --> TECH[Technology Fingerprinting]
        Worker --> TP[Third-Party Supply Chain]
        Worker --> DOMAIN[Domain & SSL/TLS Health]
    end
    
    Engine Fleet --> Score[Transparent Scoring Algorithm v1.0.0]
    Score --> DB
    Score --> WS
```

### 1. Performance Intelligence Engine
- **Lighthouse CLI 13.x Integration:** Captures raw Lighthouse JSON reports for mobile (Moto G Power emulation) and desktop form factors.
- **Navigation Timing Level 2:** Measures Time to First Byte (TTFB), DOM Interactive, DOM Content Loaded, and Page Load directly via browser performance APIs.
- **Core Web Vitals:** Evaluates Largest Contentful Paint (LCP), Interaction to Next Paint (INP), and Cumulative Layout Shift (CLS).
- **Run Stability:** Supports configurable repeated runs (e.g. 3 iterations) calculating the median to eliminate network noise.

### 2. SEO Intelligence Engine
- **Meta & Header Evaluation:** Title tags (optimal 30–60 characters), meta descriptions (optimal 120–160 characters), and robots directives (`index, follow`).
- **Heading Hierarchy:** Validates the presence of exactly one `<h1>` tag and inspects heading nesting (`<h2>`–`<h6>`).
- **Canonical & Crawl Directives:** Verifies self-referential or cross-domain canonical URLs and checks for `sitemap.xml` references.
- **Open Graph & Structured Data:** Checks Facebook OG and Twitter Card tags, and microdata/JSON-LD schemas.

### 3. Automated Accessibility Engine (axe-core)
- **WCAG 2.1 & 2.2 AA Rules:** Executes `axe-core 4.10` inside headless Chromium via Playwright.
- **Selector Precision:** Reports exact CSS selectors and DOM element snippets for every contrast, missing label, and ARIA violation.
- **Manual Review Boundaries:** Clearly distinguishes automated rule violations from tests requiring human inspection (e.g. video captions, logical focus ordering).

### 4. Passive Security Intelligence Engine
- **Security Headers:** Evaluates HTTP Strict Transport Security (HSTS), Content-Security-Policy (CSP), `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
- **Information Disclosure:** Flags leaky headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Cookie Security Flags:** Checks for `Secure`, `HttpOnly`, and `SameSite` flags on all cookies.

### 5. Authorized Active Security Testing
- **Domain Authorization Gatekeeper:** Strictly prevents active security scanning unless the domain has been verified through a cryptographic DNS TXT challenge (`_webaudit360-challenge.<domain>`) or an HTTP well-known challenge file (`/.well-known/webaudit360-challenge.txt`).
- **Non-Destructive Testing:** Executes read-only security probes adhering to OWASP Web Security Testing Guide (WSTG).

### 6. Responsive Design Intelligence Engine
- **Multi-Viewport Emulation:** Tests page rendering across 3 standard viewports:
  - Mobile: `390 × 844 px`
  - Tablet: `768 × 1024 px`
  - Desktop: `1440 × 900 px`
- **Layout & Overflow:** Detects horizontal scrolling defects (`scrollWidth > clientWidth`) and verifies viewport meta tag presence.
- **Touch Target Sizing:** Validates interactive button and link touch targets against the minimum 48×48 px standard.

### 7. Technical Health Engine
- **Console & Script Exceptions:** Listens for unhandled JavaScript errors and console warnings during live page execution.
- **HTTP Status Code Mapping:** Surfaces broken internal links, classifying 4xx client errors, 5xx server errors, and network timeouts.

### 8. Technology Intelligence Engine
- **Evidence-Based Fingerprinting:** Identifies frontend frameworks (React, Next.js, Vue, Angular), CMS platforms (WordPress), CSS frameworks (Tailwind, Bootstrap), and CDNs (Cloudflare, Vercel).
- **Confidence Scoring:** Assigns a 0.0–1.0 confidence score backed by specific DOM signatures, script URLs, or response headers.

### 9. Third-Party Supply Chain Engine
- **Origin Inventory:** Catalogs all external script, stylesheet, font, and iframe origins.
- **Resource Footprint:** Measures external domain count, highlighting potential supply-chain vulnerabilities and single-point-of-failure risks.

### 10. Domain, DNS & SSL/TLS Health Engine
- **Certificate Validity Chain:** Verifies TLS handshake, certificate issuer, and days remaining until expiration.
- **Certificate Expiration Alerts:** Flags certificates expiring in under 14 days or already expired.
- **Public DNS Records:** Audits A, AAAA (IPv6 readiness), and CAA records (RFC 8659 certificate authority protection).

---

## Anti-SSRF Multi-Layer Defense Architecture

To protect scanning infrastructure and internal networks, WebAudit 360 enforces a multi-tiered Server-Side Request Forgery (SSRF) defense before any network request or browser session is dispatched:

1. **Protocol Whitelisting:** Permits only `http://` and `https://` schemes. All other schemes (`file://`, `gopher://`, `ftp://`, `data:`, `blob:`) are rejected immediately.
2. **Credential Stripping:** Embedded URL credentials (`http://user:pass@domain/`) are rejected to prevent basic auth injection.
3. **Restricted Port Enforcement:** Only standard web ports (80, 443, 8080, 8443) are allowed.
4. **Pre-Flight DNS Resolution:** Resolves target hostnames against public DNS and parses all returned IP addresses.
5. **CIDR Subnet Blocking:** Rejects connections to:
   - Loopback: `127.0.0.0/8`, `::1`
   - RFC 1918 Private Networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local: `169.254.0.0/16`, `fe80::/10`
   - Cloud Provider Metadata Endpoints: `169.254.169.254`, `metadata.google.internal`
   - Carrier-Grade NAT & Multicast: `100.64.0.0/10`, `224.0.0.0/4`
6. **DNS Rebinding Prevention:** Validates resolved IP addresses and pins HTTP socket connections to verified safe IPs.
7. **Redirect Bounds:** Limits HTTP and browser redirects to a maximum of 5 hops, re-validating the destination IP at every hop.

---

## Transparent Scoring Algorithm (v1.0.0)

WebAudit 360 uses a versioned, reproducible scoring formula that eliminates subjective grading. The base formula weights the 5 primary pillars:

$$\text{Overall Score} = (0.25 \times \text{Perf}) + (0.20 \times \text{SEO}) + (0.20 \times \text{A11y}) + (0.25 \times \text{Sec}) + (0.10 \times \text{Tech})$$

### Dynamic Weight Normalization
If an optional module is omitted (e.g. when an unauthenticated scan excludes active security), the algorithm dynamically normalizes the remaining weights so the score remains strictly scaled from 0 to 100:

$$S_{\text{overall}} = \frac{\sum_{i \in M} (w_i \times S_i)}{\sum_{i \in M} w_i}$$

If all categories are missing or unmeasured, the overall score returns `None` and is displayed in the UI as **`N/A`** rather than a fabricated zero.

### Score Rating Bands
- **90 – 100:** Good / Healthy (Green)
- **70 – 89:** Needs Improvement (Yellow)
- **0 – 69:** Poor / Critical (Red)

---

## Frontend Architecture

The frontend is constructed with zero third-party UI frameworks (no React, Next.js, Vue, or Angular) to ensure native browser execution speeds, maximum longevity, and lightweight bundle payloads.

- **Design System:** Classical white default theme (`#F8FAFC` background with `#FFFFFF` cards) with an integrated Spatial Dark Mode toggle.
- **Navigation:** Accessible mobile slide drawer with focus trapping and ESC-key listeners, paired with a persistent desktop sidebar.
- **Controls & Buttons:** Capsule buttons with distinct primary, secondary, and ghost variants.
- **Iconography:** Pure inline Lucide vector SVGs with zero emoji substitutes.
- **Visualizations:** Genuine data-driven Canvas charts using Chart.js.
- **Live Updates:** Native browser WebSocket API for real-time scan progress feeds.
- **Responsive Layout:** Tested across viewports: `320px`, `360px`, `375px`, `390px`, `430px`, `768px`, `1024px`, `1280px`, `1440px`, `1920px`.

---

## Flutter Android Integration Contract

WebAudit 360 is built from day one to serve as the unified backend for future **Flutter mobile and desktop applications**.

- **Stateless Bearer JWT Authentication:** Standard `Authorization: Bearer <access_token>` headers with automated token refresh via `/api/v1/auth/refresh`.
- **OpenAPI 3.0 Compliance:** Fully typed JSON schemas compatible with Dart `freezed` and `json_serializable`.
- **Unified Endpoints:** All mobile features utilize the exact same versioned `/api/v1` routes as the web application.
- **Real-Time WebSocket Protocol:** Standard JSON message frames over `ws://` / `wss://` supported natively by Flutter's `web_socket_channel` package.

---

## Directory Structure

```
WebAudit360/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/
│   │   │   │   ├── auth.py             # User registration, login, JWT refresh, /me
│   │   │   │   ├── projects.py         # Project domain management
│   │   │   │   ├── authorizations.py   # Domain verification challenge tokens
│   │   │   │   ├── audits.py           # Audit initiation, listing, and cancellation
│   │   │   │   ├── findings.py         # Issue lifecycle and individual retest triggers
│   │   │   │   ├── reports.py          # JSON data exports and printable reports
│   │   │   │   ├── monitoring.py       # Recurring schedule configuration
│   │   │   │   ├── health.py           # API and dependency health checks
│   │   │   │   └── websockets.py       # Real-time WebSocket scan progress feeds
│   │   │   ├── router.py               # Combined API v1 router
│   │   │   └── dependencies.py         # Auth injection and token extractors
│   │   ├── core/
│   │   │   ├── config.py               # Pydantic v2 application settings
│   │   │   ├── database.py             # SQLAlchemy 2 async & sync engine
│   │   │   ├── security.py             # Password hashing and JWT generation
│   │   │   ├── ssrf.py                 # Multi-layer SSRF validation and IP resolver
│   │   │   └── logging.py              # Secret-redacting application logger
│   │   ├── engines/
│   │   │   ├── base.py                 # BaseAuditEngine interface & data classes
│   │   │   ├── crawler/engine.py       # Single-page & full-site crawler
│   │   │   ├── performance/engine.py   # Lighthouse CLI 13.x wrapper
│   │   │   ├── seo/engine.py           # SEO meta, heading, and microdata audit
│   │   │   ├── accessibility/engine.py # axe-core Playwright WCAG 2.1/2.2 AA runner
│   │   │   ├── security/passive.py     # Passive security header analysis
│   │   │   ├── security/active.py      # Authorized active security engine
│   │   │   ├── responsive/engine.py    # Multi-viewport emulation engine
│   │   │   ├── technology/engine.py    # Framework and CDN signature detector
│   │   │   ├── third_party/engine.py   # External dependency & origin analyzer
│   │   │   └── domain/engine.py        # DNS records and SSL/TLS certificate chain
│   │   ├── models/
│   │   │   └── entities.py             # SQLAlchemy relational database entities
│   │   ├── schemas/
│   │   │   └── __init__.py             # Pydantic v2 request & response schemas
│   │   ├── scoring/
│   │   │   └── calculator.py           # v1.0.0 scoring formula & dynamic weights
│   │   ├── services/
│   │   │   └── audit_service.py        # Multi-engine audit coordinator
│   │   ├── workers/
│   │   │   ├── celery_app.py           # Celery application configuration
│   │   │   └── tasks.py                # Asynchronous Celery audit execution tasks
│   │   └── main.py                     # FastAPI application factory & static mounts
│   └── migrations/                     # Alembic database migration scripts
├── frontend/
│   ├── css/                            # Modular CSS design system tokens
│   │   ├── variables.css               # Light default and dark spatial themes
│   │   ├── components.css              # Capsule buttons, score pills, inputs
│   │   ├── navigation.css              # Slide drawer and responsive header
│   │   └── ...                         # Page-specific stylesheets
│   ├── js/                             # Native Vanilla ES6+ JavaScript modules
│   │   ├── icons.js                    # Lucide SVG vector definitions
│   │   ├── theme.js                    # Zero-flash dark/light theme switcher
│   │   ├── api.js                      # Fetch wrapper with auto-refresh retry
│   │   ├── auth.js                     # Client-side session state manager
│   │   └── utils.js                    # URL validators, score pills, toasts
│   └── *.html                          # Complete 27-page application ecosystem
├── tests/                              # Pytest automated test suite (23 tests)
├── .github/workflows/ci.yml            # GitHub Actions CI/CD pipeline
├── docker-compose.yml                  # Complete multi-container deployment
├── Dockerfile                          # Multi-stage production container
├── requirements.txt                    # Pinned Python package dependencies
├── alembic.ini                         # Alembic database migration config
├── ARCHITECTURE.md                     # System architecture specification
├── TECHNICAL_RESEARCH.md               # Technical research and REA analysis
├── THREAT_MODEL.md                     # STRIDE threat model & mitigations
├── SECURITY.md                         # Responsible disclosure policy
└── LICENSE                             # MIT License (Harsh Patel)
```

---

## Local Development Setup

### Prerequisites
- **Python:** 3.12 or higher (tested on Python 3.12 and 3.14)
- **Node.js:** 20.x or higher (for Lighthouse CLI)
- **Redis:** 7.x (for background task queues)
- **PostgreSQL:** 16.x (SQLite is supported out-of-the-box for local development)

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/webaudit360/webaudit360.git
cd WebAudit360

# Create and activate Python virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```bash
# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright browser binaries
playwright install chromium
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
```

Review `.env` and set your `SECRET_KEY`. By default, `DATABASE_URL` will automatically fall back to local SQLite (`sqlite+aiosqlite:///./webaudit360.db`) if PostgreSQL is not running.

### 4. Run Database Migrations

```bash
alembic upgrade head
```

### 5. Launch the Development Server

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Open your browser to:
- **Application Web UI:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **OpenAPI JSON Schema:** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

### 6. Launch Celery Background Worker (Optional for Async Queue)

```bash
celery -A backend.app.workers.celery_app worker --loglevel=info
```

---

## Running Automated Tests

WebAudit 360 comes with a comprehensive automated test suite testing SSRF prevention, scoring arithmetic, token authentication, audit queueing, and audit engine execution.

```bash
# Run all tests
pytest -v

# Run tests with test coverage reporting
pytest -v --cov=backend --cov-report=term-missing
```

**Test Suite Verification:**
- 23 of 23 unit and integration tests passing cleanly.
- 75% code coverage across backend routers, core services, and engines.

---

## Docker Compose Production Deployment

To run the full WebAudit 360 production stack with PostgreSQL, Redis, API backend, and Celery workers:

```bash
# Build and launch all services in detached mode
docker-compose up -d --build

# Inspect running containers
docker-compose ps

# Follow application logs
docker-compose logs -f api
```

Services exposed:
- `api`: Web UI and REST API on `http://localhost:8000`
- `worker`: Distributed Celery audit worker
- `postgres`: Persistent database on `localhost:5432`
- `redis`: In-memory broker on `localhost:6379`

---

## API Quick Reference

### 1. User Registration & Authentication

```bash
# Register a new developer account
curl -X POST "http://127.0.0.1:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "alex@example.com", "password": "StrongPassword123!", "full_name": "Alex Developer"}'

# Authenticate and receive JWT access token
curl -X POST "http://127.0.0.1:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "alex@example.com", "password": "StrongPassword123!"}'
```

### 2. Create Project & Request Domain Verification

```bash
# Create a new project container
curl -X POST "http://127.0.0.1:8000/api/v1/projects" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Store", "domain": "store.example.com"}'

# Request a cryptographic DNS TXT challenge token
curl -X POST "http://127.0.0.1:8000/api/v1/authorizations" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"project_id": 1, "domain": "store.example.com", "verification_method": "DNS_TXT"}'

# Verify challenge completion
curl -X POST "http://127.0.0.1:8000/api/v1/authorizations/1/verify" \
  -H "Authorization: Bearer <TOKEN>"
```

### 3. Initiate an Audit & Stream Real-Time Progress

```bash
# Submit an audit job
curl -X POST "http://127.0.0.1:8000/api/v1/audits" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "scan_mode": "SINGLE_PAGE",
    "device_profile": "DESKTOP",
    "modules": ["performance", "seo", "security_passive", "technology", "domain"]
  }'
```

Connect to the WebSocket feed using the returned `audit_id`:
```javascript
const ws = new WebSocket(`ws://127.0.0.1:8000/api/v1/ws/audits/${auditId}`);
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`[Stage ${data.stage}] Progress: ${data.progress}% - ${data.message}`);
};
```

---

## Creator Attribution & Copyright

WebAudit 360 was created and engineered by **Harsh Patel**.

- **Platform:** WebAudit 360
- **Creator:** Harsh Patel
- **Copyright:** © 2026 WebAudit 360. All Rights Reserved. Made by Harsh Patel.
