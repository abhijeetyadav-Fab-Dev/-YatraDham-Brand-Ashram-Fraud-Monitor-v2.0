# 🛡️ YatraDham Brand & Ashram Fraud Monitor v2.1
**Initiative from YatraDham.Org**

---

## 📌 Executive Summary & Architectural Upgrade

The original prototype performed an initial sweep of brand typosquats (e.g., `yatradham-*.com`), certificate transparency logs, and open-web queries. While it correctly identified that YatraDham's own lookalikes (`yatradham.in`, `yatradham.com`, `yatradham.net`, etc.) safely 301-redirect to `yatradham.org`, real-world cyber fraud operators employ multi-layered evasion tactics:

1. **The Ashram & Dharamshala Impersonation Vector**:
   - Scammers rarely typosquat `yatradham.org` directly. Instead, they **impersonate specific high-demand Dharamshalas and Ashrams directly** (e.g., *Bhuj Vishranti Bhavan*, *Shree Khatu Shyam Ji Mandir*, *Salasar Balaji Dharamshala*, *Kedarnath GMVN Cottages*, *Ujjain Mahakal Bhakta Niwas*).
   - Scammers register lookalike domains, create fake Google Business Profiles / YouTube videos / Facebook pages with unauthorized mobile numbers, and dupe devotees into transferring ₹1,000–₹2,000 "advance token deposits" to personal UPI QR codes.
2. **Coordinated Scammer Syndicates**:
   - Criminal networks operate dozens of disposable domains simultaneously sharing identical UPI VPAs, mule phone numbers, hosting subnets, and Google Tag Manager / Analytics containers.
3. **Legal & Law Enforcement Friction**:
   - Cyber complaints require strict evidentiary rigor: court-admissible SHA-256 integrity hashes, TLS certificate fingerprints, and formal statutory filings for both the **National Cyber Crime Reporting Portal (cybercrime.gov.in)** and the **Department of Telecommunications (DoT) Sanchar Saathi / Chakshu portal** for emergency SIM/IMEI blocking.

---

## 🚀 Key Capabilities in Version 2.1

### 1. Persistent SQLite Enterprise Storage & Case Lifecycle Management
- **SQLite Persistence (`core/database.py`)**: Zero-leak connection-scoped database layer storing findings, inspection artifacts, investigation notes, and status histories.
- **Automated Migration**: Seamlessly ingests legacy `dashboard/findings.json` into SQLite on startup without data loss.
- **Case Lifecycle State Machine**: Full workflow transition tracking:
  `NEW` ➔ `UNDER_REVIEW` ➔ `TAKEDOWN_SENT` ➔ `BLOCKED` ➔ `RESOLVED` ➔ `WHITELISTED`.
- **Interactive UI Controls**: Operators can update case statuses, add FIR numbers, and append timestamped investigator notes directly from the dashboard.

### 2. Criminal Syndicate Graph Clustering
- **Syndicate Correlation Engine**: Automatically detects coordinated scam rings by linking targets sharing:
  - Identical unauthorized phone / WhatsApp numbers (`wa.me/91...`)
  - Shared scammer UPI VPAs (`@paytm`, `@ybl`, etc.)
  - Shared Google Tag Manager (`GTM-XXXX`) and Google Analytics (`UA-...`, `G-...`) IDs
  - Colocated hosting providers and `/24` IP subnets
- **Interactive Syndicate Inspector**: View mapped syndicates, risk profiles, and all linked fake booking portals in a dedicated dashboard tab.

### 3. Automated Abuse Dispatch & Google Safe Browsing Integration
- **Automated SMTP Abuse Dispatcher (`core/takedown_dispatcher.py`)**: One-click RFC 2142 compliant abuse email dispatch to domain registrars, hosting providers, and cloud CDNs with dry-run simulation mode and timestamped audit logs.
- **Google Safe Browsing & URLhaus Submission**: Generates automated JSON payloads formatted for Google Web Risk / Safe Browsing client APIs and abuse databases.
- **Multi-Channel Alert Dispatcher (`core/notifier.py`)**: Real-time webhook notifications for Telegram Bot (Markdown), Slack (color-coded blocks), Discord (rich embeds), WhatsApp Business templates, and generic SIEM/SOAR webhooks.

### 4. Court-Admissible Forensic Evidence & Chakshu DoT Packets
- **Forensic Evidence Capture (`core/evidence_capture.py`)**:
  - Captures raw page HTML and computes cryptographic **SHA-256 integrity hashes** for legal chain-of-custody.
  - Extracts TLS certificate thumbprints, SAN extensions, and issuer authorities.
  - Automatically generates **900×520 Court Exhibit Cards (PNG)** formatted with cybercrime classification tags, timestamping, and legal statutory disclaimers.
- **DoT Chakshu Incident Reports (`core/takedown_generator.py`)**: Formal law enforcement dossier for the Department of Telecommunications (Sanchar Saathi) requesting immediate mobile MSISDN disconnection and device IMEI blacklisting under Section 19 of the Telecommunications Act 2023.

### 5. Public Pilgrim Safety Verification API & Widget
- **Devotee Verification Engine (`GET /api/verify-channel?query=...`)**:
  - Devotees can verify any website URL, mobile number, or UPI ID before sending payment.
  - Cross-references verified trust databases and real-time blacklists to deliver immediate verdicts: `GENUINE_VERIFIED`, `KNOWN_SCAM`, `SUSPICIOUS`, or `UNVERIFIED`.
- **Interactive Dashboard Widget**: Embedded safety checker tab allowing pilgrims and customer support agents to conduct rapid safety audits.

---

### 🛠 Directory Structure

```
yatradham-brand-fraud-monitor/
├── data/
│   ├── verified_institutions.json     # Ground truth registry of Ashrams & YatraDham brand
│   └── fraud_monitor.db              # SQLite enterprise database with auto-migration
├── core/
│   ├── models.py                      # Data models, Enums, CaseStatus, Inspection schemas
│   ├── database.py                    # SQLite persistence layer, connection scope & syndicates
│   ├── entity_cross_reference.py      # Cross-referencing & signal extraction
│   ├── detector_engine.py             # 5-channel discovery, GTM/GA/QR/UPI deep crawler
│   ├── enrichment.py                  # DNS, RDAP/WHOIS, ASN, IP Geolocation, SSL
│   ├── scorer.py                      # Explainable 0-100 weighted risk scorer
│   ├── evidence_capture.py            # SHA-256 HTML integrity & PNG court exhibit generator
│   ├── takedown_generator.py          # NCRP, Police, Registrar, NPCI, Chakshu DoT dossiers
│   ├── takedown_dispatcher.py         # Automated RFC 2142 abuse dispatcher & Safe Browsing
│   └── notifier.py                    # Multi-channel alerts (Telegram, Slack, Discord, WA)
├── takedowns/
│   ├── dispatched_notices/            # Timestamped audit logs of dispatched abuse emails
│   └── evidence_snapshots/           # Generated court-admissible PNG evidence cards
├── dashboard/
│   ├── index.html                     # Tactical threat intelligence dashboard & pilgrim widget
│   └── findings.json                  # Ingested baseline findings database
├── scripts/
│   ├── run_scheduled.bat              # Batch runner for automated twice-daily sweeps
│   └── schedule_task.ps1              # Windows Task Scheduler registrar (8 AM & 8 PM IST)
├── tests/
│   ├── test_monitor.py                # Core engine & regression test suite
│   └── test_server_api.py             # FastAPI REST endpoints & lifecycle integration tests
├── run_sweep.py                       # CLI orchestrator
├── server.py                          # FastAPI ASGI application server (v2.1.0)
└── start_server.py                    # Production server starter with port failover
```

---

## 🌐 Live Web Application & REST APIs (Port 8090)

The live application runs on **Port 8090** (free and decoupled from default port 8000 conflicts):

- **Live Dashboard**: [http://127.0.0.1:8090/](http://127.0.0.1:8090/)
- **Interactive Swagger REST API Docs**: [http://127.0.0.1:8090/docs](http://127.0.0.1:8090/docs)
- **API Health Telemetry**: [http://127.0.0.1:8090/api/health](http://127.0.0.1:8090/api/health)
- **System Diagnostics & Telemetry**: [http://127.0.0.1:8090/api/debug/system](http://127.0.0.1:8090/api/debug/system)

### REST API Endpoints:

| Method | Endpoint | Description |
|:---:|---|---|
| `GET` | `/api/health` | Service health, version, uptime, and database metrics |
| `GET` | `/api/findings` | Retrieve all detected threat records with filter by band / status |
| `GET` | `/api/findings/{host}` | Detailed investigation report for a specific host |
| `POST` | `/api/scan` | On-demand scan of domain, URL, mobile number, or UPI ID |
| `PATCH` | `/api/cases/{host}/status` | Update case lifecycle status (`NEW` -> `RESOLVED`) |
| `POST` | `/api/cases/{host}/notes` | Append investigator case notes with timestamp |
| `GET` | `/api/syndicates` | Retrieve mapped scammer syndicates with linked threat nodes |
| `POST` | `/api/syndicates/rebuild` | Re-run graph clustering algorithm over active database |
| `GET` | `/api/verify-channel` | Public Pilgrim Safety Verifier for URLs, phones, or UPI IDs |
| `POST` | `/api/takedown/dispatch-email`| Dispatch RFC 2142 abuse notice (with dry-run simulation) |
| `POST` | `/api/takedown/report-safebrowsing`| Submit threat payload to Google Safe Browsing / Web Risk |
| `POST` | `/api/takedown/evidence-snapshot`| Generate SHA-256 hash & PNG Court Exhibit Card |
| `POST` | `/api/alerts/test` | Test webhook integrations (Telegram, Slack, Discord, WhatsApp) |
| `GET` | `/api/export/csv` | Export entire threat database as CSV |
| `GET` | `/api/export/json` | Export entire threat database as JSON |

### Starting the Server:

#### Option A: One-Click Windows Launcher
Double-click `start_app.bat` to launch the Uvicorn ASGI server and open your browser automatically.

#### Option B: PowerShell / Terminal
```powershell
python start_server.py
```
*(Or start with Debug mode: `python start_server.py --debug`)*

---

## 🐞 Deep Debug Mode & Diagnostics

Debug Mode allows security operators and engineers to inspect real-time system internals, memory allocation, network latency, and exact scoring breakdown reasons:

1. **Dashboard UI Toggle**:
   - Click the **`[🐞 Debug: OFF/ON]`** button in the top navigation bar, or open the dashboard with `http://127.0.0.1:8090/?debug=1`.
   - Expands the **System Diagnostics Drawer** displaying active PID, Python runtime, RSS/VMS memory consumption, cloud host environment, and DNS resolution status.
   - Enables deep forensic traces inside the on-demand scanner showing exact inspection step latency in milliseconds.
2. **Environment Variable**:
   - Set `DEBUG=true` (or `DEBUG=1`) in your terminal or cloud host to activate debug logging system-wide.
3. **CLI Tracing**:
   ```powershell
   python run_sweep.py --inspect "khatushyambooking.org" --debug
   ```
4. **Diagnostic REST Endpoints**:
   - `GET /api/debug/system`: Full snapshot of server uptime, working set memory, active threads, and egress network health.
   - `POST /api/debug/toggle`: Dynamically enable or disable debug mode at runtime without restarting the server.

---

## ☁️ Deploying to Render (render.com) Without Any Issues

The application is pre-configured and tested for native deployment on Render:

### Why It Runs Smoothly on Render:
1. **Dynamic Host & Port Binding**: Automatically reads `$PORT` and binds to `0.0.0.0` when running in cloud/container mode.
2. **Pure Standard Wheels**: No compiler or heavy C extensions required (`fastapi`, `uvicorn[standard]`, `pydantic`, `beautifulsoup4`, `httpx`). Builds in ~15 seconds.
3. **Pre-Bundled Data**: The official ashram registry (`data/verified_institutions.json`) and previous scan database (`dashboard/findings.json`) are bundled in the repository, so the app is instantly populated upon boot.
4. **Resilient Filesystem**: In-memory caching ensures that even if container disk access is delayed or ephemeral, threat detection and API serving never fail.
5. **Pre-Configured Blueprint**: Includes [`render.yaml`](render.yaml) and [`Procfile`](Procfile) for 1-click zero-configuration deployment.

### Quick Deployment Steps:
1. **Push to GitHub / GitLab**.
2. **In Render Dashboard (`dashboard.render.com`)**:
   - Click **New +** → **Web Service**.
   - Connect your repository.
   - Configure:
     - **Runtime**: `Python`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `uvicorn server:app --host 0.0.0.0 --port $PORT`
     - **Health Check Path**: `/api/health`
3. Click **Deploy Web Service**. Your live dashboard will be accessible on your Render URL (`https://your-app.onrender.com`).

---

## 💻 CLI Usage Guide

### 1. Run Quick Sweep (Priority Hotspots & High-Risk Ashrams)
```powershell
python run_sweep.py --quick
```

### 2. Run Comprehensive Full Sweep (All 5 Channels)
```powershell
python run_sweep.py --full
```

### 3. Inspect a Single Target Domain or URL
```powershell
python run_sweep.py --inspect "https://salasarbalajibooking.com"
```

### 4. Verify Ground Truth Registry
```powershell
python run_sweep.py --verify-db
```

### 5. Run Pre-Production Automated Test Suite
```powershell
python -m unittest tests/test_monitor.py
```

### 6. Register Windows Scheduled Tasks (8:00 AM & 8:00 PM IST)
Open PowerShell as Administrator and run:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\schedule_task.ps1
```

---

## 🛡️ Risk Scoring Matrix

| Risk Score | Risk Band | Recommended Action |
|:---:|:---:|---|
| **75 – 100** | `CRITICAL` | Immediate NCRP cybercrime complaint, Registrar abuse notice, NPCI VPA freeze request. |
| **55 – 74** | `HIGH` | Verified impersonation / unauthorized booking helpline. Dispatch takedown packet. |
| **35 – 54** | `MEDIUM` | Suspicious aggregator / UGC mention under surveillance. |
| **1 – 34** | `LOW` | Benign search result / non-infringing web mention. |
| **0** | `BRAND-OWNED` | Verified defensive asset 301-redirecting to `yatradham.org`. Cleared. |
