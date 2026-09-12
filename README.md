# 🛡️ YatraDham Brand & Ashram Fraud Monitor v2.0
**Initiative from YatraDham.Org**

---

## 📌 Executive Summary & Architectural Upgrade

The original prototype performed an initial sweep of brand typosquats (e.g., `yatradham-*.com`), certificate transparency logs, and open-web queries. While it correctly identified that YatraDham's own lookalikes (`yatradham.in`, `yatradham.com`, `yatradham.net`, etc.) safely 301-redirect to `yatradham.org`, it suffered from **three critical operational blindspots**:

1. **The Ashram & Dharamshala Impersonation Blindspot**:
   - In real-world cyber fraud, scammers rarely typosquat `yatradham.org` directly. Instead, they **impersonate specific high-demand Dharamshalas and Ashrams directly** (e.g., *Bhuj Vishranti Bhavan*, *Shree Khatu Shyam Ji Mandir*, *Salasar Balaji Dharamshala*, *Kedarnath GMVN Cottages*, *Ujjain Mahakal Bhakta Niwas*).
   - Scammers register lookalike domains, create fake Google Business Profiles / YouTube videos / Facebook pages with unauthorized mobile numbers, and dupe devotees into transferring ₹1,000–₹2,000 "advance token deposits" to personal UPI QR codes.
2. **False-Positive UPI Tagging**:
   - The previous regex matched corporate bank and grievance emails (e.g., `creditcards@axisbank`, `nodal.officer@axisbank`) and incorrectly penalized them with +25 risk points as "direct UPI collection".
3. **Missing Law Enforcement Dossier & Runnable Pipeline**:
   - The initial export only contained static HTML/JSON files without an automated executable Python engine, cross-referencing ground truth registry, or statutory compliance mapping for the **National Cyber Crime Reporting Portal (cybercrime.gov.in)**.

---

## 🚀 Key Upgrades in Version 2.0

### 1. Ground-Truth Verified Institution Registry (`data/verified_institutions.json`)
- Maintained database of verified top-rated Dharamshalas, Ashrams, and Trust accommodations across India.
- Stores official websites, verified landline/mobile numbers, official trust emails, payment policies, and vulnerability ratings.
- Entity Cross-Referencing Engine (`core/entity_cross_reference.py`) cross-checks any scraped phone number against verified trust contacts and immediately flags mismatched mobile numbers.

### 2. Zero-False-Positive UPI & Payment Gateway Scanner
- Precision filter isolates genuine NPCI Payment Service Provider (PSP) handles (`@paytm`, `@ybl`, `@upi`, `@axl`, `@okhdfcbank`, etc.) and personal 10-digit mobile prefixes (`9XXXXXXXXX@...`).
- Excludes legitimate corporate bank contact addresses (`creditcards@...`, `nodal.officer@...`, `support@...`, `abuse@...`).
- Scans for advance payment pressure language in English and Hindi (*"advance token amount"*, *"send screenshot on WhatsApp"*, *"room held for 15 minutes"*).

### 3. Multi-Channel Detection Engine (`core/detector_engine.py`)
- **Channel 1: Ashram & Brand Permutation Engine**: Generates targeted typosquats for both brand tokens and high-risk religious shrines across `.in`, `.com`, `.org`, `.co.in`, `.online`.
- **Channel 2: Certificate Transparency Logs**: Queries `crt.sh` for newly issued SSL certificates.
- **Channel 3: Live Search Scraper**: Scrapes DuckDuckGo / Bing / open web for fake booking desks, unauthorized customer care numbers, and refund scams.
- **Channel 4: Social Media & UGC Surveillance**: Analyzes Facebook pages, Instagram bios, YouTube descriptions, and WhatsApp direct links (`wa.me/91...`).
- **Channel 5: Deep Page Inspector**: Fetches live HTML, inspects redirects, extracts embedded gateways (Razorpay, Cashfree, PayU), and extracts payment links.

### 4. Statutory Takedown Dossier Generator (`core/takedown_generator.py`)
For every finding scoring ≥ 55, automatically builds an evidence packet:
- **NCRP Complaint Format (cybercrime.gov.in)**: Formatted under *Online Financial Fraud / Fake Website / Cheating by Personation*.
- **Statutory Law Citations**: Cites Sections 66C & 66D of Information Technology Act 2000, and Sections 318(4) & 319 of Bharatiya Nyaya Sanhita (BNS) 2023 (formerly Sections 419/420 IPC).
- **Gujarat / Bhavnagar Cyber Police Memorandum**: Ready for official police submission.
- **Registrar Abuse Notice**: RFC 2142 compliant Cease & Desist citing ICANN RAA Section 3.18.
- **NIXI (.IN Registry) Notice**: Fast-track suspension demand for Indian ccTLD domains.
- **NPCI UPI Freeze Notice**: Demands immediate debit freeze on scammer VPAs and mule bank accounts.

### 5. Tactical Threat Intelligence Dashboard (`dashboard/index.html`)
- Dark tactical UI with live KPI metrics and trend indicators.
- Side-by-side **Discrepancy Inspector** (Scammer Evidence vs Genuine Institution Ground Truth).
- Interactive **Threat Quick-Scanner**: Paste any suspect domain, phone, or UPI handle to get an instant verdict.
- One-click copy buttons for NCRP complaint text, Police Memos, and Registrar Abuse notices.
- Verified Religious Institution Directory tab.

---

## 🛠 Directory Structure

```
yatradham-brand-fraud-monitor/
├── data/
│   └── verified_institutions.json     # Ground truth registry of Ashrams & YatraDham brand
├── core/
│   ├── models.py                      # Data models & schemas
│   ├── entity_cross_reference.py      # Cross-referencing & signal extraction
│   ├── detector_engine.py             # 5-channel discovery & deep crawler
│   ├── enrichment.py                  # DNS, RDAP/WHOIS, ASN, IP Geolocation, SSL
│   ├── scorer.py                      # Explainable 0-100 weighted risk scorer
│   ├── takedown_generator.py          # NCRP, Police, Registrar, NPCI legal dossiers
│   └── notifier.py                    # Multi-channel alerts (Telegram, Slack, Email)
├── dashboard/
│   ├── index.html                     # Tactical threat intelligence dashboard
│   └── findings.json                  # Live output database
├── scripts/
│   ├── run_scheduled.bat              # Batch runner for automated twice-daily sweeps
│   └── schedule_task.ps1              # Windows Task Scheduler registrar (8 AM & 8 PM IST)
├── tests/
│   └── test_monitor.py                # Pre-production automated test suite
├── run_sweep.py                       # CLI orchestrator
└── SWEEP_REPORT.md                    # Executive sweep report
```

---

## 🌐 Live Web Application & REST APIs (Port 8090)

The live application runs on **Port 8090** (free and decoupled from default port 8000 conflicts):

- **Live Dashboard**: [http://127.0.0.1:8090/](http://127.0.0.1:8090/)
- **Interactive Swagger REST API Docs**: [http://127.0.0.1:8090/docs](http://127.0.0.1:8090/docs)
- **API Health Telemetry**: [http://127.0.0.1:8090/api/health](http://127.0.0.1:8090/api/health)
- **System Diagnostics & Telemetry**: [http://127.0.0.1:8090/api/debug/system](http://127.0.0.1:8090/api/debug/system)

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
