"""
YatraDham Brand & Ashram Fraud Monitor — Production FastAPI Backend Server.
Provides REST APIs for real-time scanning, automated sweep orchestration,
forensic enrichment, takedown generation, case management, and verified registry management.
"""
import asyncio
import csv
import io
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.models import FraudFinding, ThreatCategory, RiskBand, EvidenceItem, CaseStatus
from core.entity_cross_reference import EntityCrossReferencer
from core.enrichment import ForensicEnricher
from core.scorer import FraudRiskScorer
from core.detector_engine import DetectionEngine
from core.takedown_generator import TakedownGenerator
from core.takedown_dispatcher import TakedownDispatcher
from core.evidence_capture import EvidenceCapture
from core.notifier import AlertDispatcher
from core.database import DatabaseManager
from run_sweep import FraudSweepRunner, FINDINGS_PATH, DATA_DIR

SERVER_START_TIME = time.time()
DEBUG_MODE = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yatradham-fraud-monitor")

def get_memory_info() -> Dict[str, float]:
    """Measures process working set and virtual memory portably on Windows and Linux/Render."""
    res = {"rss_mb": 0.0, "vms_mb": 0.0}
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes
            class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
                _fields_ = [
                    ('cb', wintypes.DWORD),
                    ('PageFaultCount', wintypes.DWORD),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t),
                    ('PrivateUsage', ctypes.c_size_t),
                ]
            counters = PROCESS_MEMORY_COUNTERS_EX()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                res["rss_mb"] = round(counters.WorkingSetSize / (1024 * 1024), 2)
                res["vms_mb"] = round(counters.PagefileUsage / (1024 * 1024), 2)
        else:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            res["rss_mb"] = round(usage.ru_maxrss / 1024.0, 2)
    except Exception:
        pass
    return res

def test_network_connectivity() -> Dict[str, bool]:
    import socket
    dns_ok = False
    try:
        socket.gethostbyname("google.com")
        dns_ok = True
    except Exception:
        dns_ok = False
    return {
        "dns_resolution": dns_ok,
        "crt_sh_endpoint": "https://crt.sh",
        "ncrp_portal_endpoint": "https://cybercrime.gov.in"
    }

app = FastAPI(
    title="YatraDham Brand & Ashram Fraud Monitor API",
    description="Live Cyber Threat Intelligence and Brand Protection API for Dharamshalas and Ashrams — Initiative from YatraDham.Org",
    version="2.1.0",
    debug=DEBUG_MODE
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global Core Services
# ---------------------------------------------------------------------------
runner = FraudSweepRunner()
db_manager = DatabaseManager()
takedown_dispatcher = TakedownDispatcher()
evidence_capture = EvidenceCapture()

# Initial DB migration from existing JSON
if os.path.exists(FINDINGS_PATH):
    migrated_count = db_manager.migrate_from_json(FINDINGS_PATH)
    if migrated_count > 0:
        logger.info(f"Synchronized {migrated_count} initial findings into SQLite database.")
        db_manager.cluster_syndicates()

sweep_state = {
    "status": "idle",
    "progress_percent": 0,
    "current_step": "System Ready",
    "started_at": None,
    "finished_at": None,
    "duration_s": 0.0,
    "last_error": None,
    "mode": None
}
sweep_lock = threading.Lock()

def background_sweep_worker(quick: bool):
    global sweep_state
    try:
        with sweep_lock:
            sweep_state["status"] = "running"
            sweep_state["progress_percent"] = 10
            sweep_state["current_step"] = "Initializing detector & loading verified registry..."
            sweep_state["started_at"] = datetime.now(timezone.utc).isoformat()
            sweep_state["mode"] = "quick" if quick else "full"
            sweep_state["last_error"] = None

        time.sleep(1.0)
        with sweep_lock:
            sweep_state["progress_percent"] = 30
            sweep_state["current_step"] = "Running multi-channel sweeps (DNS, crt.sh, open web)..."

        payload = runner.run_sweep(quick=quick)

        # Sync results to DB
        findings = payload.get("findings", [])
        for f in findings:
            db_manager.upsert_finding(f)
        db_manager.cluster_syndicates()

        with sweep_lock:
            sweep_state["status"] = "completed"
            sweep_state["progress_percent"] = 100
            sweep_state["current_step"] = f"Sweep Complete — Scanned {len(findings)} hosts."
            sweep_state["finished_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as e:
        logger.error(f"Background sweep failed: {e}", exc_info=True)
        with sweep_lock:
            sweep_state["status"] = "error"
            sweep_state["last_error"] = str(e)
            sweep_state["current_step"] = f"Error: {e}"

# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, URL, phone number, or UPI ID to inspect")
    debug: bool = Field(False, description="Whether to include detailed step-by-step diagnostic trace")

class DebugToggleRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable deep debug logs and verbose metrics")

class AddInstitutionRequest(BaseModel):
    id: str
    name: str
    official_website: str
    official_phones: List[str] = []
    verified_upis: List[str] = []
    official_trust_account: Optional[str] = None
    known_scam_domains: List[str] = []
    risk_level: str = "HIGH"

class CaseStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="NEW, UNDER_REVIEW, TAKEDOWN_SENT, BLOCKED, RESOLVED, WHITELISTED")
    fir_number: Optional[str] = None
    registrar_ticket: Optional[str] = None
    assigned_analyst: Optional[str] = None
    note: Optional[str] = None

class CaseNoteRequest(BaseModel):
    note: str
    author: Optional[str] = "Analyst"

class DispatchAbuseEmailRequest(BaseModel):
    host: str
    recipient_override: Optional[str] = None
    custom_notes: Optional[str] = None
    dry_run: Optional[bool] = None

class SafeBrowsingRequest(BaseModel):
    url: str

class EvidenceSnapshotRequest(BaseModel):
    host: str

# ---------------------------------------------------------------------------
# System & Diagnostic Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["System"])
def health_check():
    """Health check for load balancers and Render."""
    uptime = round(time.time() - SERVER_START_TIME, 2)
    is_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    return {
        "status": "healthy",
        "service": "YatraDham Brand & Ashram Fraud Monitor",
        "framework": "Initiative from YatraDham.Org",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": uptime,
        "debug_mode": DEBUG_MODE,
        "render_detected": is_render,
        "verified_institutions_loaded": len(runner.ecr.institutions),
        "database_storage": "SQLite3 (Persistent)",
        "sweep_status": sweep_state["status"]
    }

@app.get("/api/debug/system", tags=["Debugging & Diagnostics"])
def get_system_debug_info():
    """Comprehensive system diagnostics."""
    uptime = round(time.time() - SERVER_START_TIME, 2)
    is_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    mem = get_memory_info()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server_uptime_seconds": uptime,
        "uptime_seconds": uptime,
        "debug_mode": DEBUG_MODE,
        "system": {
            "pid": os.getpid(),
            "active_threads": threading.active_count(),
            "python_version": sys.version,
            "platform": sys.platform,
            "memory": mem,
        },
        "environment": {
            "is_render": is_render,
            "render_service_id": os.environ.get("RENDER_SERVICE_ID", "local"),
            "port": os.environ.get("PORT", "8090"),
            "host": os.environ.get("HOST", "0.0.0.0" if is_render else "127.0.0.1"),
            "debug_env": os.environ.get("DEBUG", "false")
        },
        "storage": {
            "database_path": db_manager.db_path,
            "findings_cached": len(db_manager.get_all_findings(limit=5000)),
            "institutions_count": len(runner.ecr.institutions)
        },
        "network": test_network_connectivity()
    }

@app.post("/api/debug/toggle", tags=["Debugging & Diagnostics"])
def toggle_debug_mode(req: DebugToggleRequest):
    global DEBUG_MODE
    DEBUG_MODE = req.enabled
    logging.getLogger().setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
    logger.info(f"Debug Mode toggled to: {DEBUG_MODE}")
    return {
        "status": "success",
        "debug_mode": DEBUG_MODE,
        "message": f"Debug mode is now {'ENABLED' if DEBUG_MODE else 'DISABLED'}"
    }

@app.post("/api/alerts/test", tags=["Alerts"])
def test_alerts():
    """Tests all configured notification channels (Telegram, Slack, Discord, WhatsApp)."""
    return runner.dispatcher.test_channels()

# ---------------------------------------------------------------------------
# Analytics & Findings Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/stats", tags=["Analytics"])
def get_stats():
    """Returns live KPI counters and threat telemetry across all channels."""
    findings = db_manager.get_all_findings(limit=2000)

    hi = [f for f in findings if f.get("risk_score", 0) >= 55 and f.get("risk_band") != "BRAND-OWNED"]
    crit = [f for f in findings if f.get("risk_score", 0) >= 75 and f.get("risk_band") != "BRAND-OWNED"]
    med = [f for f in findings if 35 <= f.get("risk_score", 0) < 55]
    low = [f for f in findings if 0 < f.get("risk_score", 0) < 35]
    owned = [f for f in findings if f.get("risk_band") == "BRAND-OWNED"]
    ashram_attacks = [f for f in findings if f.get("targeted_institution_name") and f.get("risk_score", 0) >= 35]
    phone_attacks = [f for f in findings if (f.get("page", {}).get("copied_phones") or [])]
    upi_attacks = [f for f in findings if (f.get("page", {}).get("upi_ids") or [])]
    cases_open = [f for f in findings if f.get("case_status") in ("NEW", "UNDER_REVIEW", "TAKEDOWN_SENT")]

    return {
        "total_hosts_examined": len(findings),
        "critical_threats": len(crit),
        "high_risk_alerts": len(hi),
        "medium_risk_watch": len(med),
        "low_risk": len(low),
        "cleared_defensive_domains": len(owned),
        "ashram_impersonations": len(ashram_attacks),
        "fraudulent_helplines_detected": len(phone_attacks),
        "scammer_upi_handles_detected": len(upi_attacks),
        "active_cases_open": len(cases_open),
        "last_sweep_timestamp": sweep_state.get("finished_at") or datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/findings", tags=["Findings"])
def list_findings(
    risk_band: Optional[str] = None,
    threat_category: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    min_score: int = 0,
    limit: int = 100,
    offset: int = 0
):
    """Lists scanned hosts from database with flexible filtering, case status, and pagination."""
    findings = db_manager.get_all_findings(limit=2000, min_score=min_score, band=risk_band, status=status)

    filtered = []
    for f in findings:
        if threat_category and f.get("threat_category", "").upper() != threat_category.upper():
            continue
        if search:
            s = search.lower()
            host = f.get("host", "").lower()
            inst = (f.get("targeted_institution_name") or "").lower()
            phones = " ".join(f.get("page", {}).get("copied_phones", [])).lower()
            upis = " ".join(f.get("page", {}).get("upi_ids", [])).lower()
            if s not in host and s not in inst and s not in phones and s not in upis:
                continue
        filtered.append(f)

    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "results": filtered[offset : offset + limit]
    }

@app.get("/api/findings/{host:path}", tags=["Findings"])
def get_finding_detail(host: str):
    """Retrieves full forensic attribution, case notes, and takedown packet for a specific host."""
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    item = db_manager.get_finding(clean_host)
    if item:
        return item

    # Inspect live if not found
    live_finding = runner.inspect_single_host(clean_host)
    db_manager.upsert_finding(live_finding.to_dict())
    return db_manager.get_finding(clean_host) or live_finding.to_dict()

# ---------------------------------------------------------------------------
# Case Management Endpoints
# ---------------------------------------------------------------------------
@app.patch("/api/cases/{host:path}/status", tags=["Case Management"])
def update_case_status(host: str, req: CaseStatusUpdateRequest):
    """Updates case lifecycle status (NEW, UNDER_REVIEW, TAKEDOWN_SENT, BLOCKED, RESOLVED, WHITELISTED)."""
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    valid_statuses = [e.value for e in CaseStatus]
    if req.status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{req.status}'. Must be one of: {valid_statuses}")

    success = db_manager.update_case_status(
        host=clean_host,
        status=req.status,
        fir_number=req.fir_number,
        registrar_ticket=req.registrar_ticket,
        assigned_analyst=req.assigned_analyst
    )
    if req.note:
        db_manager.add_case_note(clean_host, req.note, author=req.assigned_analyst or "Analyst")

    if not success:
        raise HTTPException(status_code=404, detail="Host record not found")
    return {"status": "success", "host": clean_host, "new_case_status": req.status.upper()}

@app.post("/api/cases/{host:path}/notes", tags=["Case Management"])
def add_case_note(host: str, req: CaseNoteRequest):
    """Appends an investigative note or incident update to a host."""
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    db_manager.add_case_note(clean_host, req.note, author=req.author or "Analyst")
    return {"status": "success", "message": "Note recorded"}

# ---------------------------------------------------------------------------
# Threat Syndicates & Correlation
# ---------------------------------------------------------------------------
@app.get("/api/syndicates", tags=["Threat Syndicates"])
def get_syndicates():
    """Returns detected scammer criminal syndicates clustered by shared phones, UPI VPAs, and tracking tags."""
    return {
        "syndicates": db_manager.cluster_syndicates()
    }

@app.post("/api/syndicates/rebuild", tags=["Threat Syndicates"])
def rebuild_syndicates():
    """Forces re-clustering of all threat indicators."""
    syn = db_manager.cluster_syndicates()
    return {"status": "success", "syndicate_count": len(syn), "syndicates": syn}

# ---------------------------------------------------------------------------
# Public Pilgrim Verification Endpoint
# ---------------------------------------------------------------------------
@app.get("/api/verify-channel", tags=["Pilgrim Safety Verification"])
def verify_channel(query: str = Query(..., description="Phone, UPI ID, or URL to check")):
    """
    Public-Facing Pilgrim Protection API.
    Instantly verifies whether a booking channel, phone number, or UPI ID is officially verified
    or identified in active cyber fraud campaigns.
    """
    return db_manager.verify_channel(query)

# ---------------------------------------------------------------------------
# Automated Takedown & Dispatch Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/takedown/dispatch-email", tags=["Takedown"])
def dispatch_abuse_email(req: DispatchAbuseEmailRequest):
    """
    1-Click Automated Abuse Email Dispatch.
    Dispatches formal Cease & Desist notices to Registrar & Host abuse desks.
    """
    clean_host = req.host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    finding_data = db_manager.get_finding(clean_host)
    if not finding_data:
        finding_data = runner.inspect_single_host(clean_host).to_dict()

    res = takedown_dispatcher.dispatch_abuse_email(
        finding_data=finding_data,
        recipient_override=req.recipient_override,
        custom_notes=req.custom_notes,
        dry_run=req.dry_run
    )
    if res.get("success"):
        # Auto-update status to TAKEDOWN_SENT
        db_manager.update_case_status(clean_host, "TAKEDOWN_SENT")
        db_manager.add_case_note(clean_host, f"Abuse notice dispatched to {res.get('recipient')}. Status: {res.get('status')}")

    return res

@app.post("/api/takedown/report-safebrowsing", tags=["Takedown"])
def report_safebrowsing(req: SafeBrowsingRequest):
    """Prepares Google Safe Browsing and Microsoft SmartScreen submission URLs."""
    return takedown_dispatcher.report_safebrowsing_portal(req.url)

@app.post("/api/takedown/evidence-snapshot", tags=["Takedown"])
def capture_evidence(req: EvidenceSnapshotRequest):
    """
    Creates a court-admissible forensic evidence snapshot and visual PNG card with SHA-256 integrity hash.
    """
    clean_host = req.host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    finding_data = db_manager.get_finding(clean_host)
    if not finding_data:
        finding_data = runner.inspect_single_host(clean_host).to_dict()

    snapshot = evidence_capture.capture_snapshot(finding_data)
    # Return card relative path for UI rendering
    if snapshot.get("visual_evidence_card"):
        card_basename = os.path.basename(snapshot["visual_evidence_card"])
        snapshot["visual_card_url"] = f"/evidence/{card_basename}"

    return {
        "status": "success",
        "evidence": snapshot
    }

# ---------------------------------------------------------------------------
# Live Scanning & Sweep Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/scan", tags=["Live Scanning"])
def scan_target(req: ScanRequest):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    include_debug = req.debug or DEBUG_MODE
    t0 = time.perf_counter()

    finding = runner.inspect_single_host(target)
    finding_dict = finding.to_dict()
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    # Save to SQLite DB
    db_manager.upsert_finding(finding_dict)

    # Dispatch alerts if score is high
    if finding.risk_score >= 55:
        runner.dispatcher.process_finding(finding_dict)

    resp = {
        "status": "success",
        "target": target,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "finding": finding_dict
    }

    if include_debug:
        resp["debug_trace"] = {
            "inspection_time_ms": elapsed_ms,
            "resolved_ip": finding.ip,
            "dns_host_info": finding.host_info.__dict__ if hasattr(finding.host_info, "__dict__") else finding.host_info,
            "rdap_registrar": finding.whois.registrar if hasattr(finding.whois, "registrar") else "",
            "crawler_reachable": finding.page.reachable if hasattr(finding.page, "reachable") else False,
            "crawler_status_code": getattr(finding.page, "status_code", None),
            "matched_institution": finding.targeted_institution_name,
            "risk_reasons_count": len(finding.risk_reasons),
            "risk_reasons": finding.risk_reasons,
            "raw_score": finding.risk_score,
            "assigned_band": finding.risk_band.value if hasattr(finding.risk_band, "value") else str(finding.risk_band)
        }

    return resp

@app.post("/api/sweep/trigger", tags=["Sweep Management"])
def trigger_sweep(quick: bool = False, background_tasks: BackgroundTasks = BackgroundTasks()):
    global sweep_state
    if sweep_state["status"] == "running":
        return {
            "status": "already_running",
            "message": "A sweep is currently in progress",
            "sweep_state": sweep_state
        }

    t = threading.Thread(target=background_sweep_worker, args=(quick,))
    t.daemon = True
    t.start()

    return {
        "status": "started",
        "mode": "quick" if quick else "full",
        "message": "Sweep initiated successfully in background"
    }

@app.get("/api/sweep/status", tags=["Sweep Management"])
def get_sweep_status():
    return sweep_state

@app.get("/api/institutions", tags=["Registry"])
def list_institutions():
    return {
        "total": len(runner.ecr.institutions),
        "brand": runner.ecr.brand_data,
        "institutions": runner.ecr.institutions
    }

@app.post("/api/institutions", tags=["Registry"])
def add_institution(inst: AddInstitutionRequest):
    db_file = os.path.join(DATA_DIR, "verified_institutions.json")
    with open(db_file, "r", encoding="utf-8") as f:
        d = json.load(f)

    for existing in d.get("institutions", []):
        if existing["id"] == inst.id:
            raise HTTPException(status_code=400, detail=f"Institution '{inst.id}' already exists")

    d["institutions"].append(inst.dict())
    with open(db_file, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

    runner.ecr.load_database()
    return {"status": "success", "message": f"Added '{inst.name}' to verified directory"}

@app.get("/api/takedown/{host:path}/packet", tags=["Takedown"])
def get_takedown_packet(host: str):
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    finding_data = db_manager.get_finding(clean_host)
    if not finding_data:
        finding_data = runner.inspect_single_host(clean_host).to_dict()

    return {
        "host": clean_host,
        "target_institution": finding_data.get("targeted_institution_name"),
        "risk_score": finding_data.get("risk_score"),
        "takedown": finding_data.get("takedown", {})
    }

@app.get("/api/export/csv", tags=["Export"])
def export_csv():
    findings = db_manager.get_all_findings(limit=2000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Host", "Risk Score", "Risk Band", "Case Status", "Targeted Entity",
        "Server IP", "Hosting Provider", "ASN", "Country",
        "Registrar", "Registered On", "Scammer Helplines", "Scammer UPIs",
        "Detected Via", "Key Triggers"
    ])

    for f in findings:
        h = f.get("host_info", {})
        w = f.get("whois", {})
        p = f.get("page", {})
        writer.writerow([
            f.get("host"),
            f.get("risk_score"),
            f.get("risk_band"),
            f.get("case_status", "NEW"),
            f.get("targeted_institution_name", "General"),
            f.get("ip"),
            h.get("hosting_provider"),
            h.get("asn"),
            h.get("host_country"),
            w.get("registrar"),
            (w.get("created") or "")[:10],
            "; ".join(p.get("copied_phones", [])),
            "; ".join(p.get("upi_ids", [])),
            ", ".join(f.get("sources", [])),
            " | ".join(f.get("risk_reasons", []))
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=yatradham_fraud_findings.csv"}
    )

@app.get("/api/export/json", tags=["Export"])
def export_json():
    findings = db_manager.get_all_findings(limit=2000)
    return JSONResponse(content={"findings": findings})

# ---------------------------------------------------------------------------
# Static Mounting & Dashboard Routes
# ---------------------------------------------------------------------------
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

EVIDENCE_DIR = os.path.join(BASE_DIR, "takedowns", "evidence_snapshots")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
app.mount("/evidence", StaticFiles(directory=EVIDENCE_DIR), name="evidence")

@app.get("/", response_class=HTMLResponse, tags=["Dashboard UI"])
def serve_dashboard():
    index_file = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard index.html not found</h1>"

@app.get("/favicon.ico", include_in_schema=False)
def serve_favicon():
    fav_path = os.path.join(DASHBOARD_DIR, "favicon.ico")
    if os.path.exists(fav_path):
        return FileResponse(fav_path)
    return Response(status_code=204)

def find_available_port(start_port: int = 8090, max_attempts: int = 20) -> int:
    import socket
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start_port

if __name__ == "__main__":
    is_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    default_host = "0.0.0.0" if is_render else "127.0.0.1"
    host = os.environ.get("HOST", default_host)
    requested_port = int(os.environ.get("PORT", 8090))

    if is_render or host == "0.0.0.0":
        port = requested_port
    else:
        port = find_available_port(requested_port)
        if port != requested_port:
            logger.warning(f"Port {requested_port} is currently in use. Auto-switched to available port {port}.")

    print(f"\n==================================================================")
    print(f"🛡️ YatraDham Brand & Ashram Fraud Monitor Server v2.1")
    print(f"📡 API Docs: http://{host}:{port}/docs")
    print(f"🖥️ Live Dashboard: http://{host}:{port}/")
    print(f"🐞 Debug Mode: {'ENABLED' if DEBUG_MODE else 'DISABLED'}")
    print(f"☁️ Cloud Host: {'Render.com Container' if is_render else 'Local Server'}")
    print(f"==================================================================\n")
    uvicorn.run("server:app", host=host, port=port, reload=(not is_render and DEBUG_MODE))
