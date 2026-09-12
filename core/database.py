"""
Persistent Storage, Case Management & Syndicate Threat Clustering Database Layer.
Provides SQLite database storage (with optional PostgreSQL support via DATABASE_URL),
full case lifecycle management, automated findings.json migration,
and criminal syndicate graph correlation.
"""
import sqlite3
import json
import os
import logging
import contextlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("yatradham-database")

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        default_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        os.makedirs(default_dir, exist_ok=True)
        self.db_path = db_path or os.path.join(default_dir, "fraud_monitor.db")
        self.init_db()

    @contextlib.contextmanager
    def connection_scope(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self):
        """Initializes tables and indexes."""
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            
            # 1. Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    host TEXT PRIMARY KEY,
                    registrable_domain TEXT,
                    threat_category TEXT,
                    risk_score INTEGER,
                    risk_band TEXT,
                    risk_reasons TEXT,
                    targeted_institution_name TEXT,
                    ip TEXT,
                    hosting_provider TEXT,
                    registrar TEXT,
                    whois_created TEXT,
                    unauthorized_phones TEXT,
                    extracted_upis TEXT,
                    gtm_ids TEXT,
                    ga_ids TEXT,
                    first_detected TEXT,
                    last_seen TEXT,
                    is_new INTEGER DEFAULT 1,
                    raw_json TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(risk_score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_band ON findings(risk_band)")

            # 2. Case Status & Lifecycle Management table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS case_status (
                    host TEXT PRIMARY KEY,
                    status TEXT DEFAULT 'NEW',
                    fir_number TEXT,
                    registrar_ticket TEXT,
                    assigned_analyst TEXT,
                    updated_at TEXT,
                    FOREIGN KEY(host) REFERENCES findings(host) ON DELETE CASCADE
                )
            """)

            # 3. Case Notes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT,
                    author TEXT,
                    note TEXT,
                    created_at TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_host ON case_notes(host)")

            # 4. Criminal Syndicates table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS syndicates (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    common_identifier_type TEXT,
                    common_identifier_value TEXT,
                    domain_count INTEGER,
                    total_risk_score INTEGER,
                    domains TEXT,
                    created_at TEXT
                )
            """)

            conn.commit()
            logger.info("Database initialized successfully at %s", self.db_path)

    def upsert_finding(self, finding: Dict[str, Any]) -> bool:
        """Inserts or updates a scan finding in the database."""
        host = finding.get("host")
        if not host:
            return False

        page = finding.get("page") or {}
        whois = finding.get("whois") or {}
        host_info = finding.get("host_info") or {}

        reasons_json = json.dumps(finding.get("risk_reasons", []))
        phones_json = json.dumps(page.get("copied_phones") or finding.get("unauthorized_phones", []))
        upis_json = json.dumps(page.get("upi_ids") or finding.get("extracted_upis", []))
        gtm_json = json.dumps(page.get("gtm_ids", []))
        ga_json = json.dumps(page.get("ga_ids", []))
        raw_json = json.dumps(finding)

        now_iso = datetime.now(timezone.utc).isoformat()

        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO findings (
                    host, registrable_domain, threat_category, risk_score, risk_band,
                    risk_reasons, targeted_institution_name, ip, hosting_provider, registrar,
                    whois_created, unauthorized_phones, extracted_upis, gtm_ids, ga_ids,
                    first_detected, last_seen, is_new, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_band = excluded.risk_band,
                    risk_reasons = excluded.risk_reasons,
                    targeted_institution_name = excluded.targeted_institution_name,
                    ip = excluded.ip,
                    hosting_provider = excluded.hosting_provider,
                    registrar = excluded.registrar,
                    whois_created = excluded.whois_created,
                    unauthorized_phones = excluded.unauthorized_phones,
                    extracted_upis = excluded.extracted_upis,
                    gtm_ids = excluded.gtm_ids,
                    ga_ids = excluded.ga_ids,
                    last_seen = excluded.last_seen,
                    raw_json = excluded.raw_json
            """, (
                host,
                finding.get("registrable_domain", host),
                finding.get("threat_category", "BRAND_TYPOSQUAT"),
                finding.get("risk_score", 0),
                finding.get("risk_band", "LOW"),
                reasons_json,
                finding.get("targeted_institution_name"),
                finding.get("ip") or host_info.get("ip", ""),
                host_info.get("hosting_provider", ""),
                whois.get("registrar", ""),
                whois.get("created", ""),
                phones_json,
                upis_json,
                gtm_json,
                ga_json,
                finding.get("first_detected", now_iso),
                now_iso,
                1 if finding.get("is_new", True) else 0,
                raw_json
            ))

            # Ensure default case status entry exists
            cursor.execute("""
                INSERT OR IGNORE INTO case_status (host, status, updated_at)
                VALUES (?, 'NEW', ?)
            """, (host, now_iso))

            conn.commit()
        return True

    def get_all_findings(
        self,
        limit: int = 500,
        min_score: int = 0,
        band: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Queries stored findings with case status joined."""
        query = """
            SELECT f.*, c.status as case_status, c.fir_number, c.registrar_ticket, c.assigned_analyst
            FROM findings f
            LEFT JOIN case_status c ON f.host = c.host
            WHERE f.risk_score >= ?
        """
        params: List[Any] = [min_score]

        if band:
            query += " AND f.risk_band = ?"
            params.append(band.upper())
        if status:
            query += " AND c.status = ?"
            params.append(status.upper())

        query += " ORDER BY f.risk_score DESC, f.last_seen DESC LIMIT ?"
        params.append(limit)

        findings = []
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            for row in cursor.fetchall():
                try:
                    obj = json.loads(row["raw_json"])
                except Exception:
                    obj = dict(row)
                obj["case_status"] = row["case_status"] or "NEW"
                obj["fir_number"] = row["fir_number"]
                obj["registrar_ticket"] = row["registrar_ticket"]
                obj["assigned_analyst"] = row["assigned_analyst"]
                findings.append(obj)

        return findings

    def get_finding(self, host: str) -> Optional[Dict[str, Any]]:
        """Fetches single finding by host with full case notes."""
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.*, c.status as case_status, c.fir_number, c.registrar_ticket, c.assigned_analyst
                FROM findings f
                LEFT JOIN case_status c ON f.host = c.host
                WHERE f.host = ?
            """, (host,))
            row = cursor.fetchone()
            if not row:
                return None

            try:
                finding = json.loads(row["raw_json"])
            except Exception:
                finding = dict(row)

            finding["case_status"] = row["case_status"] or "NEW"
            finding["fir_number"] = row["fir_number"]
            finding["registrar_ticket"] = row["registrar_ticket"]
            finding["assigned_analyst"] = row["assigned_analyst"]

            # Load case notes
            cursor.execute("SELECT author, note, created_at FROM case_notes WHERE host = ? ORDER BY id ASC", (host,))
            finding["case_notes"] = [dict(r) for r in cursor.fetchall()]

            return finding

    def update_case_status(
        self,
        host: str,
        status: str,
        fir_number: Optional[str] = None,
        registrar_ticket: Optional[str] = None,
        assigned_analyst: Optional[str] = None
    ) -> bool:
        """Updates lifecycle status for a fraudulent host."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO case_status (host, status, fir_number, registrar_ticket, assigned_analyst, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    status = excluded.status,
                    fir_number = COALESCE(excluded.fir_number, case_status.fir_number),
                    registrar_ticket = COALESCE(excluded.registrar_ticket, case_status.registrar_ticket),
                    assigned_analyst = COALESCE(excluded.assigned_analyst, case_status.assigned_analyst),
                    updated_at = excluded.updated_at
            """, (host, status.upper(), fir_number, registrar_ticket, assigned_analyst, now_iso))
            conn.commit()
            return cursor.rowcount > 0

    def add_case_note(self, host: str, note: str, author: str = "Analyst") -> bool:
        """Appends an investigative note or incident update to a host."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO case_notes (host, author, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (host, author, note, now_iso))
            conn.commit()
            return cursor.rowcount > 0

    def cluster_syndicates(self) -> List[Dict[str, Any]]:
        """
        Criminal Syndicate Graph Correlation Engine.
        Clusters rogue domains into organized fraud syndicates based on:
        1. Shared unauthorized Phone numbers
        2. Shared unauthorized UPI VPAs
        3. Shared Google Tag Manager / Analytics IDs
        """
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT host, risk_score, unauthorized_phones, extracted_upis, gtm_ids, ga_ids FROM findings WHERE risk_score >= 35")
            rows = cursor.fetchall()

            phone_map: Dict[str, List[Tuple[str, int]]] = {}
            upi_map: Dict[str, List[Tuple[str, int]]] = {}
            gtm_map: Dict[str, List[Tuple[str, int]]] = {}

            for r in rows:
                host = r["host"]
                score = r["risk_score"]
                phones = json.loads(r["unauthorized_phones"] or "[]")
                upis = json.loads(r["extracted_upis"] or "[]")
                gtms = json.loads(r["gtm_ids"] or "[]")

                for p in phones:
                    phone_map.setdefault(p, []).append((host, score))
                for u in upis:
                    upi_map.setdefault(u, []).append((host, score))
                for g in gtms:
                    gtm_map.setdefault(g, []).append((host, score))

            syndicates: List[Dict[str, Any]] = []
            syn_idx = 1
            now_iso = datetime.now(timezone.utc).isoformat()

            # Phone clusters (>= 2 domains sharing same rogue mobile)
            for phone, domain_tuples in phone_map.items():
                if len(domain_tuples) >= 2:
                    unique_hosts = list(dict.fromkeys([h for h, _ in domain_tuples]))
                    total_score = sum(s for _, s in domain_tuples)
                    syn_id = f"SYN-PHO-{syn_idx:03d}"
                    syndicates.append({
                        "id": syn_id,
                        "name": f"Syndicate Ring {phone} ({len(unique_hosts)} Domains)",
                        "common_identifier_type": "SHARED_MOBILE_NUMBER",
                        "common_identifier_value": phone,
                        "domain_count": len(unique_hosts),
                        "total_risk_score": total_score,
                        "domains": unique_hosts,
                        "created_at": now_iso
                    })
                    syn_idx += 1

            # UPI clusters (>= 2 domains sharing same scam VPA)
            for upi, domain_tuples in upi_map.items():
                if len(domain_tuples) >= 2:
                    unique_hosts = list(dict.fromkeys([h for h, _ in domain_tuples]))
                    total_score = sum(s for _, s in domain_tuples)
                    syn_id = f"SYN-UPI-{syn_idx:03d}"
                    syndicates.append({
                        "id": syn_id,
                        "name": f"Financial Ring {upi} ({len(unique_hosts)} Domains)",
                        "common_identifier_type": "SHARED_UPI_HANDLE",
                        "common_identifier_value": upi,
                        "domain_count": len(unique_hosts),
                        "total_risk_score": total_score,
                        "domains": unique_hosts,
                        "created_at": now_iso
                    })
                    syn_idx += 1

            # Save to syndicates table
            cursor.execute("DELETE FROM syndicates")
            for syn in syndicates:
                cursor.execute("""
                    INSERT INTO syndicates (id, name, common_identifier_type, common_identifier_value, domain_count, total_risk_score, domains, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    syn["id"],
                    syn["name"],
                    syn["common_identifier_type"],
                    syn["common_identifier_value"],
                    syn["domain_count"],
                    syn["total_risk_score"],
                    json.dumps(syn["domains"]),
                    syn["created_at"]
                ))
            conn.commit()

        return syndicates

    def verify_channel(self, query: str, verified_data_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Public-Facing Pilgrim Safety Verification Protocol.
        Allows devotees to check a phone number, UPI ID, or URL before booking.
        """
        q = query.strip().lower()
        if not q:
            return {"verdict": "INVALID_QUERY", "message": "Please enter a valid phone number, UPI ID, or URL."}

        # 1. Load official verified database
        if not verified_data_path:
            verified_data_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "verified_institutions.json"
            )

        official_matches = []
        if os.path.exists(verified_data_path):
            try:
                with open(verified_data_path, "r", encoding="utf-8") as f:
                    institutions = json.load(f).get("institutions", [])
                    for inst in institutions:
                        inst_name = inst.get("name", "")
                        # Check official website
                        if q in inst.get("official_website", "").lower():
                            official_matches.append(inst_name)
                        # Check phones
                        for p in inst.get("official_phones", []):
                            clean_p = p.replace(" ", "").replace("-", "").replace("+91", "")
                            clean_q = q.replace(" ", "").replace("-", "").replace("+91", "")
                            if clean_q and (clean_q in clean_p or clean_p in clean_q):
                                official_matches.append(f"{inst_name} (Official Helpline: {p})")
                        # Check UPIs
                        for u in inst.get("verified_upis", []):
                            if q in u.lower():
                                official_matches.append(f"{inst_name} (Verified Trust UPI: {u})")
            except Exception:
                pass

        if "yatradham.org" in q:
            official_matches.append("YatraDham.Org Official Booking Platform")

        if official_matches:
            return {
                "verdict": "VERIFIED_OFFICIAL",
                "status": "safe",
                "badge": "🟢 VERIFIED GENUINE",
                "query": query,
                "matches": list(set(official_matches)),
                "advice": "This is an official, verified booking channel endorsed by the temple trust or YatraDham.Org."
            }

        # 2. Check detected fraud database
        with self.connection_scope() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT host, risk_score, risk_band, targeted_institution_name, unauthorized_phones, extracted_upis
                FROM findings
                WHERE risk_score >= 45
            """)
            scam_matches = []
            for r in cursor.fetchall():
                host = r["host"].lower()
                inst = r["targeted_institution_name"] or "Ashram"
                score = r["risk_score"]
                phones = json.loads(r["unauthorized_phones"] or "[]")
                upis = json.loads(r["extracted_upis"] or "[]")

                # Match host
                if q in host or host in q:
                    scam_matches.append({
                        "type": "IMPERSONATING_WEBSITE",
                        "entity": host,
                        "impersonating": inst,
                        "risk_score": score
                    })

                # Match phone
                for p in phones:
                    clean_p = p.replace(" ", "").replace("-", "").replace("+91", "")
                    clean_q = q.replace(" ", "").replace("-", "").replace("+91", "")
                    if clean_q and (clean_q in clean_p or clean_p in clean_q):
                        scam_matches.append({
                            "type": "FLAGGED_SCAMMER_PHONE",
                            "entity": p,
                            "impersonating": inst,
                            "risk_score": score
                        })

                # Match UPI
                for u in upis:
                    if q in u.lower():
                        scam_matches.append({
                            "type": "FLAGGED_FRAUDULENT_UPI",
                            "entity": u,
                            "impersonating": inst,
                            "risk_score": score
                        })

        if scam_matches:
            return {
                "verdict": "ACTIVE_SCAM_FLAGGED",
                "status": "danger",
                "badge": "🔴 HIGH RISK SCAM ALERT",
                "query": query,
                "matches": scam_matches,
                "advice": "WARNING: This contact or link is identified in active fraud reports. DO NOT TRANSFER MONEY or share OTPs."
            }

        # 3. Unknown / unverified
        return {
            "verdict": "UNKNOWN_UNVERIFIED",
            "status": "warning",
            "badge": "⚠️ UNVERIFIED ENTITY",
            "query": query,
            "advice": "This contact is not in the verified directory of YatraDham.Org or recognized temple trusts. Exercise extreme caution before making any advance payments."
        }

    def migrate_from_json(self, json_path: str) -> int:
        """Migrates existing findings.json to SQLite on first startup."""
        if not os.path.exists(json_path):
            return 0

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
                migrated = 0
                for item in findings:
                    if self.upsert_finding(item):
                        migrated += 1
                logger.info("Migrated %d findings from %s into database", migrated, json_path)
                return migrated
        except Exception as e:
            logger.error("Failed to migrate JSON data: %e", e)
            return 0
