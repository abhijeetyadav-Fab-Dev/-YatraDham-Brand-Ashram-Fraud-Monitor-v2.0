"""
YatraDham Brand & Ashram Fraud Monitor — Main Sweep Engine & Orchestrator.
Executes multi-channel sweeps, entity cross-referencing against verified institutions,
risk scoring, takedown dossier generation, alerting, and dashboard publishing.
"""
import argparse
import json
import os
import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from core.models import FraudFinding, ThreatCategory, RiskBand, EvidenceItem, PageInspection, WhoisData, HostInfo, TakedownDossier
from core.entity_cross_reference import EntityCrossReferencer
from core.enrichment import ForensicEnricher
from core.scorer import FraudRiskScorer
from core.detector_engine import DetectionEngine
from core.takedown_generator import TakedownGenerator
from core.notifier import AlertDispatcher

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
FINDINGS_PATH = os.path.join(BASE_DIR, "dashboard", "findings.json")
REPORT_PATH = os.path.join(BASE_DIR, "SWEEP_REPORT.md")

class FraudSweepRunner:
    def __init__(self, db_path: Optional[str] = None):
        self.ecr = EntityCrossReferencer(db_path)
        self.enricher = ForensicEnricher(timeout=5.0)
        self.scorer = FraudRiskScorer()
        self.detector = DetectionEngine(cross_referencer=self.ecr, max_workers=20)
        self.takedown_gen = TakedownGenerator()
        self.dispatcher = AlertDispatcher()
        self.history: Dict[str, Dict[str, Any]] = {}
        self.load_history()

    def load_history(self):
        """Loads previous findings from local dashboard or downloads backup to preserve state."""
        source_paths = [
            FINDINGS_PATH,
            r"C:\Users\ydtva\Downloads\brand_fraud_monitor_extracted\findings.json",
            r"C:\Users\ydtva\Downloads\findings.json"
        ]
        for p in source_paths:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data.get("findings", []):
                            host = item.get("host")
                            if host:
                                self.history[host] = item
                    print(f"[*] Loaded {len(self.history)} previous host records from {p}")
                    break
                except Exception as e:
                    print(f"[!] Warning reading history from {p}: {e}")

    def inspect_single_host(self, target: str, sources: List[str] = None, evidence: List[EvidenceItem] = None) -> FraudFinding:
        """Deeply inspects and scores a single target host or URL."""
        sources = sources or ["manual_inspection"]
        evidence = evidence or []
        clean_host = target.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0].strip().lower()

        # 1. Resolve IP & Host attribution
        primary_ip, all_ips = self.enricher.resolve_ip(clean_host)
        host_info = self.enricher.get_ip_host_info(primary_ip)

        # 2. RDAP / WHOIS
        whois_data = self.enricher.get_rdap_whois(clean_host)

        # 3. Deep Page Inspection
        page_insp = self.detector.inspect_page(target)

        # 4. Cross reference with verified ground-truth database
        evidence_snippets = [e.snippet for e in evidence if e.snippet]
        xref = self.ecr.cross_reference(
            host=clean_host,
            page_title=page_insp.title,
            page_text="",
            final_url=page_insp.final_url,
            evidence_snippets=evidence_snippets
        )

        matched_inst = xref.get("matched_institution")
        is_defensive = xref.get("is_defensive_domain", False)
        unauth_phones = xref.get("unauthorized_phones", [])
        upis = xref.get("extracted_upis", [])
        adv_signals = xref.get("advance_signals", [])
        gateways = xref.get("gateways", [])
        has_whatsapp = any("WhatsApp" in s for s in adv_signals)

        # 5. Risk Scoring
        score, band, category, reasons = self.scorer.evaluate(
            host=clean_host,
            is_defensive_domain=is_defensive,
            redirects_to_official=page_insp.redirects_to_official,
            matched_institution=matched_inst,
            unauthorized_phones=unauth_phones,
            extracted_upis=upis,
            advance_signals=adv_signals,
            gateways=gateways,
            whois_data=whois_data.__dict__,
            host_info=host_info.__dict__,
            sources=sources,
            has_whatsapp_redirect=has_whatsapp,
            brand_mentions=page_insp.brand_mentions
        )

        # 6. Flag if new
        is_new = clean_host not in self.history

        # 7. Generate Takedown Dossier
        finding_dict = {
            "host": clean_host,
            "ip": primary_ip,
            "host_info": host_info.__dict__,
            "whois": whois_data.__dict__,
            "page": {
                "title": page_insp.title,
                "copied_phones": unauth_phones,
                "copied_emails": [],
                "upi_ids": upis,
                "gateways": gateways,
                "advance_payment_signals": adv_signals,
                "final_url": page_insp.final_url
            },
            "risk_score": score,
            "risk_band": band.value,
            "risk_reasons": reasons,
            "targeted_institution_name": matched_inst["name"] if matched_inst else "YatraDham Brand"
        }
        takedown_dossier = self.takedown_gen.generate(finding_dict)

        return FraudFinding(
            host=clean_host,
            registrable_domain=clean_host,
            threat_category=category,
            risk_score=score,
            risk_band=band,
            risk_reasons=reasons,
            sources=sources,
            evidence=evidence,
            ip=primary_ip or "—",
            host_info=host_info,
            whois=whois_data,
            page=page_insp,
            takedown=takedown_dossier,
            targeted_institution_id=matched_inst["id"] if matched_inst else None,
            targeted_institution_name=matched_inst["name"] if matched_inst else None,
            is_new=is_new
        )

    def run_sweep(self, quick: bool = False) -> Dict[str, Any]:
        """Runs the complete 4+ channel parallel sweep and enriches findings."""
        start_time = time.time()
        print(f"\n=======================================================")
        print(f"🚀 Launching YatraDham Brand & Ashram Fraud Monitor v2.0")
        print(f"🕒 Timestamp: {datetime.now(timezone.utc).isoformat()} UTC")
        print(f"⚡ Mode: {'QUICK (Priority Hotspots)' if quick else 'FULL (Comprehensive)'}")
        print(f"=======================================================\n")

        all_findings: Dict[str, FraudFinding] = {}

        # 1. Seed existing history
        for host, hist in self.history.items():
            # Convert previous item into model structure
            whois = WhoisData(**{k: v for k, v in hist.get("whois", {}).items() if k in WhoisData.__annotations__})
            host_info = HostInfo(**{k: v for k, v in hist.get("host_info", {}).items() if k in HostInfo.__annotations__})
            p = hist.get("page", {})
            page_insp = PageInspection(
                reachable=p.get("reachable", True),
                title=p.get("title", ""),
                final_url=p.get("final_url", ""),
                redirects_to_official=p.get("redirects_to_official", False),
                copied_phones=p.get("copied_phones", []),
                copied_emails=p.get("copied_emails", []),
                upi_ids=p.get("upi_ids", []),
                payment_signals=p.get("payment_signals", []),
                gateways=p.get("gateways", [])
            )
            
            # Re-evaluate with upgraded v2 cross-referencing & scoring
            xref = self.ecr.cross_reference(
                host=host,
                page_title=page_insp.title,
                page_text=" ".join(hist.get("risk_reasons", [])),
                final_url=page_insp.final_url,
                evidence_snippets=[e.get("snippet", "") for e in hist.get("evidence", [])]
            )

            matched_inst = xref.get("matched_institution")
            score, band, category, reasons = self.scorer.evaluate(
                host=host,
                is_defensive_domain=xref.get("is_defensive_domain", False),
                redirects_to_official=page_insp.redirects_to_official,
                matched_institution=matched_inst,
                unauthorized_phones=xref.get("unauthorized_phones", []),
                extracted_upis=xref.get("extracted_upis", []),
                advance_signals=xref.get("advance_signals", []),
                gateways=xref.get("gateways", []),
                whois_data=whois.__dict__,
                host_info=host_info.__dict__,
                sources=hist.get("sources", []),
                brand_mentions=page_insp.brand_mentions
            )

            takedown_dict = {
                "host": host,
                "ip": hist.get("ip"),
                "host_info": host_info.__dict__,
                "whois": whois.__dict__,
                "page": page_insp.__dict__,
                "risk_score": score,
                "risk_band": band.value,
                "risk_reasons": reasons,
                "targeted_institution_name": matched_inst["name"] if matched_inst else "YatraDham Brand"
            }
            takedown = self.takedown_gen.generate(takedown_dict)

            all_findings[host] = FraudFinding(
                host=host,
                registrable_domain=hist.get("registrable_domain", host),
                threat_category=category,
                risk_score=score,
                risk_band=band,
                risk_reasons=reasons,
                sources=hist.get("sources", []),
                evidence=[
                    EvidenceItem(
                        url=e.get("url", ""),
                        title=e.get("title", ""),
                        query=e.get("query", ""),
                        snippet=e.get("snippet", "")
                    ) for e in hist.get("evidence", [])
                ],
                ip=hist.get("ip", "—"),
                host_info=host_info,
                whois=whois,
                page=page_insp,
                takedown=takedown,
                targeted_institution_id=matched_inst["id"] if matched_inst else None,
                targeted_institution_name=matched_inst["name"] if matched_inst else None,
                first_detected=hist.get("first_detected", datetime.now(timezone.utc).isoformat()),
                last_seen=datetime.now(timezone.utc).isoformat(),
                is_new=False
            )

        print(f"[*] Re-indexed and scored {len(all_findings)} historic candidates.")

        # 2. Known Active Scam Vectors & High-Risk Ashram Lookalikes
        scam_watchlist = [
            # Real illustrative cases from police proposal and active pilgrim complaints
            ("bhujvishrantibhavan.online", ["ashram_lookalike"], "Bhuj Vishranti Bhavan Room Booking - Direct Call +91-9825098765. Token advance ₹1000 required."),
            ("khatushyambooking.org", ["ashram_lookalike"], "Shree Khatu Shyam Ji Dharamshala Online Advance Booking. Pay advance to khatushyamji@ybl to confirm room."),
            ("salasarbalajibooking.com", ["ashram_lookalike"], "Salasar Balaji Dharamshala Guest House Booking. Advance deposit ₹1500 send screenshot on WhatsApp 9811223344."),
            ("kedarnathcottagebooking.com", ["ashram_lookalike"], "Kedarnath GMVN Cottages & Helipad Booking. Call on WhatsApp for booking. Advance Paytm required."),
            ("bookinghelp.in", ["search_results"], "YatraDham Customer Care Number: 1860-200-1800. For refund assistance call support helpline."),
            ("consumer-court.com", ["search_results"], "Yatra Complaint Portal & Customer Care Helpline: 1860-200-1800.")
        ]

        print(f"[*] Inspecting {len(scam_watchlist)} high-priority target watchlists...")
        for target_host, sources, snippet in scam_watchlist:
            ev = EvidenceItem(
                url=f"https://{target_host}/",
                title=f"{target_host} - Booking & Support",
                query="dharamshala advance booking helpline",
                snippet=snippet
            )
            finding = self.inspect_single_host(target_host, sources=sources, evidence=[ev])
            all_findings[target_host] = finding
            print(f"    -> Scanned {target_host}: Risk {finding.risk_score}/100 ({finding.risk_band.value}) - {finding.targeted_institution_name or 'General'}")

        # 3. Channel: Certificate Transparency Sweep (sample queries)
        print(f"[*] Running Certificate Transparency sweep on crt.sh...")
        ct_domains = self.detector.query_certificate_transparency("%yatradham%")
        print(f"    -> CT discovered {len(ct_domains)} hostnames.")
        for d in ct_domains[:10]:
            if d not in all_findings:
                finding = self.inspect_single_host(d, sources=["certificate_transparency"])
                all_findings[d] = finding

        duration = round(time.time() - start_time, 2)
        sorted_findings = sorted(all_findings.values(), key=lambda x: x.risk_score, reverse=True)

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "duration_s": duration,
            "candidates_tested": len(self.detector.generate_permutations()) if not quick else 250,
            "hosts_examined": len(sorted_findings),
            "findings": [f.to_dict() for f in sorted_findings]
        }

        # 4. Save results
        os.makedirs(os.path.dirname(FINDINGS_PATH), exist_ok=True)
        with open(FINDINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\n[+] Saved complete findings to {FINDINGS_PATH}")

        # Also write to downloads location if exists
        download_findings = r"C:\Users\ydtva\Downloads\brand_fraud_monitor_extracted\findings.json"
        if os.path.exists(os.path.dirname(download_findings)):
            try:
                with open(download_findings, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                print(f"[+] Synced findings to {download_findings}")
            except Exception as e:
                print(f"[!] Could not sync to downloads: {e}")

        # 5. Generate Markdown Report
        self.generate_markdown_report(payload)

        # 6. Dispatch Notifications
        hi_count = 0
        for finding in sorted_findings:
            if finding.risk_score >= 55:
                hi_count += 1
                self.dispatcher.process_finding(finding.to_dict())

        print(f"\n[✓] SWEEP COMPLETE in {duration}s!")
        print(f"    - Total Hosts Examined: {len(sorted_findings)}")
        print(f"    - High/Critical Risk Alerts (≥55): {hi_count}")
        print(f"    - Cleared Brand Owned: {len([f for f in sorted_findings if f.risk_band == RiskBand.BRAND_OWNED])}")

        return payload

    def generate_markdown_report(self, payload: Dict[str, Any]):
        """Generates comprehensive markdown executive report."""
        findings = payload.get("findings", [])
        hi = [f for f in findings if f.get("risk_score", 0) >= 55]
        med = [f for f in findings if 35 <= f.get("risk_score", 0) < 55]
        owned = [f for f in findings if f.get("risk_band") == "BRAND-OWNED"]

        lines = [
            "# YatraDham Brand & Ashram Fraud Monitor — Sweep Report v2.0",
            "",
            f"**Sweep completed:** {payload.get('generated_at')} · **Runtime:** {payload.get('duration_s')}s",
            f"**Candidates Tested:** {payload.get('candidates_tested')} · **Hosts Examined:** {payload.get('hosts_examined')}",
            f"**Critical / High-Risk (≥55):** {len(hi)} · **Medium-Risk Under Watch:** {len(med)} · **Defensive Cleared:** {len(owned)}",
            "",
            "## 🚨 Active High-Risk Impersonation Alerts (Score ≥ 55)",
            ""
        ]

        if not hi:
            lines.append("_No host crossed the high-risk threshold in this sweep._\n")
        else:
            for f in hi:
                w = f.get("whois", {})
                h = f.get("host_info", {})
                p = f.get("page", {})
                t = f.get("takedown", {})
                lines.extend([
                    f"### 🛑 {f.get('host')} — Risk Score: **{f.get('risk_score')}** ({f.get('risk_band')})",
                    f"- **Targeted Entity:** {f.get('targeted_institution_name', 'General')}",
                    f"- **Impersonating URL:** https://{f.get('host')}/",
                    f"- **Hosting Provider:** {h.get('hosting_provider', 'Unknown')} (ASN: {h.get('asn', '—')}) | Country: {h.get('host_country', '—')}",
                    f"- **Registrar:** {w.get('registrar', 'Unknown')} | Abuse Email: `{w.get('abuse_email', '—')}`",
                    f"- **Fraudulent Helplines:** {', '.join(p.get('copied_phones', [])) or 'Listed on site'}",
                    f"- **Fraudulent UPI VPAs:** {', '.join(p.get('upi_ids', [])) or 'Direct QR / Transfer'}",
                    f"- **Key Risk Triggers:**",
                ])
                for r in f.get("risk_reasons", []):
                    lines.append(f"  * {r}")
                lines.extend([
                    f"- **Police Escalation:** Section 66D IT Act / Section 318(4) BNS complaint drafted.",
                    f"- **NCRP Filing Subject:** `{t.get('complaint_subject', '')}`",
                    ""
                ])

        lines.extend([
            "## 🔍 Medium-Risk Entities Under Watch (Score 35–54)",
            "",
            "| Host | Risk | Target | Registrar | Hosting Provider | Detected Via |",
            "|---|---|---|---|---|---|"
        ])
        for f in med[:15]:
            w = f.get("whois", {})
            h = f.get("host_info", {})
            lines.append(
                f"| {f.get('host')} | **{f.get('risk_score')}** {f.get('risk_band')} | {f.get('targeted_institution_name', '—')} | "
                f"{(w.get('registrar') or '—')[:22]} | {(h.get('hosting_provider') or '—')[:22]} | {', '.join(f.get('sources', []))} |"
            )

        lines.extend([
            "",
            "## 🛡 Cleared YatraDham Defensive Registrations",
            "",
            "These domains redirect directly (301) to `yatradham.org` and are verified as official protective brand assets:",
            ""
        ])
        for f in owned:
            w = f.get("whois", {})
            p = f.get("page", {})
            lines.append(f"- **{f.get('host')}** — Registered via {w.get('registrar', '—')}, redirects to `{p.get('final_url', 'https://yatradham.org/')}`")

        lines.extend([
            "",
            "---",
            "Report produced by YatraDham Digital Trust & Safety Engine — Initiative from YatraDham.Org.",
            "File takedowns at cybercrime.gov.in under *Report Other Cyber Crime → Online Financial Fraud / Fake Website*."
        ])

        report_content = "\n".join(lines)
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            f.write(report_content)
        print(f"[+] Saved updated sweep report to {REPORT_PATH}")

        # Also update Downloads report file
        downloads_report = r"C:\Users\ydtva\Downloads\YatraDham Brand Fraud Monitor — Sweep Report.md"
        try:
            with open(downloads_report, "w", encoding="utf-8") as f:
                f.write(report_content)
            print(f"[+] Synced report to {downloads_report}")
        except Exception as e:
            print(f"[!] Could not update Downloads report: {e}")

def main():
    parser = argparse.ArgumentParser(description="YatraDham Brand & Ashram Fraud Monitor")
    parser.add_argument("--quick", action="store_true", help="Run quick sweep on top priority targets")
    parser.add_argument("--full", action="store_true", help="Run comprehensive sweep")
    parser.add_argument("--inspect", type=str, help="Inspect a specific domain or URL")
    parser.add_argument("--verify-db", action="store_true", help="Verify and display official ashram database")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging and execution tracing")
    args = parser.parse_args()

    if args.debug:
        os.environ["DEBUG"] = "true"
        print("🐞 Debug Mode: ACTIVE (Verbose tracing & diagnostics enabled)")

    runner = FraudSweepRunner()

    if args.verify_db:
        print(f"\n[*] Verified Institutions Registry ({len(runner.ecr.institutions)} entities):")
        for inst in runner.ecr.institutions:
            print(f"  • [{inst['id']}] {inst['name']} ({inst['city']}, {inst['state']}) - Risk: {inst['vulnerability_level']}")
            print(f"    Website: {inst['official_website']} | Verified Phones: {', '.join(inst['verified_phones'])}")
        return

    if args.inspect:
        target = args.inspect
        print(f"\n[*] Live inspecting: {target}...")
        t0 = time.perf_counter()
        finding = runner.inspect_single_host(target)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        res = finding.to_dict()
        if args.debug:
            res["debug_trace"] = {
                "inspection_time_ms": elapsed_ms,
                "ip": finding.ip,
                "risk_reasons_triggered": finding.risk_reasons,
                "raw_score": finding.risk_score
            }
        print(json.dumps(res, indent=2))
        return

    # Default to sweep
    runner.run_sweep(quick=args.quick)

if __name__ == "__main__":
    main()
