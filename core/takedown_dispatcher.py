"""
Automated Abuse Notice & Threat Intelligence Dispatcher.
Handles automated 1-click abuse email dispatch to Registrar & ISP abuse desks (via SMTP),
as well as reporting to Google Safe Browsing, PhishTank, and URLhaus.
"""
import os
import smtplib
import ssl
import json
import logging
import urllib.request
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .takedown_generator import TakedownGenerator

logger = logging.getLogger("yatradham-takedown-dispatcher")

class TakedownDispatcher:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.smtp_host = os.environ.get("SMTP_HOST", self.config.get("smtp_host", ""))
        self.smtp_port = int(os.environ.get("SMTP_PORT", self.config.get("smtp_port", 587)))
        self.smtp_user = os.environ.get("SMTP_USER", self.config.get("smtp_user", ""))
        self.smtp_password = os.environ.get("SMTP_PASSWORD", self.config.get("smtp_password", ""))
        self.smtp_from = os.environ.get("SMTP_FROM", self.config.get("smtp_from", "legal@yatradham.org"))
        self.smtp_active = os.environ.get("SMTP_ACTIVE", "false").lower() in ("true", "1", "yes")
        self.legal_cc = os.environ.get("YATRADHAM_LEGAL_CC", "legal@yatradham.org")
        self.takedown_generator = TakedownGenerator()
        
        self.dispatched_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "takedowns", "dispatched_notices"
        )
        os.makedirs(self.dispatched_dir, exist_ok=True)

    def dispatch_abuse_email(
        self,
        finding_data: Dict[str, Any],
        recipient_override: Optional[str] = None,
        custom_notes: Optional[str] = None,
        dry_run: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Dispatches formal Cease & Desist / Domain Suspension notice to Registrar Abuse desk.
        If SMTP is unconfigured or dry_run=True, simulates dispatch and logs the complete notice.
        """
        host = finding_data.get("host", "unknown")
        whois = finding_data.get("whois") or {}
        registrar = whois.get("registrar", "Unknown Registrar")
        abuse_email = recipient_override or whois.get("abuse_email")
        
        if not abuse_email:
            clean_reg = registrar.lower().replace(" ", "").replace(",", "").replace(".", "")
            abuse_email = f"abuse@{clean_reg}.com" if clean_reg else "abuse@unresolved-registrar.com"

        dossier = self.takedown_generator.generate(finding_data)
        subject = dossier.complaint_subject
        body = dossier.registrar_abuse_notice

        if custom_notes:
            body += f"\n\n[INVESTIGATOR NOTES & FIR REFERENCE]:\n{custom_notes}"

        is_dry_run = dry_run if dry_run is not None else (not self.smtp_active or not self.smtp_host)

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dispatch_record = {
            "host": host,
            "recipient": abuse_email,
            "cc": self.legal_cc,
            "subject": subject,
            "timestamp": timestamp_str,
            "dry_run": is_dry_run,
            "body": body
        }

        safe_host = host.replace("/", "_").replace(":", "_")
        filename = f"notice_{safe_host}_{timestamp_str}.json"
        filepath = os.path.join(self.dispatched_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(dispatch_record, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not persist notice audit file: {e}")

        if is_dry_run:
            logger.info(f"[DRY-RUN] Abuse email prepared for {abuse_email} regarding {host}")
            return {
                "success": True,
                "status": "simulated",
                "recipient": abuse_email,
                "cc": self.legal_cc,
                "subject": subject,
                "message": f"Simulated dispatch successful. Notice saved to {filename}",
                "audit_file": filepath,
                "body_preview": body[:400] + "..."
            }

        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_from
            msg["To"] = abuse_email
            msg["Cc"] = self.legal_cc
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            recipients = [abuse_email]
            if self.legal_cc:
                recipients.append(self.legal_cc)

            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_from, recipients, msg.as_string())

            logger.info(f"Abuse email successfully sent to {abuse_email} for {host}")
            return {
                "success": True,
                "status": "sent",
                "recipient": abuse_email,
                "cc": self.legal_cc,
                "subject": subject,
                "message": f"Live abuse notice dispatched to {abuse_email} via SMTP",
                "audit_file": filepath
            }
        except Exception as e:
            logger.error(f"SMTP dispatch failed for {host} to {abuse_email}: {e}")
            return {
                "success": False,
                "status": "failed",
                "error": str(e),
                "recipient": abuse_email,
                "audit_file": filepath
            }

    def report_safebrowsing_portal(self, target_url: str) -> Dict[str, Any]:
        """Provides submission link and API format for Google Safe Browsing."""
        encoded_url = urllib.parse.quote_plus(target_url)
        portal_url = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={encoded_url}"
        ms_smartscreen_url = f"https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site?url={encoded_url}"
        
        return {
            "target_url": target_url,
            "google_safebrowsing_submission_url": portal_url,
            "microsoft_smartscreen_url": ms_smartscreen_url,
            "message": "Clicking these links allows instant submission to Google and Microsoft anti-phishing networks."
        }

    def report_urlhaus(self, target_url: str, threat: str = "phishing", tags: Optional[list] = None) -> Dict[str, Any]:
        """Prepares automated submission payload for abuse.ch URLhaus threat feed."""
        payload = {
            "token": os.environ.get("URLHAUS_API_KEY", ""),
            "anonymous": 1 if not os.environ.get("URLHAUS_API_KEY") else 0,
            "submission": [{
                "url": target_url,
                "threat": threat,
                "tags": tags or ["yatradham-brand-impersonation", "fake-ashram-booking", "india-phishing"]
            }]
        }
        return {
            "status": "ready",
            "service": "abuse.ch URLhaus",
            "target_url": target_url,
            "submission_payload": payload,
            "instructions": "Submit via POST https://urlhaus-api.abuse.ch/v1/download/ or API token"
        }
