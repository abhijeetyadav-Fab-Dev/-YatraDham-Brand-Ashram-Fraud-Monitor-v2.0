"""
Multi-Channel Alerting & Notification Subsystem.
Dispatches critical alerts for high-risk findings (score >= 55) to Telegram,
Slack/Discord Webhooks, Email (SMTP), and auto-exports CyberCrime Dossiers.
"""
import json
import os
import urllib.request
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class AlertDispatcher:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self.load_config(config_path)

    def load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Loads alert notification credentials or returns defaults."""
        default_config = {
            "telegram_bot_token": os.environ.get("YATRADHAM_TELEGRAM_BOT_TOKEN", ""),
            "telegram_chat_id": os.environ.get("YATRADHAM_TELEGRAM_CHAT_ID", ""),
            "slack_webhook_url": os.environ.get("YATRADHAM_SLACK_WEBHOOK", ""),
            "alert_email_to": os.environ.get("YATRADHAM_ALERT_EMAIL", "legal@yatradham.org"),
            "alert_threshold": 55,
            "export_takedown_dir": os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "takedowns"
            )
        }
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
                    default_config.update(file_cfg)
            except Exception:
                pass
        
        os.makedirs(default_config["export_takedown_dir"], exist_ok=True)
        return default_config

    def format_telegram_alert(self, finding: Dict[str, Any]) -> str:
        """Formats clean, high-priority markdown alert for Telegram."""
        host = finding.get("host", "")
        score = finding.get("risk_score", 0)
        band = finding.get("risk_band", "HIGH")
        inst = finding.get("targeted_institution_name") or "YatraDham Brand"
        whois = finding.get("whois") or {}
        host_info = finding.get("host_info") or {}
        reasons = finding.get("risk_reasons") or []
        page = finding.get("page") or {}
        phones = page.get("copied_phones") or []
        upis = page.get("upi_ids") or []

        reasons_txt = "\n".join([f"• {r}" for r in reasons[:3]])

        msg = (
            f"🚨 *CRITICAL BRAND FRAUD ALERT — {band} ({score}/100)*\n\n"
            f"🎯 *Targeted:* {inst}\n"
            f"🌐 *Impersonating Host:* `{host}`\n"
            f"🏢 *Host/ISP:* {host_info.get('hosting_provider', 'Unknown')} ({host_info.get('host_country', '—')})\n"
            f"📋 *Registrar:* {whois.get('registrar', 'Unknown')}\n"
            f"📅 *Registered On:* {whois.get('created', '—')[:10]}\n\n"
            f"⚠️ *Key Threat Indicators:*\n{reasons_txt}\n\n"
        )
        if phones:
            msg += f"📞 *Scammer Mobile:* `{', '.join(phones[:2])}`\n"
        if upis:
            msg += f"💳 *Scammer UPI:* `{', '.join(upis[:2])}`\n"
        
        msg += "\n📄 *Action Required:* Review in Dashboard & Dispatch NCRP Dossier."
        return msg

    def send_telegram(self, text: str) -> bool:
        """Dispatches Telegram notification if bot token & chat ID are configured."""
        token = self.config.get("telegram_bot_token")
        chat_id = self.config.get("telegram_chat_id")
        if not token or not chat_id:
            return False
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = json.dumps({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown"
            }).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.getcode() == 200
        except Exception:
            return False

    def send_webhook(self, finding: Dict[str, Any]) -> bool:
        """Dispatches rich webhook payload to Slack/Discord."""
        webhook_url = self.config.get("slack_webhook_url")
        if not webhook_url:
            return False
        try:
            payload = {
                "text": f"🚨 *YatraDham Brand Fraud Alert:* {finding.get('host')} scored {finding.get('risk_score')} ({finding.get('risk_band')})",
                "attachments": [{
                    "color": "#ff4d5e" if finding.get("risk_score", 0) >= 75 else "#ff8a3d",
                    "fields": [
                        {"title": "Targeted Stay", "value": finding.get("targeted_institution_name", "YatraDham"), "short": True},
                        {"title": "Host", "value": finding.get("host"), "short": True},
                        {"title": "Hosting Provider", "value": (finding.get("host_info") or {}).get("hosting_provider", "—"), "short": True},
                        {"title": "Registrar", "value": (finding.get("whois") or {}).get("registrar", "—"), "short": True}
                    ]
                }]
            }
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.getcode() == 200
        except Exception:
            return False

    def export_takedown_packet(self, finding: Dict[str, Any]) -> str:
        """Exports standalone markdown & json takedown packet to takedowns/ folder."""
        host = finding.get("host", "unknown").replace("/", "_").replace(":", "_")
        score = finding.get("risk_score", 0)
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"takedown_{score}_{host}_{now_str}.json"
        filepath = os.path.join(self.config["export_takedown_dir"], filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(finding, f, indent=2)
            return filepath
        except Exception:
            return ""

    def process_finding(self, finding: Dict[str, Any]) -> Dict[str, bool]:
        """Triages finding and triggers alerts if score >= threshold and is new."""
        score = finding.get("risk_score", 0)
        is_new = finding.get("is_new", True)
        results = {"telegram": False, "webhook": False, "exported": False}

        if score >= self.config.get("alert_threshold", 55) and is_new:
            # Auto export legal takedown packet
            exp_file = self.export_takedown_packet(finding)
            results["exported"] = bool(exp_file)

            # Dispatch alerts
            tg_text = self.format_telegram_alert(finding)
            results["telegram"] = self.send_telegram(tg_text)
            results["webhook"] = self.send_webhook(finding)

        return results
