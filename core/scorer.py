"""
Risk Scoring Engine v2.0 for YatraDham Brand & Ashram Fraud Monitor.
Calculates explainable 0-100 risk score based on weighted forensic and behavioural signals.
"""
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
from .models import RiskBand, ThreatCategory

class FraudRiskScorer:
    def __init__(self):
        pass

    def calculate_domain_age_days(self, created_str: str):
        if not created_str or created_str == "—":
            return None
        try:
            clean_date = created_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_date)
            now = datetime.now(timezone.utc)
            delta = now - dt
            return max(0, delta.days)
        except Exception:
            return None

    def evaluate(
        self,
        host: str,
        is_defensive_domain: bool,
        redirects_to_official: bool,
        matched_institution: Dict[str, Any] = None,
        unauthorized_phones: List[str] = None,
        extracted_upis: List[str] = None,
        advance_signals: List[str] = None,
        gateways: List[str] = None,
        whois_data: Dict[str, Any] = None,
        host_info: Dict[str, Any] = None,
        sources: List[str] = None,
        has_whatsapp_redirect: bool = False,
        brand_mentions: int = 0
    ) -> Tuple[int, RiskBand, ThreatCategory, List[str]]:
        """
        Evaluates risk score, band, threat category, and list of explainable reasons.
        """
        unauthorized_phones = unauthorized_phones or []
        extracted_upis = extracted_upis or []
        advance_signals = advance_signals or []
        gateways = gateways or []
        whois_data = whois_data or {}
        host_info = host_info or {}
        sources = sources or []

        reasons = []

        # 1. Check Defensive Brand Owned
        if is_defensive_domain and redirects_to_official:
            return (
                0,
                RiskBand.BRAND_OWNED,
                ThreatCategory.DEFENSIVE_OWNED,
                ["Cleared as verified YatraDham defensive registration (301 redirects to yatradham.org)"]
            )

        score = 0
        primary_threat = ThreatCategory.BRAND_TYPOSQUAT

        # 2. Ashram / Dharamshala Impersonation
        if matched_institution:
            score += 30
            primary_threat = ThreatCategory.ASHRAM_IMPERSONATION
            reasons.append(
                f"Impersonating top-rated religious stay: {matched_institution['name']} ({matched_institution.get('city', '')}) (+30)"
            )

        # 3. Unauthorized Contact / Fake Helpline
        if unauthorized_phones:
            score += 25
            if primary_threat != ThreatCategory.ASHRAM_IMPERSONATION:
                primary_threat = ThreatCategory.FAKE_HELPLINE
            sample_phones = ", ".join(unauthorized_phones[:2])
            reasons.append(
                f"Publishing unauthorized booking helpline / mobile number: {sample_phones} (+25)"
            )

        # 4. Direct Personal UPI Payment Handles
        if extracted_upis:
            score += 25
            primary_threat = ThreatCategory.SUSPICIOUS_PAYMENT_UPI
            sample_upis = ", ".join(extracted_upis[:3])
            reasons.append(
                f"Direct personal UPI payment handles found: {sample_upis} (+25)"
            )

        # 5. WhatsApp Direct Phishing Link
        if has_whatsapp_redirect:
            score += 15
            reasons.append("Direct WhatsApp booking redirect (wa.me) detected (+15)")

        # 6. High-Pressure Advance Token Phrasing
        if advance_signals:
            score += 15
            reasons.append(
                f"High-pressure advance token/payment demand detected: '{advance_signals[0]}' (+15)"
            )

        # 7. Brand Typosquat / Lookalike Domain
        host_lower = host.lower()
        if any(term in host_lower for term in ["yatradham", "yatra-dham", "yatradham-booking"]):
            score += 20
            if primary_threat == ThreatCategory.BRAND_TYPOSQUAT:
                primary_threat = ThreatCategory.BRAND_TYPOSQUAT
            reasons.append("Lookalike domain using YatraDham brand trademark (+20)")

        # 8. Domain Age & Registration Recency
        created_date = whois_data.get("created")
        if created_date:
            days = self.calculate_domain_age_days(created_date)
            if days is not None:
                if days <= 30:
                    score += 15
                    reasons.append(f"Newly registered domain ({days} days old) (+15)")
                elif days <= 90:
                    score += 10
                    reasons.append(f"Recently registered domain ({days} days old) (+10)")
                elif days <= 365:
                    score += 5
                    reasons.append(f"Domain registered within past year ({days} days old) (+5)")

        # 9. WHOIS Privacy Protection
        if whois_data.get("privacy_protected"):
            score += 5
            reasons.append("WHOIS privacy proxy / identity concealment enabled (+5)")

        # 10. Offshore Hosting Provider
        country = host_info.get("host_country", "")
        if country and country != "India" and country != "Unknown":
            score += 5
            reasons.append(f"Indian pilgrimage booking site hosted offshore ({country}) (+5)")

        # 11. Discovery Source Weighting
        if "search_results" in sources:
            score += 8
            reasons.append("Active in open-web/search results for pilgrim booking queries (+8)")
        if "certificate_transparency" in sources:
            score += 5
            reasons.append("Active TLS certificate discovered via Certificate Transparency logs (+5)")
        if "typosquat_dns" in sources:
            score += 5
            reasons.append("Resolving live IP via permutation DNS sweep (+5)")

        # Cap at 100
        score = min(100, score)

        # Determine Risk Band
        if score >= 75:
            band = RiskBand.CRITICAL
        elif score >= 55:
            band = RiskBand.HIGH
        elif score >= 35:
            band = RiskBand.MEDIUM
        else:
            band = RiskBand.LOW

        return (score, band, primary_threat, reasons)
