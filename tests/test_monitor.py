"""
Comprehensive Pre-Production Automated Test Suite for YatraDham Fraud Monitor.
Tests data integrity, entity cross-referencing, scoring rules, takedown generation,
and false-positive suppression (Global Protocol Compliance).
"""
import unittest
import os
import json
import re

from core.entity_cross_reference import EntityCrossReferencer
from core.scorer import FraudRiskScorer
from core.takedown_generator import TakedownGenerator
from core.models import RiskBand, ThreatCategory, FraudFinding

class TestBrandFraudMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.db_path = os.path.join(cls.base_dir, "data", "verified_institutions.json")
        cls.ecr = EntityCrossReferencer(cls.db_path)
        cls.scorer = FraudRiskScorer()
        cls.takedown_gen = TakedownGenerator()

    def test_database_integrity(self):
        """Verifies ground truth database contains valid required fields and no corrupt schemas."""
        self.assertTrue(os.path.exists(self.db_path), "Database file does not exist")
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Verify brand profile
        brand = data.get("brand", {})
        self.assertEqual(brand.get("primary_domain"), "yatradham.org")
        self.assertIn("yatradham.in", brand.get("defensive_domains", []))
        self.assertTrue(len(brand.get("official_phones", [])) >= 2)

        # Verify institutions
        institutions = data.get("institutions", [])
        self.assertGreaterEqual(len(institutions), 10, "Should have at least 10 high-risk institutions")
        for inst in institutions:
            self.assertIn("id", inst)
            self.assertIn("name", inst)
            self.assertIn("official_website", inst)
            self.assertTrue(len(inst.get("verified_phones", [])) >= 1, f"Missing phone for {inst['id']}")
            self.assertIn("payment_policy", inst)
            self.assertIn(inst.get("vulnerability_level"), ["MEDIUM", "HIGH", "CRITICAL"])

    def test_upi_false_positive_elimination(self):
        """
        REGRESSION BUG SQUASH:
        Ensures corporate bank emails like creditcards@axisbank or nodal.officer@axisbank
        are NEVER tagged as UPI payment handles.
        """
        tricky_text = """
        For consumer grievances, contact nodal.officer@axisbank and creditcards@axisbank.
        Also support@hdfcbank.com and abuse@godaddy.com.
        However, advance money should be sent to scammer99@paytm or 9825012345@ybl or donation@upi.
        """
        upis = self.ecr.extract_upi_ids(tricky_text)
        
        # Must exclude corporate bank emails
        self.assertNotIn("creditcards@axisbank", upis)
        self.assertNotIn("nodal.officer@axisbank", upis)
        self.assertNotIn("support@hdfcbank.com", upis)
        self.assertNotIn("abuse@godaddy.com", upis)

        # Must include legitimate UPI handles
        self.assertIn("scammer99@paytm", upis)
        self.assertIn("9825012345@ybl", upis)
        self.assertIn("donation@upi", upis)

    def test_ashram_entity_matching(self):
        """Verifies accurate matching of high-risk Dharamshalas and Ashrams."""
        # Exact match
        inst1 = self.ecr.match_institution("bhujvishrantibhavan.online")
        self.assertIsNotNone(inst1)
        self.assertEqual(inst1["id"], "bhuj-vishranti-bhavan")

        # Stem keyword match
        inst2 = self.ecr.match_institution("khatushyambooking.org")
        self.assertIsNotNone(inst2)
        self.assertEqual(inst2["id"], "khatu-shyam-trust")

        # Complex query
        inst3 = self.ecr.match_institution("Kedarnath GMVN Cottages Room Advance")
        self.assertIsNotNone(inst3)
        self.assertEqual(inst3["id"], "kedarnath-gmvn")

    def test_phone_mismatch_detection(self):
        """Detects unauthorized scammer phone numbers published on impersonating pages."""
        # Official Bhuj Vishranti phone is 02832-250100 or +919426212345
        scam_page = "Welcome to Bhuj Vishranti Bhavan. For room booking call manager at +91-9876543210."
        xref = self.ecr.cross_reference(
            host="bhujvishrantibhavan.online",
            page_title="Bhuj Vishranti Bhavan Booking",
            page_text=scam_page
        )
        self.assertEqual(xref["matched_institution"]["id"], "bhuj-vishranti-bhavan")
        self.assertIn("+919876543210", xref["unauthorized_phones"])
        self.assertTrue(any("unauthorized booking phone" in d for d in xref["discrepancies"]))

    def test_advance_payment_urgency_detection(self):
        """Detects high-pressure advance token scams."""
        text = "Please deposit advance payment token ₹1500 to confirm your Dharamshala room. Send payment screenshot on WhatsApp."
        signals = self.ecr.detect_advance_payment_signals(text)
        self.assertTrue(len(signals) >= 1)

    def test_defensive_domain_zero_risk(self):
        """Verified YatraDham defensive domains redirecting (301) to yatradham.org MUST score 0 (BRAND-OWNED)."""
        score, band, threat, reasons = self.scorer.evaluate(
            host="yatradham.in",
            is_defensive_domain=True,
            redirects_to_official=True
        )
        self.assertEqual(score, 0)
        self.assertEqual(band, RiskBand.BRAND_OWNED)
        self.assertEqual(threat, ThreatCategory.DEFENSIVE_OWNED)

    def test_high_risk_impersonator_scoring(self):
        """Active impersonator with unauthorized phone and UPI MUST score in HIGH/CRITICAL band (>=55)."""
        inst = self.ecr.match_institution("khatushyambooking.org")
        score, band, threat, reasons = self.scorer.evaluate(
            host="khatushyambooking.org",
            is_defensive_domain=False,
            redirects_to_official=False,
            matched_institution=inst,
            unauthorized_phones=["+919811223344"],
            extracted_upis=["khaturooms@paytm"],
            advance_signals=["advance token amount required"],
            whois_data={"created": "2026-08-15T00:00:00Z", "privacy_protected": True},
            host_info={"host_country": "Lithuania"},
            sources=["search_results"]
        )
        self.assertGreaterEqual(score, 75, "Should score CRITICAL due to multi-vector threat signals")
        self.assertEqual(band, RiskBand.CRITICAL)
        self.assertTrue(any("Impersonating" in r for r in reasons))
        self.assertTrue(any("UPI" in r for r in reasons))

    def test_takedown_dossier_generation(self):
        """Verifies takedown packet contains all legal sections and NCRP complaint narrative."""
        sample_finding = {
            "host": "bhujvishrantibhavan.online",
            "ip": "104.21.45.12",
            "host_info": {
                "hosting_provider": "Cloudflare, Inc.",
                "asn": "AS13335",
                "host_country": "United States"
            },
            "whois": {
                "registrar": "Namecheap",
                "created": "2026-08-10T12:00:00Z",
                "abuse_email": "abuse@namecheap.com"
            },
            "page": {
                "title": "Bhuj Vishranti Bhavan Booking",
                "copied_phones": ["+919825098765"],
                "upi_ids": ["vishrantibooking@ybl"],
                "advance_payment_signals": ["Token advance required"]
            },
            "risk_score": 85,
            "risk_band": "CRITICAL",
            "risk_reasons": ["Impersonating Bhuj Vishranti Bhavan (+30)", "Unauthorized mobile (+25)", "UPI (+25)"],
            "targeted_institution_name": "Bhuj Vishranti Bhavan"
        }
        dossier = self.takedown_gen.generate(sample_finding)
        
        # Verify NCRP Police Memo
        self.assertIn("66D", dossier.police_memo)
        self.assertIn("Initiative from YatraDham.Org", dossier.police_memo)
        self.assertIn("Bhuj Vishranti Bhavan", dossier.police_memo)

        # Verify Registrar Notice
        self.assertIn("abuse@namecheap.com", dossier.registrar_abuse_notice)
        self.assertIn("ICANN Registrar", dossier.registrar_abuse_notice)

        # Verify NPCI UPI Freeze notice
        self.assertIn("vishrantibooking@ybl", dossier.npci_bank_freeze_request)

if __name__ == "__main__":
    unittest.main()
