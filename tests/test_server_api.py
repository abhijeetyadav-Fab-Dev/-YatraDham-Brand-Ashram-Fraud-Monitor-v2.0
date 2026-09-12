"""
Automated Integration Test Suite for YatraDham Fraud Monitor FastAPI Server.
Verifies all REST API endpoints, response contracts, takedown generators,
and dashboard serving.
"""
import unittest
import os
import sys

# Ensure parent directory is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from server import app

class TestServerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertIn("Initiative from YatraDham.Org", data.get("framework", ""))

    def test_stats_endpoint(self):
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_hosts_examined", data)
        self.assertIn("critical_threats", data)
        self.assertIn("high_risk_alerts", data)
        self.assertIn("ashram_impersonations", data)
        self.assertIn("fraudulent_helplines_detected", data)

    def test_findings_endpoint(self):
        resp = self.client.get("/api/findings")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total", data)
        self.assertIn("results", data)
        self.assertIsInstance(data["results"], list)

    def test_scan_domain_endpoint(self):
        payload = {"target": "khatushyambooking.org"}
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        finding = data.get("finding", {})
        self.assertEqual(finding.get("host"), "khatushyambooking.org")
        self.assertGreaterEqual(finding.get("risk_score", 0), 30)
        self.assertIn("evidence", finding)

    def test_scan_phone_endpoint(self):
        payload = {"target": "+919876543210"}
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("finding", data)

    def test_institutions_endpoint(self):
        resp = self.client.get("/api/institutions")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("institutions", data)
        self.assertGreaterEqual(data.get("total", 0), 10)

    def test_sweep_status_endpoint(self):
        resp = self.client.get("/api/sweep/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("progress_percent", data)

    def test_export_json_endpoint(self):
        resp = self.client.get("/api/export/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-type"), "application/json")

    def test_export_csv_endpoint(self):
        resp = self.client.get("/api/export/csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers.get("content-type", ""))

    def test_dashboard_ui_served(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text
        self.assertIn("Initiative from YatraDham.Org", html)
        self.assertIn("YatraDham Brand & Ashram Fraud Monitor", html)
        self.assertNotIn("Gujarat Police", html)
        self.assertIn("btn-debug-toggle", html)
        self.assertIn("debug-drawer", html)
        self.assertIn("favicon.png", html)

    def test_favicon_served(self):
        resp = self.client.get("/favicon.ico")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("image", resp.headers.get("content-type", ""))

    def test_debug_system_info(self):
        resp = self.client.get("/api/debug/system")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("debug_mode", data)
        self.assertIn("server_uptime_seconds", data)
        self.assertIn("system", data)
        self.assertIn("memory", data["system"])
        self.assertIn("rss_mb", data["system"]["memory"])
        self.assertIn("environment", data)
        self.assertIn("storage", data)
        self.assertIn("network", data)

    def test_debug_toggle(self):
        # Enable
        resp = self.client.post("/api/debug/toggle", json={"enabled": True})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json().get("debug_mode"))

        # Verify reflected in health
        h_resp = self.client.get("/api/health")
        self.assertTrue(h_resp.json().get("debug_mode"))

        # Disable
        resp2 = self.client.post("/api/debug/toggle", json={"enabled": False})
        self.assertEqual(resp2.status_code, 200)
        self.assertFalse(resp2.json().get("debug_mode"))

    def test_scan_with_debug_trace(self):
        payload = {"target": "khatushyambooking.org", "debug": True}
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("debug_trace", data)
        trace = data["debug_trace"]
        self.assertIn("inspection_time_ms", trace)
        self.assertIn("raw_score", trace)
        self.assertIn("risk_reasons", trace)

if __name__ == "__main__":
    unittest.main()
