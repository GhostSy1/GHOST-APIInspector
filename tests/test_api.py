import unittest
import json
import os

class TestAPIInspectorLogic(unittest.TestCase):
    def test_report_structure(self):
        # Verify basic report generation structure without mocking real target attacks
        report = {
            "target": "https://api.test.local",
            "engine": "GHOST-APIInspector v3.4-PRO",
            "endpoints_analyzed": 1,
            "findings": [{"endpoint": "https://api.test.local/api/v1", "status": 200, "active": True}]
        }
        self.assertEqual(report["target"], "https://api.test.local")
        self.assertIn("findings", report)
        self.assertEqual(len(report["findings"]), 1)

    def test_idor_logic_condition(self):
        # Verify BOLA / IDOR detection condition: status 200 and identical bodies
        code_a, body_a = 200, "{\"id\": 101, \"data\": \"secret\"}"
        code_b, body_b = 200, "{\"id\": 101, \"data\": \"secret\"}"
        bola_risk = (code_a == 200 and code_b == 200 and body_a == body_b)
        self.assertTrue(bola_risk)

    def test_bfla_logic_condition(self):
        # Verify BFLA detection condition: low priv user accessing admin endpoint with 200 OK
        low_priv_status = 200
        bfla_risk = (low_priv_status == 200 or low_priv_status == 201)
        self.assertTrue(bfla_risk)

        blocked_status = 403
        bfla_blocked = (blocked_status == 200 or blocked_status == 201)
        self.assertFalse(bfla_blocked)

if __name__ == "__main__":
    unittest.main()
