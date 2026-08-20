import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import classify_bfla_status, compare_idor_responses, inspect_api


class AccessControlHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if self.path == "/resource/1":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":1,"owner":"account-a"}')
            return
        if self.path == "/admin/settings":
            if auth == "Bearer low-priv":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"role":"admin-settings"}')
            else:
                self.send_response(403)
                self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_PUT(self):
        auth = self.headers.get("Authorization", "")
        if self.path == "/api/v1/profile":
            if not auth:
                self.send_response(401)
                self.end_headers()
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, _format, *_args):
        return


class TestAPIInspectorAccessControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), AccessControlHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_bfla_classifier(self):
        self.assertTrue(classify_bfla_status(200))
        self.assertTrue(classify_bfla_status(201))
        self.assertFalse(classify_bfla_status(401))
        self.assertFalse(classify_bfla_status(403))

    def test_idor_comparison_requires_two_successful_equal_responses(self):
        self.assertTrue(compare_idor_responses(200, "same", 200, "same"))
        self.assertFalse(compare_idor_responses(200, "same", 403, "same"))
        self.assertFalse(compare_idor_responses(200, "a", 200, "b"))
        self.assertFalse(compare_idor_responses(200, "", 200, ""))

    def test_live_local_http_inspections(self):
        findings = inspect_api(
            self.base_url,
            test_endpoint=f"{self.base_url}/resource/1",
            token_a="account-a-token",
            token_b="account-b-token",
            bfla_endpoint=f"{self.base_url}/admin/settings",
            low_priv_token="low-priv",
            mass_endpoint=f"{self.base_url}/api/v1/profile",
            mass_token="mass-test-token"
        )

        idor = next(item for item in findings if "idor_test_endpoint" in item)
        bfla = next(item for item in findings if "bfla_test_endpoint" in item)
        mass = next(item for item in findings if "mass_assignment_endpoint" in item)

        self.assertEqual(idor["user_a_status"], 200)
        self.assertEqual(idor["user_b_status"], 200)
        self.assertTrue(idor["bola_potential_vulnerability"])
        self.assertEqual(bfla["low_priv_status_code"], 200)
        self.assertTrue(bfla["bfla_potential_vulnerability"])
        self.assertEqual(mass["status_code"], 200)
        self.assertTrue(mass["mass_assignment_potential_vulnerability"])

        serialized = json.dumps(findings)
        self.assertNotIn("account-a-token", serialized)
        self.assertNotIn("account-b-token", serialized)
        self.assertNotIn("low-priv", serialized)
        self.assertNotIn("mass-test-token", serialized)


if __name__ == "__main__":
    unittest.main()
