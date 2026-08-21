import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


class APIInspectorTests(unittest.TestCase):
    def test_hashes_real_input_and_inspects_api(self):
        path = Path(__file__).parents[1] / "tools" / "ghost_extension.py"
        spec = importlib.util.spec_from_file_location("ghost_extension", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "api_spec.json"
            content = b"{\"paths\": {\"/api/v1/users\": {\"get\": {\"authorization\": \"bearer secret\"}}}}\n"
            target.write_bytes(content)
            report = module.analyze(target)
        self.assertEqual(report["artifacts"][0]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertTrue(any(f["rule_id"] == "API-AUTH" for f in report["findings"]))
        self.assertFalse(report["metadata"]["execution_performed"])


if __name__ == "__main__":
    unittest.main()
