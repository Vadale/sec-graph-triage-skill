"""Public, synthetic regression checks; no private evaluation inputs needed."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "skills/sec-graph-triage/scripts/collect_context.py"


class EvidenceCLI(unittest.TestCase):
    def run_cli(self, report, root=None, **kwargs):
        workspace = Path(self.tmp.name)
        source = root or ROOT / "examples/project"
        self.serial += 1
        input_path = workspace / f"report-{self.serial}.sarif"
        input_path.write_text(json.dumps(report))
        output = workspace / f"evidence-{self.serial}.json"
        completed = subprocess.run([sys.executable, "-B", str(HELPER), "--root", str(source),
                                    "--sarif", str(input_path), "--output", str(output)],
                                   capture_output=True, text=True, timeout=15, **kwargs)
        bundle = json.loads(output.read_text()) if output.exists() else json.loads(completed.stdout)
        return completed, bundle

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="secgraph-public-")
        self.addCleanup(self.tmp.cleanup)
        self.serial = 0

    def example(self):
        return json.loads((ROOT / "examples/findings.sarif").read_text())

    def test_exact_current_evidence_and_preserved_flow(self):
        process, bundle = self.run_cli(self.example())
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(bundle["status"], "ok")
        steps = bundle["results"][0]["code_flows"][0]["thread_flows"][0]["steps"]
        self.assertEqual([(s["location"]["path"], s["location"]["line"]) for s in steps],
                         [("orders.py", 2), ("orders.py", 3), ("database.py", 3)])
        for item in bundle["files"]:
            expected = hashlib.sha256((ROOT / "examples/project" / item["path"]).read_bytes()).hexdigest()
            self.assertEqual(item["current_sha256"], expected)
            self.assertEqual(item["reported_digest_relation"], "unknown")
            self.assertFalse(item["scan_time_verified"])
        primary = bundle["results"][0]["primary_locations"][0]
        self.assertEqual(primary["window"][1], {"line": 2, "text": '    query = "SELECT id FROM orders WHERE id = " + order_id'})

    def test_digest_mismatch_is_partial_not_a_freshness_claim(self):
        report = self.example()
        report["runs"][0]["artifacts"] = [{"location": {"uri": "database.py"},
                                           "hashes": {"sha-256": "0" * 64}}]
        process, bundle = self.run_cli(report)
        self.assertEqual(process.returncode, 2)
        self.assertIn("reported_digest_mismatch", {d["code"] for d in bundle["diagnostics"]})
        self.assertEqual(next(f for f in bundle["files"] if f["path"] == "database.py")["reported_digest_relation"], "mismatch")

    def test_missing_hop_remains_in_its_position(self):
        report = self.example()
        steps = report["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
        steps[1]["location"]["physicalLocation"]["artifactLocation"]["uri"] = "missing.py"
        process, bundle = self.run_cli(report)
        self.assertEqual(process.returncode, 2)
        actual = bundle["results"][0]["code_flows"][0]["thread_flows"][0]["steps"]
        self.assertEqual([s["index"] for s in actual], [0, 1, 2])
        self.assertEqual(actual[1]["location"]["error"], "source_missing")

    @unittest.skipUnless(os.name == "posix", "Supported source-open route is POSIX")
    def test_escaping_symlink_is_not_read(self):
        workspace = Path(self.tmp.name)
        source = workspace / "source"
        source.mkdir()
        outside = workspace / "outside.py"
        outside.write_text("PUBLIC_TEST_CANARY = True\n")
        (source / "database.py").symlink_to(outside)
        report = self.example()
        report["runs"][0]["results"][0].pop("codeFlows")
        process, bundle = self.run_cli(report, root=source)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn("PUBLIC_TEST_CANARY", json.dumps(bundle))
        self.assertIn("source_symlink", {d["code"] for d in bundle["diagnostics"]})


if __name__ == "__main__":
    unittest.main()
