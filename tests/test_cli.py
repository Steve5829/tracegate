import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, "-m", "tracegate", *arguments], cwd=ROOT,
                              capture_output=True, text=True, check=False)

    def test_dry_run_stdout_is_json(self):
        result = self.run_cli("evaluate", "fixtures/plans/docs-review.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["outcome"], "dry-run")

    def test_rejected_plan_exit_code(self):
        result = self.run_cli("evaluate", "fixtures/plans/blocked-export.json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["outcome"], "reject")

    def test_invalid_input_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invalid.json"
            path.write_text('{"plan_id":"a","plan_id":"b"}')
            result = self.run_cli("evaluate", str(path))
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stderr)["error"], "input.invalid")

    def test_audit_receipt_and_checkpoint_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "audit.jsonl")
            result = self.run_cli("evaluate", "fixtures/plans/docs-review.json", "--approve", "--audit", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["outcome"], "approve")
            head = json.loads(result.stderr)["audit_receipt"]["head"]
            verified = self.run_cli("verify-audit", path, "--expected-head", head)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            invalid = self.run_cli("verify-audit", path, "--expected-head", "0" * 64)
            self.assertEqual(invalid.returncode, 4)

    def test_replay_output_and_failure_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "evaluation.json")
            success = self.run_cli("replay", "fixtures/cases.json", "--output", out)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(json.loads(Path(out).read_text()), json.loads(success.stdout))
            suite = json.loads((ROOT / "fixtures/cases.json").read_text())
            suite["cases"][0]["expected_outcome"] = "reject"
            altered = Path(temp) / "suite.json"
            altered.write_text(json.dumps(suite))
            failure = self.run_cli("replay", str(altered))
            self.assertEqual(failure.returncode, 1, failure.stderr)
            self.assertEqual(json.loads(failure.stdout)["failed"], 1)


if __name__ == "__main__":
    unittest.main()
