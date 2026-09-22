import copy
from pathlib import Path
import tempfile
import unittest

from tracegate import evaluate_plan, load_policy
from tracegate.audit import AuditError, ZERO_HASH, append_report, verify_audit
from tracegate.jsonio import canonical, load_json, loads

ROOT = Path(__file__).resolve().parents[1]


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "audit.jsonl"
        policy = load_policy(str(ROOT / "policy.json"))
        plan = load_json(ROOT / "fixtures/plans/docs-review.json")
        self.report = evaluate_plan(plan, policy)

    def seed(self, count=3):
        for _ in range(count):
            receipt = append_report(self.path, self.report)
        return receipt

    def test_append_verify_and_trusted_checkpoint(self):
        receipt = self.seed()
        state = verify_audit(self.path, expected_head=receipt["head"])
        self.assertEqual(state["records"], 3)
        self.assertEqual(receipt["sequence"], 3)
        self.assertTrue(state["checkpoint_verified"])

    def test_decision_tamper_detected(self):
        self.seed()
        lines = self.path.read_bytes().splitlines()
        item = loads(lines[0])
        item["payload"]["outcome"] = "approve"
        lines[0] = canonical(item)
        self.path.write_bytes(b"\n".join(lines) + b"\n")
        with self.assertRaisesRegex(AuditError, "record hash mismatch"):
            verify_audit(self.path)

    def test_reordering_and_middle_deletion_detected(self):
        self.seed()
        lines = self.path.read_bytes().splitlines(keepends=True)
        for altered in ([lines[1], lines[0], lines[2]], [lines[0], lines[2]]):
            with self.subTest(count=len(altered)):
                self.path.write_bytes(b"".join(altered))
                with self.assertRaises(AuditError):
                    verify_audit(self.path)

    def test_tail_deletion_requires_external_checkpoint(self):
        receipt = self.seed()
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:-1]))
        self.assertTrue(verify_audit(self.path)["valid"])
        with self.assertRaisesRegex(AuditError, "trusted checkpoint"):
            verify_audit(self.path, expected_head=receipt["head"])

    def test_full_chain_rewrite_requires_external_checkpoint(self):
        receipt = self.seed(1)
        self.path.unlink()
        report = copy.deepcopy(self.report)
        report["outcome"] = "approve"
        append_report(self.path, report)
        self.assertTrue(verify_audit(self.path)["valid"])
        with self.assertRaises(AuditError):
            verify_audit(self.path, expected_head=receipt["head"])

    def test_partial_write_is_rejected(self):
        self.seed()
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaisesRegex(AuditError, "final newline"):
            verify_audit(self.path)

    def test_corrupt_chain_is_not_extended(self):
        self.seed()
        raw = self.path.read_bytes() + b"not-json\n"
        self.path.write_bytes(raw)
        with self.assertRaises(AuditError):
            append_report(self.path, self.report)
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertFalse(self.path.with_name("audit.jsonl.lock").exists())

    def test_canonical_line_format_is_enforced(self):
        self.seed(1)
        raw = self.path.read_bytes()
        for changed in (b" " + raw, raw.replace(b"\n", b"\r\n")):
            with self.subTest(changed=changed[:20]):
                self.path.write_bytes(changed)
                with self.assertRaisesRegex(AuditError, "not canonical"):
                    verify_audit(self.path)

    def test_duplicate_json_keys_rejected_in_audit(self):
        self.seed(1)
        raw = self.path.read_bytes().replace(b'{"audit_version":1,', b'{"audit_version":1,"audit_version":1,', 1)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(AuditError, "duplicate JSON key"):
            verify_audit(self.path)

    def test_writer_lock_prevents_cooperating_concurrent_append(self):
        lock = self.path.with_name("audit.jsonl.lock")
        lock.write_text("")
        with self.assertRaisesRegex(AuditError, "lock exists"):
            append_report(self.path, self.report)
        self.assertTrue(lock.exists())
        self.assertFalse(self.path.exists())

    def test_empty_chain_and_invalid_checkpoint(self):
        self.path.write_bytes(b"")
        self.assertEqual(verify_audit(self.path)["head"], ZERO_HASH)
        with self.assertRaises(AuditError):
            verify_audit(self.path, expected_head="not-a-hash")

    def test_audit_omits_raw_plan_content_and_urls(self):
        self.seed(1)
        raw = self.path.read_text()
        self.assertNotIn("Validate tool arguments", raw)
        self.assertNotIn("https://", raw)
        self.assertNotIn("workspace/", raw)
        self.assertIn(self.report["plan_sha256"], raw)


if __name__ == "__main__":
    unittest.main()
