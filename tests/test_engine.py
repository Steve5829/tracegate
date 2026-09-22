import copy
from dataclasses import replace
from pathlib import Path
import unittest

from tracegate import evaluate_plan, load_policy
from tracegate.jsonio import InputError, canonical, load_json, loads
from tracegate.policy import Policy
from tracegate.replay import reason_codes, replay_suite

ROOT = Path(__file__).resolve().parents[1]


class GateTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(str(ROOT / "policy.json"))
        self.plan = load_json(ROOT / "fixtures/plans/docs-review.json")

    def check(self, code):
        report = evaluate_plan(self.plan, self.policy)
        self.assertEqual(report["outcome"], "reject")
        self.assertIn(code, reason_codes(report))
        return report

    def test_default_is_dry_run(self):
        report = evaluate_plan(self.plan, self.policy)
        self.assertEqual(report["outcome"], "dry-run")
        self.assertEqual(len(report["checks"]), 3)
        self.assertEqual(report["errors"], [])

    def test_approve_does_not_write_a_file(self):
        destination = ROOT / "workspace/reports/review.md"
        self.assertFalse(destination.exists())
        self.assertEqual(evaluate_plan(self.plan, self.policy, mode="approve")["outcome"], "approve")
        self.assertFalse(destination.exists())

    def test_unknown_mode_is_error(self):
        with self.assertRaises(InputError):
            evaluate_plan(self.plan, self.policy, mode="execute")

    def test_result_is_deterministic_and_input_is_unchanged(self):
        original = copy.deepcopy(self.plan)
        first = evaluate_plan(self.plan, self.policy)
        self.assertEqual(canonical(first), canonical(evaluate_plan(self.plan, self.policy)))
        self.assertEqual(original, self.plan)

    def test_object_key_order_does_not_change_hash(self):
        first = evaluate_plan(self.plan, self.policy)
        reordered = dict(reversed(list(self.plan.items())))
        self.assertEqual(first, evaluate_plan(reordered, self.policy))

    def test_policy_change_changes_hash(self):
        first = evaluate_plan(self.plan, self.policy)
        second = evaluate_plan(self.plan, replace(self.policy, max_read_bytes=8192))
        self.assertNotEqual(first["policy_sha256"], second["policy_sha256"])

    def test_plan_change_changes_hash(self):
        first = evaluate_plan(self.plan, self.policy)
        self.plan["steps"][0]["args"]["max_bytes"] = 512
        self.assertNotEqual(first["plan_sha256"], evaluate_plan(self.plan, self.policy)["plan_sha256"])

    def test_path_traversal_and_ambiguous_paths(self):
        for path in ("../secrets", "workspace/../secrets", "/workspace/file", "workspace//file",
                     "workspace/./file", "workspace\\file", "C:/workspace/file",
                     "workspace/%2e%2e/file", "workspace/a\x00b", "workspace/file.",
                     "workspace/file ", "workspace/~/file"):
            with self.subTest(path=path):
                self.plan["steps"][0]["args"]["path"] = path
                self.check("path.invalid")

    def test_component_prefix_not_string_prefix(self):
        self.plan["steps"][0]["args"]["path"] = "workspace-backup/secrets"
        self.check("path.outside_allowlist")

    def test_read_limit_boundary(self):
        self.plan["steps"][0]["args"]["max_bytes"] = self.policy.max_read_bytes
        self.assertEqual(evaluate_plan(self.plan, self.policy)["outcome"], "dry-run")
        self.plan["steps"][0]["args"]["max_bytes"] += 1
        self.check("read.limit")

    def test_utf8_write_limit_counts_bytes(self):
        self.plan["steps"][2]["args"]["content"] = "界" * (self.policy.max_write_bytes // 3 + 1)
        self.check("write.limit")

    def test_overwrite_is_explicitly_blocked(self):
        self.plan["steps"][2]["args"]["overwrite"] = True
        self.check("write.overwrite")

    def test_boolean_float_and_string_are_not_integer_limits(self):
        for value in (True, False, 1.0, "4096", None, -1, 0, 16 * 1024 * 1024 + 1):
            with self.subTest(value=value):
                self.plan["steps"][0]["args"]["max_bytes"] = value
                self.check("schema.invalid")

    def test_unknown_keys_rejected_at_every_level(self):
        original = copy.deepcopy(self.plan)
        for level in ("plan", "step", "args"):
            with self.subTest(level=level):
                self.plan = copy.deepcopy(original)
                target = {"plan": self.plan, "step": self.plan["steps"][0],
                          "args": self.plan["steps"][0]["args"]}[level]
                target["ignore_policy"] = True
                report = self.check("schema.invalid")
                self.assertEqual(report["checks"], [])

    def test_unknown_tool_fails_schema(self):
        self.plan["steps"][0]["tool"] = "shell.exec"
        self.check("schema.invalid")

    def test_known_but_disabled_tool_fails_policy(self):
        self.policy = replace(self.policy, allowed_tools=("file.read",))
        self.check("tool.denied")

    def test_missing_field_fails_schema(self):
        del self.plan["steps"][2]["args"]["overwrite"]
        self.check("schema.invalid")

    def test_duplicate_step_id_fails_schema(self):
        self.plan["steps"][1]["id"] = self.plan["steps"][0]["id"]
        self.check("schema.invalid")

    def test_invalid_step_count_and_container_types(self):
        for steps in ([], {}, "read", [None], [self.plan["steps"][0]] * 129):
            with self.subTest(steps_type=type(steps).__name__):
                self.plan["steps"] = steps
                self.check("schema.invalid")

    def test_policy_step_budget(self):
        self.policy = replace(self.policy, max_steps=2)
        report = self.check("plan.step_limit")
        self.assertEqual(len(report["checks"]), 3)

    def test_one_denied_step_rejects_whole_plan(self):
        self.plan["steps"][2]["args"]["path"] = "outside/report.md"
        report = self.check("path.outside_allowlist")
        self.assertEqual([item["status"] for item in report["checks"]], ["pass", "pass", "reject"])

    def test_host_is_exact_not_suffix_or_substring(self):
        for url in ("https://docs.python.org.evil.example/", "https://evil.example/docs.python.org",
                    "https://sub.docs.python.org/", "https://docs.python.org./",
                    "https://127.0.0.1/", "https://[::1]/", "https://docs.python.org%00.evil.example/"):
            with self.subTest(url=url):
                self.plan["steps"][1]["args"]["url"] = url
                self.check("url.host")

    def test_url_credentials_fragments_scheme_and_port(self):
        cases = {"https://secret@docs.python.org/": "url.credentials",
                 "https://docs.python.org/#": "url.fragment",
                 "http://docs.python.org/": "url.scheme",
                 "https://docs.python.org:80/": "url.port",
                 "https://docs.python.org:/": "url.port",
                 "https://docs.python.org:bad/": "url.invalid",
                 "https://docs.python.org:65536/": "url.invalid",
                 "https://[bad/": "url.invalid"}
        for url, code in cases.items():
            with self.subTest(url=url):
                self.plan["steps"][1]["args"]["url"] = url
                self.check(code)

    def test_url_parser_normalization_does_not_hide_controls(self):
        for url in ("\nhttps://docs.python.org/", "https://docs.python.org/\tpath",
                    "https://docs.python.org\\@evil.example/", "https://dócs.python.org/"):
            with self.subTest(url=url):
                self.plan["steps"][1]["args"]["url"] = url
                self.check("url.invalid")

    def test_http_method_timeout_and_response_limits(self):
        self.plan["steps"][1]["args"].update(method="POST", timeout_ms=10001, max_response_bytes=262145)
        self.assertEqual(reason_codes(evaluate_plan(self.plan, self.policy)),
                         ["http.method", "http.response_limit", "http.timeout"])

    def test_nonfinite_and_surrogate_api_inputs_reject(self):
        for value in (float("nan"), float("inf"), "\ud800"):
            with self.subTest(value=repr(value)):
                self.plan["steps"][2]["args"]["content"] = value
                self.check("schema.invalid")

    def test_policy_constructor_cannot_bypass_validation(self):
        self.policy = replace(self.policy, max_steps=True)
        with self.assertRaises(InputError):
            evaluate_plan(self.plan, self.policy)

    def test_legacy_ipv4_forms_cannot_be_allowlisted(self):
        for host in ("127.1", "0177.0.0.1", "0x7f.0.0.1", "127.0x1", "127.0.01",
                     "2130706433", "0x7f000001", "127.0.0.1", "::1"):
            with self.subTest(host=host):
                data = self.policy.as_dict()
                data["allowed_hosts"] = [host]
                with self.assertRaises(InputError):
                    Policy.from_dict(data)

    def test_strict_json_rejects_duplicates_nonfinite_and_bad_encoding(self):
        for raw in ('{"key":1,"key":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}',
                    '{"x":"\\ud800"}', b'{"x":"\xff"}'):
            with self.subTest(raw=repr(raw)):
                with self.assertRaises(InputError):
                    loads(raw)

    def test_policy_config_rejects_invalid_values(self):
        for field, value in (("typo", True), ("max_steps", True), ("allowed_hosts", ["127.0.0.1"]),
                             ("allowed_hosts", ["DOCS.python.org"]),
                             ("allowed_hosts", ["docs.python.org", "docs.python.org"]),
                             ("allowed_path_prefixes", ["workspace/../private"]),
                             ("allowed_tools", ["shell.exec"]), ("allow_overwrite", 1)):
            with self.subTest(field=field, value=value):
                data = self.policy.as_dict()
                data[field] = value
                with self.assertRaises(InputError):
                    Policy.from_dict(data)

    def test_fixture_replay_matches_all_expected_decisions(self):
        result = replay_suite(load_json(ROOT / "fixtures/cases.json"), self.policy)
        self.assertEqual(result["failed"], 0, result)
        self.assertEqual(result["total"], 25)
        self.assertTrue(result["deterministic"])

    def test_replay_detects_changed_expectation(self):
        suite = load_json(ROOT / "fixtures/cases.json")
        suite["cases"][0]["expected_outcome"] = "reject"
        self.assertEqual(replay_suite(suite, self.policy)["failed"], 1)

    def test_replay_rejects_duplicate_case_names(self):
        suite = load_json(ROOT / "fixtures/cases.json")
        suite["cases"][1]["name"] = suite["cases"][0]["name"]
        with self.assertRaises(InputError):
            replay_suite(suite, self.policy)


if __name__ == "__main__":
    unittest.main()
