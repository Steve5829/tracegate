"""Replay local fixtures against declared expected decisions and reason codes."""

from collections import Counter
from typing import Any

from .engine import evaluate_plan
from .jsonio import InputError, canonical, digest
from .policy import Policy
from .schema import exact_object, identifier, integer, string


def reason_codes(report: dict[str, Any]) -> list[str]:
    return sorted({item["code"] for item in report["errors"]} |
                  {item["code"] for check in report["checks"] for item in check["reasons"]})


def replay_suite(suite: Any, policy: Policy) -> dict[str, Any]:
    exact_object(suite, {"suite_version", "cases"}, "suite")
    integer(suite["suite_version"], "suite_version", 1, 1)
    if type(suite["cases"]) is not list or not 1 <= len(suite["cases"]) <= 1000:
        raise InputError("suite.cases must contain 1 to 1000 cases")
    seen: set[str] = set()
    results = []
    counts: Counter[str] = Counter()
    for case in suite["cases"]:
        exact_object(case, {"name", "plan", "mode", "expected_outcome", "expected_codes"}, "case")
        name = identifier(case["name"], "case.name")
        if name in seen:
            raise InputError(f"duplicate case name: {name}")
        seen.add(name)
        mode = string(case["mode"], "case.mode", 16)
        expected = string(case["expected_outcome"], "expected_outcome", 16)
        if expected not in {"dry-run", "approve", "reject"}:
            raise InputError("invalid expected outcome")
        codes = case["expected_codes"]
        if type(codes) is not list or any(type(code) is not str for code in codes):
            raise InputError("expected_codes must be a list of strings")
        if len(codes) != len(set(codes)):
            raise InputError("expected_codes must be unique")
        first = evaluate_plan(case["plan"], policy, mode=mode)
        second = evaluate_plan(case["plan"], policy, mode=mode)
        actual_codes = reason_codes(first)
        deterministic = canonical(first) == canonical(second)
        passed = (first["outcome"] == expected and actual_codes == sorted(codes) and deterministic)
        counts.update(actual_codes)
        results.append({"name": name, "passed": passed, "deterministic": deterministic,
                        "expected_outcome": expected, "actual_outcome": first["outcome"],
                        "expected_codes": sorted(codes), "actual_codes": actual_codes,
                        "report_sha256": digest(first)})
    return {"evaluation_version": 1, "suite_sha256": digest(suite),
            "policy_sha256": digest(policy.as_dict()), "total": len(results),
            "passed": sum(result["passed"] for result in results),
            "failed": sum(not result["passed"] for result in results),
            "deterministic": all(result["deterministic"] for result in results),
            "reason_counts": dict(sorted(counts.items())), "cases": results}
