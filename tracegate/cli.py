"""Command-line interface with machine-readable output and stable exit codes."""

import argparse
import json
import sys

from . import __version__
from .audit import AuditError, append_report, verify_audit
from .engine import evaluate_plan
from .jsonio import InputError, load_json, write_json
from .policy import load_policy
from .replay import replay_suite


def _emit(value: object, *, error: bool = False) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False),
          file=sys.stderr if error else sys.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check tool plans without executing them.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate = commands.add_parser("evaluate", help="validate and check a JSON plan")
    evaluate.add_argument("plan")
    evaluate.add_argument("--policy", default="policy.json")
    evaluate.add_argument("--approve", action="store_true", help="label policy-passing plans approve")
    evaluate.add_argument("--audit", help="append decision metadata to this JSONL chain")
    replay = commands.add_parser("replay", help="run deterministic fixture evaluation")
    replay.add_argument("suite")
    replay.add_argument("--policy", default="policy.json")
    replay.add_argument("--output", help="also save the evaluation JSON")
    verify = commands.add_parser("verify-audit", help="verify a JSONL audit chain")
    verify.add_argument("audit")
    verify.add_argument("--expected-head", help="trusted SHA-256 checkpoint, held separately")
    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            report = evaluate_plan(load_json(args.plan), load_policy(args.policy),
                                   mode="approve" if args.approve else "dry-run")
            if args.audit:
                receipt = append_report(args.audit, report)
                _emit({"audit_receipt": receipt}, error=True)
            _emit(report)
            return 2 if report["outcome"] == "reject" else 0
        if args.command == "replay":
            evaluation = replay_suite(load_json(args.suite), load_policy(args.policy))
            if args.output:
                write_json(args.output, evaluation)
            _emit(evaluation)
            return 1 if evaluation["failed"] else 0
        _emit(verify_audit(args.audit, expected_head=args.expected_head))
        return 0
    except AuditError as exc:
        _emit({"error": "audit.invalid", "message": str(exc)}, error=True)
        return 4
    except (InputError, OSError, UnicodeError) as exc:
        _emit({"error": "input.invalid", "message": str(exc)}, error=True)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
