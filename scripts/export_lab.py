"""Export real engine decisions for the static portfolio replay viewer."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracegate.engine import evaluate_plan
from tracegate.jsonio import load_json, write_json
from tracegate.policy import load_policy
from tracegate.replay import replay_suite


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "lab.json")
    args = parser.parse_args()
    policy = load_policy(ROOT / "policy.json")
    suite = load_json(ROOT / "fixtures" / "cases.json")
    evaluation = replay_suite(suite, policy)
    if evaluation["failed"] or not evaluation["deterministic"]:
        raise SystemExit("Refusing to export a failed or nondeterministic fixture run")
    payload = {
        "format_version": 1,
        "source": "https://github.com/Steve5829/tracegate",
        "policy": policy.as_dict(),
        "evaluation": evaluation,
        "cases": [
            {
                "name": case["name"],
                "plan": case["plan"],
                "report": evaluate_plan(case["plan"], policy, mode=case["mode"]),
            }
            for case in suite["cases"]
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, payload)
    print(f"Exported {len(payload['cases'])} passing fixture evaluations to {args.output}")


if __name__ == "__main__":
    main()
