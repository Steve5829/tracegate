"""Pure policy evaluation. This module has no filesystem or network executor."""

from typing import Any
from urllib.parse import urlsplit

from .jsonio import InputError, digest
from .policy import Policy, path_parts
from .schema import validate_plan


def reason(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _path_checks(path: str, policy: Policy) -> list[dict[str, str]]:
    try:
        parts = path_parts(path)
    except InputError as exc:
        return [reason("path.invalid", str(exc))]
    if not any(parts[:len(prefix)] == prefix
               for prefix in map(path_parts, policy.allowed_path_prefixes)):
        return [reason("path.outside_allowlist", "path is outside every allowed prefix")]
    return []


def _url_checks(url: str, policy: Policy) -> list[dict[str, str]]:
    if any(ord(char) <= 32 or ord(char) >= 127 for char in url) or "\\" in url:
        return [reason("url.invalid", "URL must be ASCII without whitespace, controls, or backslashes")]
    try:
        parsed = urlsplit(url)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        return [reason("url.invalid", "URL authority or port is malformed")]
    issues = []
    if parsed.scheme != "https":
        issues.append(reason("url.scheme", "only HTTPS URLs are permitted"))
    if parsed.username is not None or parsed.password is not None:
        issues.append(reason("url.credentials", "URL credentials are prohibited"))
    if "#" in url:
        issues.append(reason("url.fragment", "URL fragments are prohibited"))
    if port not in (None, 443) or parsed.netloc.endswith(":"):
        issues.append(reason("url.port", "only the default HTTPS port is permitted"))
    if host not in policy.allowed_hosts:
        issues.append(reason("url.host", "hostname is not an exact allowlist match"))
    return issues


def _step_checks(step: dict[str, Any], policy: Policy) -> list[dict[str, str]]:
    tool, args = step["tool"], step["args"]
    if tool not in policy.allowed_tools:
        return [reason("tool.denied", "tool is disabled by policy")]
    issues = []
    if tool in {"file.read", "file.write"}:
        issues.extend(_path_checks(args["path"], policy))
    if tool == "file.read" and args["max_bytes"] > policy.max_read_bytes:
        issues.append(reason("read.limit", "requested read size exceeds policy"))
    elif tool == "file.write":
        if len(args["content"].encode("utf-8")) > policy.max_write_bytes:
            issues.append(reason("write.limit", "UTF-8 content size exceeds policy"))
        if args["overwrite"] and not policy.allow_overwrite:
            issues.append(reason("write.overwrite", "overwriting files is disabled"))
    elif tool == "http.request":
        issues.extend(_url_checks(args["url"], policy))
        if args["method"] not in policy.allowed_methods:
            issues.append(reason("http.method", "HTTP method is disabled by policy"))
        if args["timeout_ms"] > policy.max_timeout_ms:
            issues.append(reason("http.timeout", "requested timeout exceeds policy"))
        if args["max_response_bytes"] > policy.max_response_bytes:
            issues.append(reason("http.response_limit", "requested response size exceeds policy"))
    return issues


def evaluate_plan(plan: Any, policy: Policy, *, mode: str = "dry-run") -> dict[str, Any]:
    """Return a deterministic decision without performing any proposed operation.

    `approve` labels a policy-passing proposal; it is not a human approval token.
    Schema rejection is all-or-nothing. Policy checks report every valid step.
    """
    if mode not in {"dry-run", "approve"}:
        raise InputError("mode must be dry-run or approve")
    # Revalidate even a directly constructed dataclass at the public API boundary.
    policy = Policy.from_dict(policy.as_dict())
    report: dict[str, Any] = {
        "report_version": 1, "plan_id": None, "outcome": "reject", "mode": mode,
        "plan_sha256": None, "policy_sha256": digest(policy.as_dict()),
        "errors": [], "checks": [],
    }
    try:
        report["plan_sha256"] = digest(plan)
        validate_plan(plan)
    except InputError as exc:
        report["errors"].append(reason("schema.invalid", str(exc)))
        return report
    report["plan_id"] = plan["plan_id"]
    if len(plan["steps"]) > policy.max_steps:
        report["errors"].append(reason("plan.step_limit", "step count exceeds policy"))
    for step in plan["steps"]:
        issues = _step_checks(step, policy)
        report["checks"].append({"step_id": step["id"], "tool": step["tool"],
                                 "status": "reject" if issues else "pass", "reasons": issues})
    if not report["errors"] and all(check["status"] == "pass" for check in report["checks"]):
        report["outcome"] = mode
    return report
