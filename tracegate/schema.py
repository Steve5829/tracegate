"""Small explicit schemas: unknown fields and bool-as-int are errors."""

import re
from typing import Any

from .jsonio import InputError

TOOLS = frozenset({"file.read", "file.write", "http.request"})
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})


def exact_object(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise InputError(f"{where} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown or missing:
        raise InputError(f"{where}: unknown fields={sorted(unknown, key=str)}, "
                         f"missing fields={sorted(missing)}")
    return value


def string(value: Any, where: str, maximum: int = 2048, *, empty: bool = False) -> str:
    if type(value) is not str or (not value and not empty) or len(value) > maximum:
        raise InputError(f"{where} must be a {'possibly empty ' if empty else ''}string "
                         f"of at most {maximum} characters")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise InputError(f"{where} must contain valid Unicode") from exc
    return value


def integer(value: Any, where: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InputError(f"{where} must be an integer in [{minimum}, {maximum}]")
    return value


def identifier(value: Any, where: str) -> str:
    string(value, where, 80)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise InputError(f"{where} must be an ASCII identifier")
    return value


def validate_plan(plan: Any) -> dict[str, Any]:
    exact_object(plan, {"schema_version", "plan_id", "steps"}, "plan")
    integer(plan["schema_version"], "schema_version", 1, 1)
    identifier(plan["plan_id"], "plan_id")
    steps = plan["steps"]
    if type(steps) is not list or not 1 <= len(steps) <= 128:
        raise InputError("steps must be a list containing 1 to 128 operations")
    identifiers: set[str] = set()
    for index, step in enumerate(steps):
        where = f"steps[{index}]"
        exact_object(step, {"id", "tool", "args"}, where)
        step_id = identifier(step["id"], f"{where}.id")
        if step_id in identifiers:
            raise InputError(f"duplicate step id: {step_id}")
        identifiers.add(step_id)
        tool = string(step["tool"], f"{where}.tool", 80)
        if tool not in TOOLS:
            raise InputError(f"unknown tool: {tool}")
        args = step["args"]
        if tool == "file.read":
            exact_object(args, {"path", "max_bytes"}, f"{where}.args")
            string(args["path"], f"{where}.args.path")
            integer(args["max_bytes"], f"{where}.args.max_bytes", 1, 16 * 1024 * 1024)
        elif tool == "file.write":
            exact_object(args, {"path", "content", "overwrite"}, f"{where}.args")
            string(args["path"], f"{where}.args.path")
            string(args["content"], f"{where}.args.content", 1024 * 1024, empty=True)
            if type(args["overwrite"]) is not bool:
                raise InputError(f"{where}.args.overwrite must be a boolean")
        else:
            exact_object(args, {"url", "method", "timeout_ms", "max_response_bytes"},
                         f"{where}.args")
            string(args["url"], f"{where}.args.url", 4096)
            method = string(args["method"], f"{where}.args.method", 8)
            if method not in METHODS:
                raise InputError(f"unsupported HTTP method: {method}")
            integer(args["timeout_ms"], f"{where}.args.timeout_ms", 1, 120_000)
            integer(args["max_response_bytes"], f"{where}.args.max_response_bytes",
                    1, 16 * 1024 * 1024)
    return plan
