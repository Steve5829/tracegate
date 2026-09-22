"""Immutable, strictly loaded policy configuration."""

from dataclasses import asdict, dataclass
import ipaddress
import re
from typing import Any

from .jsonio import InputError, load_json
from .schema import METHODS, TOOLS, exact_object, identifier, integer, string


def path_parts(path: str) -> tuple[str, ...]:
    parts = tuple(path.split("/"))
    if any(part in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9_. -]+", part)
           or part.endswith((" ", ".")) for part in parts):
        raise InputError("path must be a canonical relative ASCII path without traversal, "
                         "backslashes, encoding, or ambiguous trailing characters")
    return parts


def hostname(host: Any) -> str:
    string(host, "allowed_hosts entry", 253)
    if host != host.lower() or "." not in host:
        raise InputError("allowed hosts must be lowercase fully qualified DNS names")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
               for label in host.split(".")):
        raise InputError("allowed hosts must be canonical ASCII DNS names")
    # Legacy IPv4 parsers accept forms ipaddress rejects, including 127.1,
    # 0177.0.0.1 and 0x7f.0.0.1. A letter-led final DNS label excludes these
    # numeric address forms without DNS lookups or platform-specific parsing.
    if not re.match(r"[a-z]", host.rsplit(".", 1)[-1]):
        raise InputError("allowed hosts must have a final DNS label beginning with a letter")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise InputError("IP literals cannot be allowlisted")


def unique_strings(value: Any, where: str, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 128:
        raise InputError(f"{where} must be a list of at most 128 strings")
    for item in value:
        string(item, f"{where} entry")
        if allowed is not None and item not in allowed:
            raise InputError(f"unsupported {where} entry: {item}")
    if len(value) != len(set(value)):
        raise InputError(f"{where} must not contain duplicates")
    return tuple(sorted(value))


@dataclass(frozen=True)
class Policy:
    policy_version: int
    name: str
    allowed_tools: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allow_overwrite: bool
    max_steps: int
    max_read_bytes: int
    max_write_bytes: int
    max_response_bytes: int
    max_timeout_ms: int

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for field in ("allowed_tools", "allowed_path_prefixes", "allowed_hosts", "allowed_methods"):
            result[field] = list(result[field])
        return result

    @classmethod
    def from_dict(cls, value: Any) -> "Policy":
        exact_object(value, set(cls.__dataclass_fields__), "policy")
        integer(value["policy_version"], "policy_version", 1, 1)
        identifier(value["name"], "policy.name")
        tools = unique_strings(value["allowed_tools"], "allowed_tools", TOOLS)
        paths = unique_strings(value["allowed_path_prefixes"], "allowed_path_prefixes")
        for path in paths:
            path_parts(path)
        hosts = unique_strings(value["allowed_hosts"], "allowed_hosts")
        for host in hosts:
            hostname(host)
        methods = unique_strings(value["allowed_methods"], "allowed_methods", METHODS)
        if type(value["allow_overwrite"]) is not bool:
            raise InputError("allow_overwrite must be a boolean")
        integer(value["max_steps"], "max_steps", 1, 128)
        for field in ("max_read_bytes", "max_write_bytes", "max_response_bytes"):
            integer(value[field], field, 1, 16 * 1024 * 1024)
        integer(value["max_timeout_ms"], "max_timeout_ms", 1, 120_000)
        return cls(**{**value, "allowed_tools": tools, "allowed_path_prefixes": paths,
                      "allowed_hosts": hosts, "allowed_methods": methods})


def load_policy(path: str) -> Policy:
    return Policy.from_dict(load_json(path))
