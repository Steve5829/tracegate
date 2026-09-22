"""Canonical JSONL hash chain, with optional externally trusted head checking.

Hashes detect edits relative to a trusted checkpoint; they do not authenticate a
writer. Lock files serialize cooperating writers only. Reports omit raw tool
arguments, but identifiers and diagnostic strings can contain caller input.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import re
from typing import Any, Iterator

from .jsonio import InputError, canonical, digest, loads
from .schema import exact_object, integer

ZERO_HASH = "0" * 64
MAX_AUDIT_BYTES = 64 * 1024 * 1024


class AuditError(ValueError):
    """An audit chain or cooperating-writer lock is invalid."""


def _verify(raw: bytes, expected_head: str | None = None) -> dict[str, Any]:
    if raw and not raw.endswith(b"\n"):
        raise AuditError("audit is incomplete: final newline is missing")
    previous = ZERO_HASH
    count = 0
    for count, line in enumerate(raw.split(b"\n")[:-1], 1):
        try:
            entry = loads(line)
            exact_object(entry, {"audit_version", "sequence", "previous_hash", "event",
                                 "payload", "hash"}, f"audit line {count}")
            integer(entry["audit_version"], "audit_version", 1, 1)
            integer(entry["sequence"], "sequence", count, count)
            if entry["event"] != "plan.evaluated" or type(entry["payload"]) is not dict:
                raise InputError("unsupported event or payload type")
            if canonical(entry) != line:
                raise InputError("record is not canonical JSON")
            if entry["previous_hash"] != previous:
                raise InputError("previous hash mismatch")
            body = {key: value for key, value in entry.items() if key != "hash"}
            if entry["hash"] != digest(body):
                raise InputError("record hash mismatch")
            previous = entry["hash"]
        except InputError as exc:
            raise AuditError(f"audit line {count}: {exc}") from exc
    if expected_head is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_head):
            raise AuditError("expected head must be a lowercase SHA-256 digest")
        if previous != expected_head:
            raise AuditError("head differs from trusted checkpoint (possible truncation or rewrite)")
    return {"valid": True, "records": count, "head": previous,
            "checkpoint_verified": expected_head is not None}


def _read(path: Path) -> bytes:
    with path.open("rb") as source:
        raw = source.read(MAX_AUDIT_BYTES + 1)
    if len(raw) > MAX_AUDIT_BYTES:
        raise AuditError(f"audit exceeds {MAX_AUDIT_BYTES} bytes; rotate to a new chain")
    return raw


def verify_audit(path: str | Path, *, expected_head: str | None = None) -> dict[str, Any]:
    return _verify(_read(Path(path)), expected_head)


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise AuditError(f"audit lock exists: {lock_path}; another writer may be active") from exc
    try:
        os.close(descriptor)
        yield
    finally:
        lock_path.unlink()


def append_report(path: str | Path, report: dict[str, Any]) -> dict[str, Any]:
    """Append a trusted engine report. This function is not a redaction boundary.

    The CLI supplies evaluate_plan output, which excludes raw tool arguments.
    Direct API callers must supply that output, not arbitrary report-shaped data.
    """
    exact_object(report, {"report_version", "plan_id", "outcome", "mode", "plan_sha256",
                          "policy_sha256", "errors", "checks"}, "audit report")
    path = Path(path)
    with _lock(path):
        raw = _read(path) if path.exists() else b""
        state = _verify(raw)
        body = {"audit_version": 1, "sequence": state["records"] + 1,
                "previous_hash": state["head"], "event": "plan.evaluated", "payload": report}
        record = {**body, "hash": digest(body)}
        encoded = canonical(record) + b"\n"
        if len(raw) + len(encoded) > MAX_AUDIT_BYTES:
            raise AuditError("append would exceed audit size limit")
        with path.open("ab") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
    return {"sequence": record["sequence"], "head": record["hash"]}
