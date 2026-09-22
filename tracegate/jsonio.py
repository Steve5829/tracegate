"""Strict JSON input and one canonical encoding used for every digest."""

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 2 * 1024 * 1024


class InputError(ValueError):
    """Untrusted input did not satisfy the declared contract."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InputError(f"non-finite JSON number: {value}")


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise InputError("value cannot be encoded as canonical UTF-8 JSON") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def loads(raw: str | bytes) -> Any:
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
        canonical(value)  # Reject invalid Unicode and numbers such as 1e999.
        return value
    except InputError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from exc


def load_json(path: str | Path) -> Any:
    with Path(path).open("rb") as source:
        raw = source.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise InputError(f"JSON input exceeds {MAX_JSON_BYTES} bytes")
    return loads(raw)


def write_json(path: str | Path, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False,
                                     allow_nan=False) + "\n", encoding="utf-8")
