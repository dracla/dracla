"""Strict RFC 8785 JSON Canonicalization Scheme helpers."""

from __future__ import annotations

import json
from typing import Any

import rfc8785


class CanonicalJsonError(ValueError):
    """A value or byte string is not valid canonical JSON."""


class NonCanonicalJsonError(CanonicalJsonError):
    """JSON is parseable but its bytes are not the one canonical encoding."""


def _validate_json_value(value: Any, *, location: str = "$") -> None:
    if value is None or type(value) in (bool, str, int, float):
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_json_value(item, location=f"{location}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalJsonError(f"{location} has a non-string object key")
            _validate_json_value(item, location=f"{location}.{key}")
        return
    raise CanonicalJsonError(
        f"{location} has unsupported JSON value type {type(value).__name__}"
    )


def canonical_json(value: Any) -> bytes:
    """Return the sole RFC 8785 UTF-8 encoding for a JSON data-model value."""

    _validate_json_value(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError) as error:
        raise CanonicalJsonError(str(error)) from error


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CanonicalJsonError(f"duplicate object member {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise CanonicalJsonError(f"non-JSON numeric constant {value!r}")


def parse_canonical_json(data: bytes) -> Any:
    """Parse only exact JCS bytes, rejecting duplicates and alternate encodings."""

    if type(data) is not bytes:
        raise TypeError("canonical JSON input must be bytes")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except CanonicalJsonError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CanonicalJsonError(str(error)) from error
    if canonical_json(value) != data:
        raise NonCanonicalJsonError("JSON bytes are not the RFC 8785 encoding")
    return value

