"""Closed, finite records-derived release limits (M1 LLD §M1-11)."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from .canonical import canonical_json, parse_canonical_json
from .events import _freeze, _thaw

DERIVED_CLASSES = ("derived_index", "status_detail", "reader_authority")
_LIMITS = (
    "max_prepared_operation_bytes", "max_reader_source_members",
    "max_bulk_shards_per_operation", "max_mutation_retries",
    "max_subrequests_per_request", "max_continuous_reader_rules",
    "max_continuous_exemption_rules", "max_reader_cursor_entries",
    "max_state_ciphertext_bytes",
)
_FIELDS = {"profile_version", "shard_count", "max_shard_ciphertext_bytes", *_LIMITS}


class ReleaseProfileError(ValueError):
    """The installed profile or an observed bounded operation is invalid."""


def _positive(value: Any) -> None:
    if type(value) is not int or not 0 < value <= 2**53 - 1:
        raise ReleaseProfileError("profile limits must be finite positive safe integers")


@dataclass(frozen=True, slots=True, init=False)
class ReleaseProfile:
    """Immutable v1 profile; coverage size limits are unrepresentable."""

    _value: Any

    def __init__(self, value: dict[str, Any]) -> None:
        if type(value) is not dict or set(value) != _FIELDS:
            raise ReleaseProfileError("profile has missing or unknown members")
        if type(value["profile_version"]) is not int or value["profile_version"] != 1:
            raise ReleaseProfileError("unsupported release profile")
        if type(value["shard_count"]) is not int or value["shard_count"] != 32:
            raise ReleaseProfileError("profile requires exactly 32 shards")
        limits = value["max_shard_ciphertext_bytes"]
        if type(limits) is not dict or set(limits) != set(DERIVED_CLASSES):
            raise ReleaseProfileError("shard limits must name exactly the private derived classes")
        for limit in (*limits.values(), *(value[key] for key in _LIMITS)):
            _positive(limit)
        if value["max_subrequests_per_request"] >= 50:
            raise ReleaseProfileError("subrequest limit must be below 50")
        if value["max_continuous_reader_rules"] != 10:
            raise ReleaseProfileError("v1 permits exactly ten active continuous reader rules")
        object.__setattr__(self, "_value", _freeze(value))

    def to_dict(self) -> dict[str, Any]:
        return _thaw(self._value)

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    def limit(self, name: str, *, derived_class: str | None = None) -> int:
        if name == "max_shard_ciphertext_bytes":
            if derived_class not in DERIVED_CLASSES:
                raise ReleaseProfileError("a private derived class is required")
            return self._value[name][derived_class]
        if name not in _LIMITS or derived_class is not None:
            raise ReleaseProfileError("unknown or misclassified profile limit")
        return self._value[name]

    def check(self, name: str, actual: int, *, derived_class: str | None = None) -> None:
        """Check an observed count/byte length, including zero, against its own limit."""
        maximum = self.limit(name, derived_class=derived_class)
        if type(actual) is not int or not 0 <= actual <= maximum:
            raise ReleaseProfileError("operation exceeds its installed profile limit")


def load_release_profile(data: bytes | None = None) -> ReleaseProfile:
    """Parse exact JCS bytes, or load the packaged, checked-in numeric profile."""
    if data is None:
        data = files(__package__).joinpath("release-profile-v1.json").read_bytes()
    try:
        return ReleaseProfile(parse_canonical_json(data))
    except (ValueError, TypeError) as error:
        raise ReleaseProfileError("release profile must be closed canonical JSON") from error
