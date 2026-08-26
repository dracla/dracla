"""Normative revision-13 private-artifact identity namespace."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from .canonical import canonical_json

SCHEMA_VERSION = 1
RECORDS = "records"
COVERAGE = "coverage"
MAX_SAFE_INTEGER = (1 << 53) - 1


class ArtifactIdentityError(ValueError):
    """A branch/path or derived token is outside the closed v1 namespace."""


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    repository_role: str
    branch: str
    path: str
    artifact_kind: str
    capability: str
    schema_version: int = SCHEMA_VERSION

    @property
    def logical_id(self) -> str:
        return f"{self.branch}:{self.path}"


_STATIC_IDENTITIES: dict[tuple[str, str, str], tuple[str, str]] = {
    (RECORDS, "events", "config/project.enc.json"): ("project-config", RECORDS),
    (RECORDS, "events", "config/materialization-generations.enc.json"): (
        "materialization-generations",
        RECORDS,
    ),
    (RECORDS, "operations", "prepared-operation.enc.json"): (
        "prepared-operation",
        RECORDS,
    ),
    (RECORDS, "derived", "derived/state.enc.json"): ("derived-state", RECORDS),
    (COVERAGE, "coverage", "source.enc.json"): ("coverage-source", COVERAGE),
    (COVERAGE, "coverage", "inflight.enc.json"): ("inflight", COVERAGE),
    (COVERAGE, "coverage", "decision-fence.enc.json"): (
        "decision-fence",
        COVERAGE,
    ),
    (COVERAGE, "coverage", "agreements/active.enc.json"): (
        "active-agreement",
        COVERAGE,
    ),
    (COVERAGE, "coverage", "exemptions.enc.json"): (
        "exemption-fold",
        COVERAGE,
    ),
}

_EVENT_PATH = re.compile(
    r"events/(?P<aa>[A-Za-z0-9_-]{2})/(?P<bb>[A-Za-z0-9_-]{2})/"
    r"(?P<event_id>[A-Za-z0-9_-]{43})\.enc\.json"
)
_SHARD_PATHS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"derived/index/(?P<shard>\d{2})\.enc\.json"),
        "derived-index",
        RECORDS,
    ),
    (
        re.compile(r"derived/status-detail/(?P<shard>\d{2})\.enc\.json"),
        "status-detail",
        RECORDS,
    ),
    (
        re.compile(r"derived/reader-authority/(?P<shard>\d{2})\.enc\.json"),
        "reader-authority",
        RECORDS,
    ),
    (
        re.compile(r"users/(?P<shard>\d{2})\.enc\.json"),
        "coverage-shard",
        COVERAGE,
    ),
)
_EXPORT_PATH = re.compile(
    r"derived/exports/(?P<request_id>[A-Za-z0-9_-]{22})\.enc\.(?P<format>json|csv)"
)
_LOWER_HEX = re.compile(r"[0-9a-f]+")


def _validate_path(path: str) -> None:
    if type(path) is not str or not path or not path.isascii():
        raise ArtifactIdentityError("artifact path must be non-empty ASCII")
    invalid_segment = any(part in ("", ".", "..") for part in path.split("/"))
    if path.startswith("/") or invalid_segment:
        raise ArtifactIdentityError("artifact path is not repository-relative canonical form")


def _decode_base64url(value: str, *, decoded_bytes: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise ArtifactIdentityError(f"{label} is not unpadded base64url") from error
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != value or len(decoded) != decoded_bytes:
        raise ArtifactIdentityError(
            f"{label} must be canonical base64url for {decoded_bytes} bytes"
        )
    return decoded


def _validate_shard(value: str) -> None:
    if value != f"{int(value):02d}" or not 0 <= int(value) < 32:
        raise ArtifactIdentityError("shard must be a two-digit value from 00 through 31")


def resolve_artifact_identity(
    repository_role: str, branch: str, path: str
) -> ArtifactIdentity:
    """Resolve one exact row from HLD §4's closed v1 identity table."""

    if repository_role not in (RECORDS, COVERAGE):
        raise ArtifactIdentityError("repository role must be records or coverage")
    if type(branch) is not str or not branch.isascii() or not branch:
        raise ArtifactIdentityError("branch must be non-empty ASCII")
    _validate_path(path)

    static = _STATIC_IDENTITIES.get((repository_role, branch, path))
    if static is not None:
        kind, capability = static
        return ArtifactIdentity(repository_role, branch, path, kind, capability)

    if (
        repository_role == RECORDS
        and branch == "events"
        and (match := _EVENT_PATH.fullmatch(path))
    ):
        event_id = match.group("event_id")
        _decode_base64url(event_id, decoded_bytes=32, label="event_id")
        if match.group("aa") != event_id[:2] or match.group("bb") != event_id[2:4]:
            raise ArtifactIdentityError("event path shards do not match event_id")
        return ArtifactIdentity(repository_role, branch, path, "canonical-event", RECORDS)

    for pattern, kind, capability in _SHARD_PATHS:
        if match := pattern.fullmatch(path):
            expected_branch = "coverage" if capability == COVERAGE else "derived"
            if repository_role != capability or branch != expected_branch:
                break
            _validate_shard(match.group("shard"))
            return ArtifactIdentity(repository_role, branch, path, kind, capability)

    if (
        repository_role == RECORDS
        and branch == "derived"
        and (match := _EXPORT_PATH.fullmatch(path))
    ):
        _decode_base64url(
            match.group("request_id"), decoded_bytes=16, label="request_id"
        )
        kind = "export-json" if match.group("format") == "json" else "export-csv"
        return ArtifactIdentity(repository_role, branch, path, kind, RECORDS)

    raise ArtifactIdentityError(
        f"unknown v1 artifact identity {repository_role}/{branch}:{path}"
    )


def segment(value: str) -> str:
    """Hash one schema-valid agreement identifier or version into a path token."""

    if type(value) is not str or not value:
        raise ArtifactIdentityError("segment input must be a non-empty string")
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _positive_safe_integer(value: int, *, label: str) -> int:
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        raise ArtifactIdentityError(f"{label} must be a positive safe integer")
    return value


def override_key(
    *,
    repository_id: int,
    pull_request_number: int,
    subject_user_id: int,
    tree_oid: str,
) -> str:
    """Derive the normative per-subject override entry key from HLD §4."""

    if type(tree_oid) is not str or _LOWER_HEX.fullmatch(tree_oid) is None:
        raise ArtifactIdentityError("tree_oid must be non-empty lowercase hexadecimal")
    value = {
        "repository_id": _positive_safe_integer(repository_id, label="repository_id"),
        "pull_request_number": _positive_safe_integer(
            pull_request_number, label="pull_request_number"
        ),
        "subject_user_id": _positive_safe_integer(
            subject_user_id, label="subject_user_id"
        ),
        "tree_oid": tree_oid,
    }
    digest = hashlib.sha256(canonical_json(value)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
