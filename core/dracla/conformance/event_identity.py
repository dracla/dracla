"""Revision-13 event identities, operation nonces, and authorization evidence.

This module intentionally stops at the identity and authorization boundary.  It
does not know the v1 event target/payload union (that belongs to ``events``),
nor does it inspect GitHub.  Inputs are checked sufficiently to make the
byte-level identity and the closed authorization vocabulary unambiguous.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .canonical import MAX_SAFE_INTEGER, canonical_json
from .encoding import Base64UrlError, base64url_decode, base64url_encode


OPERATION_NONCE_BYTES = 16
SHA256_BYTES = 32
EVENT_ID_BYTES = SHA256_BYTES
SCHEMA_VERSION = 1

_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ASCII_TOKEN = re.compile(r"[\x21-\x7e]+\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class EventIdentityError(ValueError):
    """An event identity input is outside the revision-13 contract."""


class AuthorizationError(EventIdentityError):
    """Authorization evidence is malformed or not valid for the event."""


# A named subclass is useful to callers that distinguish a malformed evidence
# member from an identity failure.  The public parent remains intentionally
# small: callers should not need to inspect untrusted values in exceptions.
class AuthorizationValidationError(AuthorizationError):
    """Authorization evidence failed the closed vocabulary or relation checks."""


# The literal v1 operation/resource/authority table from HLD §5.1.  In
# particular, operation names are not inferred from event-name prefixes.
AUTHORIZATION_TABLE: tuple[tuple[str, str, str, str], ...] = (
    ("project_connected", "project_connect_owner", "account", "repository_owner_control"),
    ("project_connected", "project_connect_records_repository", "repository", "project_repository_admin"),
    ("project_connected", "project_connect_coverage_repository", "repository", "project_repository_admin"),
    ("project_connected", "project_connect_control_repository", "repository", "project_repository_admin"),
    ("project_connected", "project_connect_records_app", "installation", "records_app_binding"),
    ("project_connected", "project_connect_enforcer_app", "installation", "enforcer_app_binding"),
    ("project_connected", "project_connect_trigger_app", "installation", "trigger_app_binding"),
    ("project_repository_owner_changed", "project_repository_owner_change_owner", "account", "repository_owner_control"),
    ("project_repository_owner_changed", "project_repository_owner_change_records_repository", "repository", "project_repository_admin"),
    ("project_repository_owner_changed", "project_repository_owner_change_coverage_repository", "repository", "project_repository_admin"),
    ("project_repository_owner_changed", "project_repository_owner_change_control_repository", "repository", "project_repository_admin"),
    ("project_repository_owner_changed", "project_repository_owner_change_records_app", "installation", "records_app_binding"),
    ("project_repository_owner_changed", "project_repository_owner_change_enforcer_app", "installation", "enforcer_app_binding"),
    ("project_repository_owner_changed", "project_repository_owner_change_trigger_app", "installation", "trigger_app_binding"),
    ("project_succeeded", "project_succeed", "repository", "records_repository_admin"),
    ("keyring_activated", "keyring_activate", "repository", "project_repository_admin"),
    ("agreement_published", "agreement_publish", "repository", "records_repository_admin"),
    ("agreement_activated", "agreement_activate", "repository", "records_repository_admin"),
    ("config_updated", "project_config_update", "repository", "records_repository_admin"),
    ("enforcement_scope_requested", "enforcement_scope_repository_bind", "repository", "contributing_repository_admin"),
    ("enforcement_scope_requested", "enforcement_scope_repository_widen", "repository", "contributing_repository_admin"),
    ("enforcement_scope_requested", "enforcement_scope_repository_narrow", "repository", "contributing_repository_admin"),
    ("enforcement_scope_requested", "enforcement_scope_repository_remove", "repository", "contributing_repository_admin"),
    ("enforcement_scope_requested", "enforcement_scope_organization_bind", "organization", "organization_owner"),
    ("enforcement_scope_requested", "enforcement_scope_organization_widen", "organization", "organization_owner"),
    ("enforcement_scope_requested", "enforcement_scope_organization_narrow", "organization", "organization_owner"),
    ("enforcement_scope_requested", "enforcement_scope_organization_remove", "organization", "organization_owner"),
    ("enforcement_scope_activated", "enforcement_scope_repository_bind", "repository", "contributing_repository_admin"),
    ("enforcement_scope_activated", "enforcement_scope_repository_widen", "repository", "contributing_repository_admin"),
    ("enforcement_scope_activated", "enforcement_scope_repository_narrow", "repository", "contributing_repository_admin"),
    ("enforcement_scope_activated", "enforcement_scope_repository_remove", "repository", "contributing_repository_admin"),
    ("enforcement_scope_activated", "enforcement_scope_organization_bind", "organization", "organization_owner"),
    ("enforcement_scope_activated", "enforcement_scope_organization_widen", "organization", "organization_owner"),
    ("enforcement_scope_activated", "enforcement_scope_organization_narrow", "organization", "organization_owner"),
    ("enforcement_scope_activated", "enforcement_scope_organization_remove", "organization", "organization_owner"),
    ("enforcement_scope_abandoned", "enforcement_scope_repository_bind", "repository", "contributing_repository_admin"),
    ("enforcement_scope_abandoned", "enforcement_scope_repository_widen", "repository", "contributing_repository_admin"),
    ("enforcement_scope_abandoned", "enforcement_scope_repository_narrow", "repository", "contributing_repository_admin"),
    ("enforcement_scope_abandoned", "enforcement_scope_repository_remove", "repository", "contributing_repository_admin"),
    ("enforcement_scope_abandoned", "enforcement_scope_organization_bind", "organization", "organization_owner"),
    ("enforcement_scope_abandoned", "enforcement_scope_organization_widen", "organization", "organization_owner"),
    ("enforcement_scope_abandoned", "enforcement_scope_organization_narrow", "organization", "organization_owner"),
    ("enforcement_scope_abandoned", "enforcement_scope_organization_remove", "organization", "organization_owner"),
    ("exemption", "exemption_bot_add", "repository", "records_repository_admin"),
    ("exemption", "exemption_individual_add", "repository", "records_repository_admin"),
    ("exemption_snapshot", "exemption_snapshot_add", "repository", "records_repository_admin"),
    ("exemption_source_withdrawn", "exemption_source_withdraw", "repository", "records_repository_admin"),
    ("exemption_rule_configured", "exemption_rule_configure", "repository", "records_repository_admin"),
    ("exemption_rule_withdrawn", "exemption_rule_withdraw", "repository", "records_repository_admin"),
    ("records_reader_authorized", "records_reader_individual_add", "repository", "records_repository_admin"),
    ("records_reader_snapshot_authorized", "records_reader_snapshot_add", "repository", "records_repository_admin"),
    ("records_reader_withdrawn", "records_reader_source_withdraw", "repository", "records_repository_admin"),
    ("records_reader_rule_configured", "records_reader_rule_configure", "repository", "records_repository_admin"),
    ("records_reader_rule_withdrawn", "records_reader_rule_withdraw", "repository", "records_repository_admin"),
    ("override", "override_grant", "repository", "contributing_repository_maintain"),
    ("override_withdrawn", "override_withdraw", "repository", "contributing_repository_maintain"),
    ("retry_requested", "retry_request", "repository", "contributing_repository_write"),
)

_EVENT_TYPES = frozenset(
    {
        "acceptance",
        "revocation",
        "agreement_published",
        "agreement_activated",
        "project_connected",
        "project_repository_owner_changed",
        "project_succeeded",
        "config_updated",
        "keyring_activated",
        "enforcement_scope_requested",
        "enforcement_scope_activated",
        "enforcement_scope_abandoned",
        "override",
        "override_withdrawn",
        "retry_requested",
        "exemption",
        "exemption_snapshot",
        "exemption_source_withdrawn",
        "exemption_rule_configured",
        "exemption_rule_withdrawn",
        "exemption_materialized",
        "records_reader_authorized",
        "records_reader_snapshot_authorized",
        "records_reader_withdrawn",
        "records_reader_rule_configured",
        "records_reader_rule_withdrawn",
        "records_reader_materialized",
    }
)

_NO_AUTH_EVENTS = frozenset(
    {"acceptance", "revocation", "exemption_materialized", "records_reader_materialized"}
)
_SCOPE_EVENTS = frozenset(
    {
        "enforcement_scope_requested",
        "enforcement_scope_activated",
        "enforcement_scope_abandoned",
    }
)
_AUTH_RESOURCE_KINDS = frozenset({"account", "repository", "organization", "installation"})
_REQUIRED_AUTHORITIES = frozenset(
    {
        "repository_owner_control",
        "project_repository_admin",
        "records_app_binding",
        "enforcer_app_binding",
        "trigger_app_binding",
        "records_repository_admin",
        "contributing_repository_admin",
        "contributing_repository_maintain",
        "contributing_repository_write",
        "organization_owner",
    }
)

_OPERATION_PAIRS: dict[str, tuple[str, str]] = {
    operation: (resource_kind, authority)
    for _event, operation, resource_kind, authority in AUTHORIZATION_TABLE
}
_OPERATION_PAIRS = MappingProxyType(_OPERATION_PAIRS)

_FIXED_EVENT_ROWS: Mapping[str, tuple[str, str, str]] = MappingProxyType(
    {
        "project_succeeded": ("project_succeed", "repository", "records_repository_admin"),
        "agreement_published": ("agreement_publish", "repository", "records_repository_admin"),
        "agreement_activated": ("agreement_activate", "repository", "records_repository_admin"),
        "config_updated": ("project_config_update", "repository", "records_repository_admin"),
        "exemption_snapshot": ("exemption_snapshot_add", "repository", "records_repository_admin"),
        "exemption_source_withdrawn": ("exemption_source_withdraw", "repository", "records_repository_admin"),
        "exemption_rule_configured": ("exemption_rule_configure", "repository", "records_repository_admin"),
        "exemption_rule_withdrawn": ("exemption_rule_withdraw", "repository", "records_repository_admin"),
        "records_reader_authorized": ("records_reader_individual_add", "repository", "records_repository_admin"),
        "records_reader_snapshot_authorized": ("records_reader_snapshot_add", "repository", "records_repository_admin"),
        "records_reader_withdrawn": ("records_reader_source_withdraw", "repository", "records_repository_admin"),
        "records_reader_rule_configured": ("records_reader_rule_configure", "repository", "records_repository_admin"),
        "records_reader_rule_withdrawn": ("records_reader_rule_withdraw", "repository", "records_repository_admin"),
        "override": ("override_grant", "repository", "contributing_repository_maintain"),
        "override_withdrawn": ("override_withdraw", "repository", "contributing_repository_maintain"),
        "retry_requested": ("retry_request", "repository", "contributing_repository_write"),
    }
)

_SCOPE_OPERATIONS: Mapping[str, tuple[str, str, str]] = MappingProxyType(
    {
        "enforcement_scope_repository_bind": ("repository", "contributing_repository_admin", "bind"),
        "enforcement_scope_repository_widen": ("repository", "contributing_repository_admin", "widen"),
        "enforcement_scope_repository_narrow": ("repository", "contributing_repository_admin", "narrow"),
        "enforcement_scope_repository_remove": ("repository", "contributing_repository_admin", "remove"),
        "enforcement_scope_organization_bind": ("organization", "organization_owner", "bind"),
        "enforcement_scope_organization_widen": ("organization", "organization_owner", "widen"),
        "enforcement_scope_organization_narrow": ("organization", "organization_owner", "narrow"),
        "enforcement_scope_organization_remove": ("organization", "organization_owner", "remove"),
    }
)


def _fail(message: str, *, authorization: bool = False) -> None:
    error = AuthorizationValidationError if authorization else EventIdentityError
    raise error(message)


def _non_empty_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _token(value: Any, label: str) -> str:
    if type(value) is not str or _ASCII_TOKEN.fullmatch(value) is None:
        _fail(f"{label} must be a non-empty ASCII token")
    return value


def _positive_id(value: Any, label: str, *, authorization: bool = False) -> int:
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        _fail(f"{label} must be a positive safe integer", authorization=authorization)
    return value


def _git_oid(value: Any, label: str, *, authorization: bool = False) -> str:
    if type(value) is not str or _GIT_OID.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase Git object ID", authorization=authorization)
    return value


def _object(value: Any, label: str, *, authorization: bool = False) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{label} must be a JSON object", authorization=authorization)
    try:
        canonical_json(value)
    except (TypeError, ValueError):
        _fail(f"{label} is not a canonical JSON data-model value", authorization=authorization)
    return value


def _validate_timestamp(value: Any, *, authorization: bool = False) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        _fail("checked_at must be a UTC whole-second timestamp", authorization=authorization)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail("checked_at must be a valid UTC timestamp", authorization=authorization)
    return value


def stable_actor_identity(actor: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable identity portion of one v1 actor object."""

    if not isinstance(actor, Mapping):
        _fail("actor must be an object")
    keys = set(actor)
    kind = actor.get("kind")
    if kind == "github" and keys == {"kind", "github_user_id", "login_snapshot"}:
        _positive_id(actor.get("github_user_id"), "github_user_id")
        _non_empty_string(actor.get("login_snapshot"), "login_snapshot")
        return {"kind": "github", "github_user_id": actor["github_user_id"]}
    if (
        kind == "automation"
        and keys == {"kind", "principal"}
        and actor.get("principal") == "worker-portal"
    ):
        return {"kind": "automation", "principal": "worker-portal"}
    _fail("actor is not a supported v1 actor")


def _nonce_from_digest(domain: str, value: dict[str, Any]) -> str:
    digest = hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_json(value)).digest()
    return base64url_encode(digest[:OPERATION_NONCE_BYTES])


def new_operation_nonce() -> str:
    """Generate exactly 16 CSPRNG bytes and return unpadded base64url."""

    value = secrets.token_bytes(OPERATION_NONCE_BYTES)
    if type(value) is not bytes or len(value) != OPERATION_NONCE_BYTES:
        _fail("platform CSPRNG returned an invalid nonce")
    return base64url_encode(value)


def derive_automation_nonce(
    rule_event_id: str,
    subject_user_id: int,
    result: str,
    prior_materialization_event_id: str | None,
) -> str:
    """Derive the retry-stable nonce for one team-rule observation."""

    _non_empty_string(rule_event_id, "rule_event_id")
    _positive_id(subject_user_id, "subject_user_id")
    if type(result) is not str or result not in {"add", "withdraw"}:
        _fail("result is not a supported automation transition")
    if prior_materialization_event_id is not None:
        _non_empty_string(prior_materialization_event_id, "prior_materialization_event_id")
    return _nonce_from_digest(
        "dracla-automation-transition-v1",
        {
            "rule_event_id": rule_event_id,
            "subject_user_id": subject_user_id,
            "result": result,
            "prior_materialization_event_id": prior_materialization_event_id,
        },
    )


def derive_github_retry_nonce(
    repository_id: int,
    check_kind: str,
    check_identity: int | str,
    github_delivery_id: str | None,
) -> str:
    """Derive the retry-stable nonce for a GitHub delivery."""

    _positive_id(repository_id, "repository_id")
    if type(check_kind) is not str or check_kind not in {"pull_request", "merge_group"}:
        _fail("check_kind is not supported")
    if check_kind == "pull_request":
        _positive_id(check_identity, "check_identity")
    else:
        _git_oid(check_identity, "check_identity")
    if github_delivery_id is not None:
        _non_empty_string(github_delivery_id, "github_delivery_id")
    return _nonce_from_digest(
        "dracla-github-retry-v1",
        {
            "repository_id": repository_id,
            "check_kind": check_kind,
            "check_identity": check_identity,
            "github_delivery_id": github_delivery_id,
        },
    )


def derive_scope_terminal_nonce(request_event_id: str, terminal_type: str) -> str:
    """Derive a scope-terminal child nonce after checking both child materials."""

    _non_empty_string(request_event_id, "request_event_id")
    if type(terminal_type) is not str or terminal_type not in {
        "enforcement_scope_activated",
        "enforcement_scope_abandoned",
    }:
        _fail("terminal_type is not a supported scope terminal")
    child_material = {
        child_type: hashlib.sha256(
            b"dracla-scope-terminal-v1\0"
            + canonical_json({"request_event_id": request_event_id, "terminal_type": child_type})
        ).digest()[:OPERATION_NONCE_BYTES]
        for child_type in ("enforcement_scope_activated", "enforcement_scope_abandoned")
    }
    if child_material["enforcement_scope_activated"] == child_material["enforcement_scope_abandoned"]:
        _fail("scope terminal child nonce digest collision")
    return base64url_encode(child_material[terminal_type])


def event_path(event_id: str) -> str:
    """Return the canonical records path for a 256-bit event ID."""

    try:
        base64url_decode(event_id, expected_length=EVENT_ID_BYTES, label="event_id")
    except (Base64UrlError, TypeError):
        _fail("event_id must be canonical base64url for 32 bytes")
    return f"events/{event_id[:2]}/{event_id[2:4]}/{event_id}.enc.json"


def _validate_digest_text(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_DIGEST.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class EventIdentity:
    """Immutable operation and event identity derived from one event attempt."""

    operation_nonce: str
    idempotency_key: str
    operation_sha256: str
    event_id: str
    path: str

    def __post_init__(self) -> None:
        try:
            base64url_decode(
                self.operation_nonce,
                expected_length=OPERATION_NONCE_BYTES,
                label="operation_nonce",
            )
            base64url_decode(
                self.idempotency_key,
                expected_length=SHA256_BYTES,
                label="idempotency_key",
            )
        except (Base64UrlError, TypeError):
            _fail("identity contains a non-canonical base64url value")
        _validate_digest_text(self.operation_sha256, "operation_sha256")
        try:
            base64url_decode(self.event_id, expected_length=EVENT_ID_BYTES, label="event_id")
        except (Base64UrlError, TypeError):
            _fail("identity contains an invalid event_id")
        if self.path != event_path(self.event_id):
            _fail("identity path does not match event_id")

    @property
    def event_path(self) -> str:
        """Alias using the public function's terminology."""

        return self.path


def derive_event_identity(
    project_id: str,
    operation_nonce: str,
    actor: Mapping[str, Any],
    event_type: str,
    target: dict[str, Any],
    payload: dict[str, Any],
    confirmed_canonical_oid: str | None,
) -> EventIdentity:
    """Derive idempotency key, operation fingerprint, event ID, and path."""

    _non_empty_string(project_id, "project_id")
    try:
        base64url_decode(
            operation_nonce,
            expected_length=OPERATION_NONCE_BYTES,
            label="operation_nonce",
        )
    except (Base64UrlError, TypeError):
        _fail("operation_nonce must be canonical base64url for 16 bytes")
    actor_identity = stable_actor_identity(actor)
    _token(event_type, "event_type")
    if event_type not in _EVENT_TYPES:
        _fail("event_type is not in the closed v1 vocabulary")
    _object(target, "target")
    _object(payload, "payload")
    if confirmed_canonical_oid is not None:
        _git_oid(confirmed_canonical_oid, "confirmed_canonical_oid")

    idempotency_digest = hashlib.sha256(
        b"dracla-idempotency-v1\0"
        + canonical_json({"project_id": project_id, "operation_nonce": operation_nonce})
    ).digest()
    operation_digest = hashlib.sha256(
        b"dracla-operation-v1\0"
        + canonical_json(
            {
                "project_id": project_id,
                "actor_identity": actor_identity,
                "type": event_type,
                "target": target,
                "payload": payload,
                "confirmed_canonical_oid": confirmed_canonical_oid,
            }
        )
    ).digest()
    event_digest = hashlib.sha256(b"dracla-event-v1\0" + idempotency_digest).digest()
    idempotency_key = base64url_encode(idempotency_digest)
    event_id = base64url_encode(event_digest)
    return EventIdentity(
        operation_nonce=operation_nonce,
        idempotency_key=idempotency_key,
        operation_sha256="sha256:" + operation_digest.hex(),
        event_id=event_id,
        path=event_path(event_id),
    )


def _authorization_object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("authorization member must be an object", authorization=True)
    return value


@dataclass(frozen=True, slots=True)
class AuthorizationEvidence:
    """One immutable, action-time GitHub authorization observation."""

    operation: str
    resource_kind: str
    resource_id: int
    required_authority: str
    observed_authority: str
    authorized: bool
    checked_at: str
    github_request_id: str | None

    def __post_init__(self) -> None:
        if type(self.operation) is not str or self.operation not in _OPERATION_PAIRS:
            _fail("authorization operation is not in the closed vocabulary", authorization=True)
        expected_kind, expected_authority = _OPERATION_PAIRS[self.operation]
        if (
            type(self.resource_kind) is not str
            or type(self.required_authority) is not str
            or self.resource_kind != expected_kind
            or self.required_authority != expected_authority
        ):
            _fail("authorization operation and authority do not pair", authorization=True)
        _positive_id(self.resource_id, "resource_id", authorization=True)
        if type(self.observed_authority) is not str or not self.observed_authority:
            _fail("observed_authority must be non-empty", authorization=True)
        if self.authorized is not True:
            _fail("authorization result must be true", authorization=True)
        _validate_timestamp(self.checked_at, authorization=True)
        if self.github_request_id is not None and (
            type(self.github_request_id) is not str or not self.github_request_id
        ):
            _fail("github_request_id must be non-empty or null", authorization=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "resource_kind": self.resource_kind,
            "resource_id": self.resource_id,
            "required_authority": self.required_authority,
            "observed_authority": self.observed_authority,
            "authorized": self.authorized,
            "checked_at": self.checked_at,
            "github_request_id": self.github_request_id,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


def _coerce_authorization(value: Any) -> AuthorizationEvidence:
    if isinstance(value, AuthorizationEvidence):
        return value
    obj = _authorization_object(value)
    expected = {
        "operation",
        "resource_kind",
        "resource_id",
        "required_authority",
        "observed_authority",
        "authorized",
        "checked_at",
        "github_request_id",
    }
    if set(obj) != expected:
        _fail("authorization member has missing or extra fields", authorization=True)
    return AuthorizationEvidence(**obj)


def _prepare_authorizations(authorizations: Sequence[Any]) -> tuple[AuthorizationEvidence, ...]:
    if isinstance(authorizations, (str, bytes, bytearray)) or not isinstance(
        authorizations, Sequence
    ):
        _fail("authorizations must be an ordered sequence", authorization=True)
    values = tuple(_coerce_authorization(item) for item in authorizations)
    identities = tuple((item.operation, item.resource_kind, item.resource_id) for item in values)
    if len(set(identities)) != len(identities):
        _fail("authorization evidence contains a duplicate identity", authorization=True)
    encoded = tuple(item.canonical_bytes for item in values)
    if encoded != tuple(sorted(encoded)):
        _fail("authorization evidence is not in JCS lexical order", authorization=True)
    return values


def _affected_repository_ids(value: Sequence[int] | None) -> tuple[int, ...]:
    if value is None:
        _fail("keyring activation requires affected repository IDs", authorization=True)
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail("affected repository IDs must be an ordered sequence", authorization=True)
    values = tuple(value)
    if not values:
        _fail("affected repository IDs must be non-empty", authorization=True)
    for resource_id in values:
        _positive_id(resource_id, "affected repository ID", authorization=True)
    if len(set(values)) != len(values):
        _fail("affected repository IDs must be unique", authorization=True)
    return values


def _actor_kind(actor: Mapping[str, Any], kind: str) -> None:
    identity = stable_actor_identity(actor)
    if identity["kind"] != kind:
        _fail("actor kind is not valid for this event", authorization=True)


def _target_id(target: dict[str, Any], key: str) -> int | None:
    value = target.get(key)
    return value if type(value) is int and 0 < value <= MAX_SAFE_INTEGER else None


def _check_single_row(
    values: tuple[AuthorizationEvidence, ...],
    row: tuple[str, str, str],
    *,
    resource_id: int | None = None,
) -> None:
    if len(values) != 1:
        _fail("event requires exactly one authorization row", authorization=True)
    item = values[0]
    operation, kind, authority = row
    if (item.operation, item.resource_kind, item.required_authority) != row:
        _fail("authorization row does not match event action", authorization=True)
    if resource_id is not None and item.resource_id != resource_id:
        _fail("authorization resource does not match event target", authorization=True)


def _connection_rows(
    event_type: str,
    target: dict[str, Any],
    payload: dict[str, Any],
    values: tuple[AuthorizationEvidence, ...],
) -> None:
    rows = tuple(row for row in AUTHORIZATION_TABLE if row[0] == event_type)
    if len(values) != 7:
        _fail("project connection requires exactly seven authorization rows", authorization=True)
    by_operation = {item.operation: item for item in values}
    if set(by_operation) != {row[1] for row in rows}:
        _fail("project connection authorization rows are incomplete", authorization=True)

    owner_key = "new_repository_owner" if event_type == "project_repository_owner_changed" else "repository_owner"
    owner = payload.get(owner_key)
    if type(owner) is not dict:
        _fail("project connection payload has no repository owner", authorization=True)
    owner_id = _positive_id(owner.get("github_account_id"), "repository owner", authorization=True)
    owner_operation = (
        "project_repository_owner_change_owner"
        if event_type == "project_repository_owner_changed"
        else "project_connect_owner"
    )
    if by_operation[owner_operation].resource_id != owner_id:
        _fail("owner authorization resource does not match payload", authorization=True)

    repository_ids = payload.get("repository_ids")
    if type(repository_ids) is not dict:
        _fail("project connection payload has no repository IDs", authorization=True)
    repo_ops = (
        (
            "project_repository_owner_change_records_repository",
            "records",
        ),
        (
            "project_repository_owner_change_coverage_repository",
            "coverage",
        ),
        (
            "project_repository_owner_change_control_repository",
            "control",
        ),
    ) if event_type == "project_repository_owner_changed" else (
        ("project_connect_records_repository", "records"),
        ("project_connect_coverage_repository", "coverage"),
        ("project_connect_control_repository", "control"),
    )
    repository_values = []
    for operation, key in repo_ops:
        repository_values.append(
            by_operation[operation].resource_id
        )
        expected = _positive_id(repository_ids.get(key), f"repository_ids.{key}", authorization=True)
        if by_operation[operation].resource_id != expected:
            _fail("repository authorization resource does not match payload", authorization=True)
    if len(set(repository_values)) != 3:
        _fail("project repository IDs must be distinct", authorization=True)

    app_ops = (
        (
            "project_repository_owner_change_records_app",
            "project_repository_owner_change_enforcer_app",
            "project_repository_owner_change_trigger_app",
        ) if event_type == "project_repository_owner_changed" else (
            "project_connect_records_app",
            "project_connect_enforcer_app",
            "project_connect_trigger_app",
        )
    )
    app_ids = [by_operation[operation].resource_id for operation in app_ops]
    if len(set(app_ids)) != 3:
        _fail("bound App installation IDs must be distinct", authorization=True)


def _scope_set(value: Any, label: str) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, (list, tuple)):
        _fail(f"{label} must be an ordered scope set", authorization=True)
    selectors: list[tuple[str, int, bytes]] = []
    for selector in value:
        if type(selector) is not dict:
            _fail("scope selector must be an object", authorization=True)
        kind = selector.get("kind")
        if kind == "repository":
            expected = {"kind", "repository_id", "owner_snapshot", "name_snapshot"}
            if set(selector) != expected:
                _fail("repository scope selector is malformed", authorization=True)
            resource_id = _positive_id(selector.get("repository_id"), "repository scope ID", authorization=True)
        elif kind == "organization":
            expected = {"kind", "organization_id", "login_snapshot"}
            if set(selector) != expected:
                _fail("organization scope selector is malformed", authorization=True)
            resource_id = _positive_id(selector.get("organization_id"), "organization scope ID", authorization=True)
        else:
            _fail("scope selector kind is unsupported", authorization=True)
        for key, item in selector.items():
            if key != "kind" and key.endswith("snapshot") and (type(item) is not str or not item):
                _fail("scope selector snapshot is malformed", authorization=True)
        encoded = canonical_json(selector)
        selectors.append((kind, resource_id, encoded))
    if len({(kind, resource_id) for kind, resource_id, _encoded in selectors}) != len(selectors):
        _fail("scope set contains duplicate identities", authorization=True)
    encoded = tuple(item[2] for item in selectors)
    if encoded != tuple(sorted(encoded)):
        _fail("scope set is not in JCS lexical order", authorization=True)
    return tuple((kind, resource_id) for kind, resource_id, _encoded in selectors)


def _scope_expected(
    event_type: str,
    target: dict[str, Any],
    payload: dict[str, Any],
    values: tuple[AuthorizationEvidence, ...],
) -> None:
    if len(values) != 1:
        _fail("scope event requires one authorization row", authorization=True)
    item = values[0]
    if item.operation not in _SCOPE_OPERATIONS:
        _fail("scope authorization operation is not a scope action", authorization=True)
    kind, authority, action = _SCOPE_OPERATIONS[item.operation]
    prior_value = payload.get("prior_scope")
    desired_value = payload.get("desired_scope")
    prior = _scope_set(prior_value, "prior_scope") if prior_value is not None else None
    desired = _scope_set(desired_value, "desired_scope") if desired_value is not None else None
    if event_type == "enforcement_scope_requested":
        if prior is None or desired is None:
            _fail("scope request must include prior and desired scope", authorization=True)
        prior_set, desired_set = set(prior), set(desired)
        added = desired_set - prior_set
        removed = prior_set - desired_set
        expected_action: str | None = None
        selected: tuple[str, int] | None = None
        if not prior_set and len(added) == len(desired_set) and desired_set:
            expected_action = "bind"
            if len(added) == 1:
                selected = next(iter(added))
        elif len(added) == 1 and not removed:
            expected_action, selected = "widen", next(iter(added))
        elif not desired_set and len(removed) == 1:
            expected_action, selected = "remove", next(iter(removed))
        elif len(removed) == 1 and not added:
            expected_action, selected = "narrow", next(iter(removed))
        if expected_action is None:
            _fail("scope request is not one exact bind/widen/narrow/remove action", authorization=True)
        if expected_action == "bind" and selected is None:
            # A complete empty-to-multiple scope is still a bind, but one
            # authorization row cannot identify multiple GitHub resources.
            _fail("scope bind must identify one resource", authorization=True)
        if action != expected_action or selected is None or (kind, item.resource_id) != selected:
            _fail("scope authorization does not match the requested transition", authorization=True)
        return
    if event_type == "enforcement_scope_activated" and desired is not None:
        # Activation repeats the request's desired set.  Its exact operation
        # and resource identity are carried by the authorization row; ensure
        # the named resource remains in that set without dereferencing history.
        if (kind, item.resource_id) not in set(desired):
            _fail("scope activation resource is absent from desired scope", authorization=True)
    if event_type == "enforcement_scope_abandoned":
        # Abandonment has no scope payload; the repeated operation/resource
        # identity is checked by replay when the request is available.
        return
    if event_type == "enforcement_scope_activated" and desired is None:
        _fail("scope activation must include desired scope", authorization=True)
def validate_authorizations(
    event_type: str,
    target: dict[str, Any],
    payload: dict[str, Any],
    actor: Mapping[str, Any],
    authorizations: Sequence[Any],
    *,
    affected_repository_ids: Sequence[int] | None = None,
) -> tuple[AuthorizationEvidence, ...]:
    """Validate and return canonical-order authorization evidence.

    The function checks action-specific relation rules that are decidable from
    the supplied event.  Key activation receives its affected repository set
    explicitly; history-dependent checks (for example, whether a scope
    terminal repeats the request's exact desired set) remain in replay.
    """

    if type(event_type) is not str or event_type not in _EVENT_TYPES:
        _fail("event type is not in the closed v1 vocabulary", authorization=True)
    _object(target, "target", authorization=True)
    _object(payload, "payload", authorization=True)
    if event_type != "keyring_activated" and affected_repository_ids is not None:
        _fail("affected repository IDs are only valid for keyring activation", authorization=True)
    if event_type in _NO_AUTH_EVENTS:
        required_kind = "automation" if event_type.endswith("materialized") else "github"
        _actor_kind(actor, required_kind)
        if authorizations not in ([], ()):
            _fail("event requires an empty authorization set", authorization=True)
        return ()
    _actor_kind(actor, "github")
    values = _prepare_authorizations(authorizations)
    if not values:
        _fail("event requires authorization evidence", authorization=True)
    if event_type in {"project_connected", "project_repository_owner_changed"}:
        _connection_rows(event_type, target, payload, values)
        return values
    if event_type in _SCOPE_EVENTS:
        _scope_expected(event_type, target, payload, values)
        return values
    if event_type == "keyring_activated":
        expected_repository_ids = _affected_repository_ids(affected_repository_ids)
        for item in values:
            if (item.operation, item.resource_kind, item.required_authority) != (
                "keyring_activate",
                "repository",
                "project_repository_admin",
            ):
                _fail("keyring activation authorization row is invalid", authorization=True)
        evidence_repository_ids = tuple(item.resource_id for item in values)
        if set(evidence_repository_ids) != set(expected_repository_ids) or len(evidence_repository_ids) != len(expected_repository_ids):
            _fail("keyring activation repositories do not match affected repository IDs", authorization=True)
        return values
    if event_type == "exemption":
        source_kind = payload.get("source_kind")
        operation = "exemption_bot_add" if source_kind == "bot" else "exemption_individual_add" if source_kind == "individual" else None
        if operation is None:
            _fail("exemption source kind is unsupported", authorization=True)
        _check_single_row(values, (operation, "repository", "records_repository_admin"))
        return values
    row = _FIXED_EVENT_ROWS[event_type]
    resource_id = None
    if event_type in {"override", "retry_requested"}:
        resource_id = _target_id(target, "repository_id")
        if resource_id is None:
            _fail("event target has no repository identity", authorization=True)
    _check_single_row(values, row, resource_id=resource_id)
    return values


__all__ = [
    "AUTHORIZATION_TABLE",
    "AuthorizationError",
    "AuthorizationEvidence",
    "AuthorizationValidationError",
    "EVENT_ID_BYTES",
    "EventIdentity",
    "EventIdentityError",
    "OPERATION_NONCE_BYTES",
    "derive_automation_nonce",
    "derive_event_identity",
    "derive_github_retry_nonce",
    "derive_scope_terminal_nonce",
    "event_path",
    "new_operation_nonce",
    "stable_actor_identity",
    "validate_authorizations",
]
