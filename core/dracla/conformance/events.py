"""Closed revision-14 event models and precondition declaration helpers.

This module is deliberately a local boundary.  It validates complete events,
recomputes their byte-level identity, and declares the history relations that
must be resolved before preparation.  It never fetches repositories,
decrypts artifacts, or folds events.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from .artifacts import segment
from .canonical import MAX_SAFE_INTEGER, canonical_json, parse_canonical_json
from .encoding import Base64UrlError, base64url_decode, base64url_encode
from .event_identity import (
    AuthorizationEvidence,
    EventIdentity,
    EventIdentityError,
    derive_event_identity,
    derive_automation_nonce,
    derive_github_retry_nonce,
    derive_scope_terminal_nonce,
    event_path,
    stable_actor_identity,
    validate_authorizations,
)


class EventValidationError(ValueError):
    """An event is not a closed, semantically valid v1 event."""


class PreconditionValidationError(EventValidationError):
    """A precondition declaration is malformed or cannot be bound."""


EVENT_TYPES = frozenset(
    {
        "acceptance",
        "revocation",
        "agreement_published",
        "agreement_activated",
        "agreement_activation_restored",
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

_AUTOMATION_TYPES = frozenset({"exemption_materialized", "records_reader_materialized"})
_NO_AUTH_TYPES = frozenset({"acceptance", "revocation", *_AUTOMATION_TYPES})
_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ASCII_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PROJECT_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:?[0-9]{2}:[0-9]{2}Z\Z")
_EVENT_FIELDS = {
    "acceptance": (
        ("coverage_tuple", "recipient", "version", "digest"),
        ("fields", "confirmations", "supersedes"),
    ),
    "revocation": (("coverage_tuple",), ("effect",)),
    "agreement_published": (
        ("agreement_id", "version"),
        (
            "recipient",
            "ref",
            "content_commit_oid",
            "digest",
            "snapshot_content_path",
            "snapshot_metadata_path",
            "snapshot_sha256",
        ),
    ),
    "agreement_activated": (
        ("agreement_id", "version"),
        ("published_event_id", "supersedes_coverage", "accepted_versions"),
    ),
    "agreement_activation_restored": (
        ("agreement_id", "activation_event_id"),
        ("accepted_versions", "reason"),
    ),
    "project_connected": (
        (),
        (
            "recipient",
            "repository_owner",
            "project_slug",
            "repository_ids",
            "bootstrap",
            "project_configuration",
            "successor_of",
        ),
    ),
    "project_repository_owner_changed": (
        ("prior_repository_owner",),
        ("new_repository_owner", "project_slug", "repository_ids", "registry_commit_oid", "registry_generation"),
    ),
    "project_succeeded": (("successor_project_id",), ("successor_connected_event_id",)),
    "config_updated": ((), ("project_configuration",)),
    "keyring_activated": ((), ("generation", "keys_commit_oid", "current_kids")),
    "enforcement_scope_requested": (("change_id",), ("prior_scope", "desired_scope", "prior_registry_generation")),
    "enforcement_scope_activated": (("change_id",), ("request_event_id", "desired_scope", "registry_commit_oid", "registry_generation")),
    "enforcement_scope_abandoned": (("change_id",), ("request_event_id", "reason_code")),
    "override": (("repository_id", "pull_request_number", "tree_oid"), ("subjects", "reason", "instrument_ref")),
    "override_withdrawn": (("override_event_id",), ("reason", "instrument_ref")),
    "retry_requested": (("repository_id", "check_kind", "check_identity"), ("github_delivery_id",)),
    "exemption": (("subject",), ("source_kind", "basis", "instrument_ref")),
    "exemption_snapshot": (("subjects",), ("team", "basis", "instrument_ref")),
    "exemption_source_withdrawn": (("source_event_id", "subject"), ()),
    "exemption_rule_configured": (("team",), ("basis", "instrument_ref")),
    "exemption_rule_withdrawn": (("rule_event_id",), ()),
    "exemption_materialized": (
        ("rule_event_id", "subject"),
        ("result", "team", "membership_evidence", "prior_materialization_event_id"),
    ),
    "records_reader_authorized": (("subject",), ()),
    "records_reader_snapshot_authorized": (("subjects",), ("team",)),
    "records_reader_withdrawn": (("source_event_id", "subject"), ()),
    "records_reader_rule_configured": (("team",), ()),
    "records_reader_rule_withdrawn": (("rule_event_id",), ()),
    "records_reader_materialized": (
        ("rule_event_id", "subject"),
        ("result", "team", "membership_evidence", "prior_materialization_event_id"),
    ),
}


def _error(message: str, error_type: type[EventValidationError] = EventValidationError) -> None:
    raise error_type(message)


def _exact_object(value: Any, keys: Sequence[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        _error(f"{label} has missing or extra fields")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _error(f"{label} must be an object")
    try:
        canonical_json(value)
    except (TypeError, ValueError, RecursionError):
        _error(f"{label} is not a JSON data-model object")
    return value


def _string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        _error(f"{label} must be a non-empty string")
    return value


def _ascii_token(value: Any, label: str) -> str:
    value = _string(value, label)
    if not value.isascii() or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        _error(f"{label} must be a printable ASCII token")
    return value


def _positive(value: Any, label: str) -> int:
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        _error(f"{label} must be a positive safe integer")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        _error(f"{label} must be a non-negative safe integer")
    return value


def _oid(value: Any, label: str) -> str:
    if type(value) is not str or _GIT_OID.fullmatch(value) is None:
        _error(f"{label} must be a lowercase Git object ID")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _error(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        _error(f"{label} must be a UTC whole-second timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _error(f"{label} must be a valid UTC timestamp")
    return value


def _event_id(value: Any, label: str) -> str:
    if type(value) is not str:
        _error(f"{label} must be an event ID")
    try:
        base64url_decode(value, expected_length=32, label=label)
    except (Base64UrlError, TypeError):
        _error(f"{label} must be canonical base64url for 32 bytes")
    return value


def _binding_field(validator: Any, value: Any, label: str) -> Any:
    """Apply a closed event validator at the exported binding boundary."""

    try:
        return validator(value, label)
    except EventValidationError as error:
        _error(str(error), PreconditionValidationError)


def _url(value: Any, label: str) -> str:
    value = _string(value, label)
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in value) or "\\" in value:
        _error(f"{label} must be an absolute HTTPS URL")
    if any(value[index] == "%" and (index + 2 >= len(value) or any(digit not in "0123456789abcdefABCDEF" for digit in value[index + 1:index + 3])) for index in range(len(value))):
        _error(f"{label} must be an absolute HTTPS URL")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        _error(f"{label} must be an absolute HTTPS URL")
    if parts.scheme != "https" or not parts.netloc or not hostname or parts.username or parts.password or parts.netloc.endswith(":"):
        _error(f"{label} must be an absolute HTTPS URL")
    return value


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class CoverageTuple:
    github_user_id: int
    project_id: str
    agreement_id: str
    recipient_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"github_user_id": self.github_user_id, "project_id": self.project_id, "agreement_id": self.agreement_id, "recipient_id": self.recipient_id}


@dataclass(frozen=True, slots=True)
class Recipient:
    recipient_id: str
    legal_name: str

    def to_dict(self) -> dict[str, Any]:
        return {"recipient_id": self.recipient_id, "legal_name": self.legal_name}


@dataclass(frozen=True, slots=True)
class RepositoryOwner:
    github_account_id: int
    login_snapshot: str

    def to_dict(self) -> dict[str, Any]:
        return {"github_account_id": self.github_account_id, "login_snapshot": self.login_snapshot}


@dataclass(frozen=True, slots=True)
class Subject:
    github_user_id: int
    login_snapshot: str

    def to_dict(self) -> dict[str, Any]:
        return {"github_user_id": self.github_user_id, "login_snapshot": self.login_snapshot}


@dataclass(frozen=True, slots=True)
class Team:
    organization_id: int
    team_id: int
    slug_snapshot: str

    def to_dict(self) -> dict[str, Any]:
        return {"organization_id": self.organization_id, "team_id": self.team_id, "slug_snapshot": self.slug_snapshot}


@dataclass(frozen=True, slots=True)
class MembershipEvidence:
    organization_id: int
    team_id: int
    github_user_id: int
    state: str
    checked_at: str
    etag: str | None
    github_request_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"organization_id": self.organization_id, "team_id": self.team_id, "github_user_id": self.github_user_id, "state": self.state, "checked_at": self.checked_at, "etag": self.etag, "github_request_id": self.github_request_id}


@dataclass(frozen=True, slots=True)
class RepositoryIds:
    records: int
    coverage: int
    control: int

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records, "coverage": self.coverage, "control": self.control}


@dataclass(frozen=True, slots=True)
class CurrentKids:
    records: str
    coverage: str

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records, "coverage": self.coverage}


@dataclass(frozen=True, slots=True)
class Bootstrap:
    install_generation: str
    manifest_commit_oid: str
    manifest_sha256: str
    records_keyring_candidate_oid: str
    repository_ids: RepositoryIds
    current_kids: CurrentKids

    def to_dict(self) -> dict[str, Any]:
        return {"install_generation": self.install_generation, "manifest_commit_oid": self.manifest_commit_oid, "manifest_sha256": self.manifest_sha256, "records_keyring_candidate_oid": self.records_keyring_candidate_oid, "repository_ids": self.repository_ids.to_dict(), "current_kids": self.current_kids.to_dict()}


@dataclass(frozen=True, slots=True)
class ConfigurationField:
    name: str
    label: str
    kind: str
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "label": self.label, "kind": self.kind, "required": self.required}


@dataclass(frozen=True, slots=True)
class ProjectConfiguration:
    privacy_policy_url: str
    retention_statement: str
    correction_procedure: str
    required_fields: tuple[ConfigurationField, ...]
    confirmation_labels: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"privacy_policy_url": self.privacy_policy_url, "retention_statement": self.retention_statement, "correction_procedure": self.correction_procedure, "required_fields": [item.to_dict() for item in self.required_fields], "confirmation_labels": list(self.confirmation_labels)}


@dataclass(frozen=True, slots=True)
class ScopeSelector:
    kind: str
    resource_id: int
    snapshot: str
    name_snapshot: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.kind == "repository":
            return {"kind": self.kind, "repository_id": self.resource_id, "owner_snapshot": self.snapshot, "name_snapshot": self.name_snapshot}
        return {"kind": self.kind, "organization_id": self.resource_id, "login_snapshot": self.snapshot}


def _parse_coverage(value: Any) -> CoverageTuple:
    obj = _exact_object(value, ("github_user_id", "project_id", "agreement_id", "recipient_id"), "coverage_tuple")
    return CoverageTuple(_positive(obj["github_user_id"], "coverage_tuple.github_user_id"), _string(obj["project_id"], "coverage_tuple.project_id"), _string(obj["agreement_id"], "coverage_tuple.agreement_id"), _string(obj["recipient_id"], "coverage_tuple.recipient_id"))


def _parse_recipient(value: Any) -> Recipient:
    obj = _exact_object(value, ("recipient_id", "legal_name"), "recipient")
    return Recipient(_string(obj["recipient_id"], "recipient.recipient_id"), _string(obj["legal_name"], "recipient.legal_name"))


def _parse_owner(value: Any, label: str = "repository_owner") -> RepositoryOwner:
    obj = _exact_object(value, ("github_account_id", "login_snapshot"), label)
    return RepositoryOwner(_positive(obj["github_account_id"], f"{label}.github_account_id"), _string(obj["login_snapshot"], f"{label}.login_snapshot"))


def _parse_subject(value: Any, label: str = "subject") -> Subject:
    obj = _exact_object(value, ("github_user_id", "login_snapshot"), label)
    return Subject(_positive(obj["github_user_id"], f"{label}.github_user_id"), _string(obj["login_snapshot"], f"{label}.login_snapshot"))


def _parse_team(value: Any) -> Team:
    obj = _exact_object(value, ("organization_id", "team_id", "slug_snapshot"), "team")
    return Team(_positive(obj["organization_id"], "team.organization_id"), _positive(obj["team_id"], "team.team_id"), _string(obj["slug_snapshot"], "team.slug_snapshot"))


def _parse_membership(value: Any) -> MembershipEvidence:
    obj = _exact_object(value, ("organization_id", "team_id", "github_user_id", "state", "checked_at", "etag", "github_request_id"), "membership_evidence")
    for key in ("etag", "github_request_id"):
        if obj[key] is not None and (type(obj[key]) is not str or not obj[key]):
            _error(f"membership_evidence.{key} must be a non-empty string or null")
    state = obj["state"]
    if state not in {"member", "not_member"}:
        _error("membership_evidence.state is unsupported")
    return MembershipEvidence(_positive(obj["organization_id"], "membership_evidence.organization_id"), _positive(obj["team_id"], "membership_evidence.team_id"), _positive(obj["github_user_id"], "membership_evidence.github_user_id"), state, _timestamp(obj["checked_at"], "membership_evidence.checked_at"), obj["etag"], obj["github_request_id"])


def _parse_repo_ids(value: Any, label: str = "repository_ids") -> RepositoryIds:
    obj = _exact_object(value, ("records", "coverage", "control"), label)
    result = RepositoryIds(*(_positive(obj[key], f"{label}.{key}") for key in ("records", "coverage", "control")))
    if len({result.records, result.coverage, result.control}) != 3:
        _error(f"{label} repository IDs must be distinct")
    return result


def _parse_kids(value: Any) -> CurrentKids:
    obj = _exact_object(value, ("records", "coverage"), "current_kids")
    return CurrentKids(_string(obj["records"], "current_kids.records"), _string(obj["coverage"], "current_kids.coverage"))


def _parse_string_set(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is not list or not value:
        _error(f"{label} must be a non-empty ordered string set")
    result = tuple(_string(item, f"{label} member") for item in value)
    if len(set(result)) != len(result):
        _error(f"{label} contains duplicate values")
    encoded = tuple(canonical_json(item) for item in result)
    if encoded != tuple(sorted(encoded)):
        _error(f"{label} is not in JCS lexical order")
    return result


def _parse_bootstrap(value: Any) -> Bootstrap:
    obj = _exact_object(value, ("install_generation", "manifest_commit_oid", "manifest_sha256", "records_keyring_candidate_oid", "repository_ids", "current_kids"), "bootstrap")
    return Bootstrap(_string(obj["install_generation"], "bootstrap.install_generation"), _oid(obj["manifest_commit_oid"], "bootstrap.manifest_commit_oid"), _digest(obj["manifest_sha256"], "bootstrap.manifest_sha256"), _oid(obj["records_keyring_candidate_oid"], "bootstrap.records_keyring_candidate_oid"), _parse_repo_ids(obj["repository_ids"], "bootstrap.repository_ids"), _parse_kids(obj["current_kids"]))


def _parse_configuration(value: Any) -> ProjectConfiguration:
    obj = _exact_object(value, ("privacy_policy_url", "retention_statement", "correction_procedure", "required_fields", "confirmation_labels"), "project_configuration")
    fields = obj["required_fields"]
    labels = obj["confirmation_labels"]
    if type(fields) is not list:
        _error("project_configuration.required_fields must be an array")
    if type(labels) is not list:
        _error("project_configuration.confirmation_labels must be an array")
    parsed_fields: list[ConfigurationField] = []
    for item in fields:
        field = _exact_object(item, ("name", "label", "kind", "required"), "configuration field")
        name = field["name"]
        if type(name) is not str or not name.isascii() or _ASCII_IDENTIFIER.fullmatch(name) is None:
            _error("configuration field name is not a safe ASCII identifier")
        kind = field["kind"]
        if kind not in {"text", "email"} or field["required"] is not True:
            _error("configuration field kind or required flag is invalid")
        parsed_fields.append(ConfigurationField(name, _string(field["label"], "configuration field.label"), kind))
    if len({field.name for field in parsed_fields}) != len(parsed_fields):
        _error("configuration field names must be unique")
    parsed_labels = tuple(_string(label, "confirmation label") for label in labels)
    if len(set(parsed_labels)) != len(parsed_labels):
        _error("confirmation labels must be unique")
    return ProjectConfiguration(_url(obj["privacy_policy_url"], "privacy_policy_url"), _string(obj["retention_statement"], "retention_statement"), _string(obj["correction_procedure"], "correction_procedure"), tuple(parsed_fields), parsed_labels)


def _parse_scope(value: Any, label: str) -> tuple[ScopeSelector, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _error(f"{label} must be an ordered scope set")
    result: list[ScopeSelector] = []
    encoded: list[bytes] = []
    identities: set[tuple[str, int]] = set()
    for item in value:
        if not isinstance(item, Mapping):
            _error("scope selector must be an object")
        kind = item.get("kind")
        if kind == "repository":
            obj = _exact_object(item, ("kind", "repository_id", "owner_snapshot", "name_snapshot"), "repository scope selector")
            selector = ScopeSelector(kind, _positive(obj["repository_id"], "repository scope ID"), _string(obj["owner_snapshot"], "owner_snapshot"), _string(obj["name_snapshot"], "name_snapshot"))
        elif kind == "organization":
            obj = _exact_object(item, ("kind", "organization_id", "login_snapshot"), "organization scope selector")
            selector = ScopeSelector(kind, _positive(obj["organization_id"], "organization scope ID"), _string(obj["login_snapshot"], "login_snapshot"))
        else:
            _error("scope selector kind is unsupported")
        identity = (selector.kind, selector.resource_id)
        if identity in identities:
            _error("scope set contains duplicate identities")
        identities.add(identity)
        result.append(selector)
        encoded.append(canonical_json(_thaw(item)))
    if tuple(encoded) != tuple(sorted(encoded)):
        _error(f"{label} is not in JCS lexical order")
    return tuple(result)


def _parse_subjects(value: Any, label: str) -> tuple[Subject, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence) or not value:
        _error(f"{label} must be a non-empty subject set")
    result = tuple(_parse_subject(item, f"{label} member") for item in value)
    if len({item.github_user_id for item in result}) != len(result):
        _error(f"{label} contains duplicate subjects")
    if tuple(canonical_json(_thaw(item)) for item in value) != tuple(sorted(canonical_json(_thaw(item)) for item in value)):
        _error(f"{label} is not in JCS lexical order")
    return result


def _parse_actor(value: Any, event_type: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        _error("actor must be an object")
    try:
        identity = stable_actor_identity(value)
    except (EventIdentityError, TypeError, ValueError):
        _error("actor is not a supported v1 actor")
    expected = "automation" if event_type in _AUTOMATION_TYPES else "github"
    if identity["kind"] != expected:
        _error("actor kind is not valid for this event")
    return _freeze(value)


def _parse_auth_structure(value: Any, event_type: str) -> tuple[AuthorizationEvidence, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _error("authorizations must be an ordered sequence")
    if event_type in _NO_AUTH_TYPES:
        if len(value) != 0:
            _error("event requires an empty authorization set")
        return ()
    if not value:
        _error("event requires authorization evidence")
    parsed: list[AuthorizationEvidence] = []
    for item in value:
        if isinstance(item, AuthorizationEvidence):
            parsed.append(item)
            continue
        if type(item) is not dict:
            _error("authorization member must be an object")
        try:
            parsed.append(AuthorizationEvidence(**item))
        except (EventIdentityError, TypeError, ValueError):
            _error("authorization member is malformed")
    identities = [(item.operation, item.resource_kind, item.resource_id) for item in parsed]
    if len(set(identities)) != len(identities):
        _error("authorization evidence contains a duplicate identity")
    encoded = tuple(item.canonical_bytes for item in parsed)
    if encoded != tuple(sorted(encoded)):
        _error("authorization evidence is not in JCS lexical order")
    if event_type == "keyring_activated":
        for item in parsed:
            if (item.operation, item.resource_kind, item.required_authority) != ("keyring_activate", "repository", "project_repository_admin"):
                _error("keyring authorization row is invalid")
    return tuple(parsed)


def _parse_target_payload(event_type: str, target: Any, payload: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    target_obj = _object(target, "target")
    payload_obj = _object(payload, "payload")
    target_keys, payload_keys = _EVENT_FIELDS[event_type]
    _exact_object(target_obj, target_keys, "target")
    _exact_object(payload_obj, payload_keys, "payload")

    if event_type == "acceptance":
        _parse_coverage(target_obj["coverage_tuple"])
        _parse_recipient(target_obj["recipient"])
        _string(target_obj["version"], "target.version")
        _digest(target_obj["digest"], "target.digest")
        fields = payload_obj["fields"]
        if type(fields) is not dict or any(type(key) is not str or not key for key in fields) or any(type(item) is not str for item in fields.values()):
            _error("acceptance fields must be a closed string map")
        confirmations = payload_obj["confirmations"]
        if type(confirmations) is not list:
            _error("acceptance confirmations must be an array")
        seen: set[str] = set()
        for item in confirmations:
            obj = _exact_object(item, ("label", "checked"), "confirmation")
            label = _string(obj["label"], "confirmation.label")
            if obj["checked"] is not True or label in seen:
                _error("acceptance confirmations are not affirmative and unique")
            seen.add(label)
        if payload_obj["supersedes"] is not None:
            _event_id(payload_obj["supersedes"], "acceptance.supersedes")
    elif event_type == "revocation":
        _parse_coverage(target_obj["coverage_tuple"])
        if payload_obj["effect"] != "cutoff_all_prior_versions":
            _error("revocation effect is not the closed v1 value")
    elif event_type == "agreement_published":
        agreement_id = _string(target_obj["agreement_id"], "target.agreement_id")
        version = _string(target_obj["version"], "target.version")
        _parse_recipient(payload_obj["recipient"])
        _string(payload_obj["ref"], "payload.ref")
        _oid(payload_obj["content_commit_oid"], "payload.content_commit_oid")
        _digest(payload_obj["digest"], "payload.digest")
        _digest(payload_obj["snapshot_sha256"], "payload.snapshot_sha256")
        content_path = f"agreements/{segment(agreement_id)}/{segment(version)}.md"
        metadata_path = content_path[:-3] + ".meta.json"
        if payload_obj["snapshot_content_path"] != content_path or payload_obj["snapshot_metadata_path"] != metadata_path:
            _error("agreement snapshot paths are not derived from agreement identity")
    elif event_type == "agreement_activated":
        _string(target_obj["agreement_id"], "target.agreement_id")
        _string(target_obj["version"], "target.version")
        _event_id(payload_obj["published_event_id"], "published_event_id")
        if type(payload_obj["supersedes_coverage"]) is not bool:
            _error("supersedes_coverage must be a boolean")
        _parse_string_set(payload_obj["accepted_versions"], "accepted_versions")
    elif event_type == "agreement_activation_restored":
        _string(target_obj["agreement_id"], "target.agreement_id")
        _event_id(target_obj["activation_event_id"], "target.activation_event_id")
        _parse_string_set(payload_obj["accepted_versions"], "accepted_versions")
        _string(payload_obj["reason"], "payload.reason")
    elif event_type == "project_connected":
        _parse_recipient(payload_obj["recipient"])
        _parse_owner(payload_obj["repository_owner"])
        slug = payload_obj["project_slug"]
        if type(slug) is not str or slug.isascii() is False or _PROJECT_SLUG.fullmatch(slug) is None:
            _error("project_slug is not a valid lowercase repository slug")
        _parse_repo_ids(payload_obj["repository_ids"])
        _parse_bootstrap(payload_obj["bootstrap"])
        _parse_configuration(payload_obj["project_configuration"])
        if payload_obj["successor_of"] is not None:
            _string(payload_obj["successor_of"], "successor_of")
    elif event_type == "project_repository_owner_changed":
        _parse_owner(target_obj["prior_repository_owner"], "prior_repository_owner")
        _parse_owner(payload_obj["new_repository_owner"], "new_repository_owner")
        slug = payload_obj["project_slug"]
        if type(slug) is not str or not slug.isascii() or _PROJECT_SLUG.fullmatch(slug) is None:
            _error("project_slug is not a valid lowercase repository slug")
        _parse_repo_ids(payload_obj["repository_ids"])
        _oid(payload_obj["registry_commit_oid"], "registry_commit_oid")
        _nonnegative(payload_obj["registry_generation"], "registry_generation")
    elif event_type == "project_succeeded":
        _string(target_obj["successor_project_id"], "successor_project_id")
        _event_id(payload_obj["successor_connected_event_id"], "successor_connected_event_id")
    elif event_type == "config_updated":
        _parse_configuration(payload_obj["project_configuration"])
    elif event_type == "keyring_activated":
        _positive(payload_obj["generation"], "generation")
        _oid(payload_obj["keys_commit_oid"], "keys_commit_oid")
        _parse_kids(payload_obj["current_kids"])
    elif event_type == "enforcement_scope_requested":
        _string(target_obj["change_id"], "change_id")
        _parse_scope(payload_obj["prior_scope"], "prior_scope")
        _parse_scope(payload_obj["desired_scope"], "desired_scope")
        _nonnegative(payload_obj["prior_registry_generation"], "prior_registry_generation")
    elif event_type == "enforcement_scope_activated":
        _string(target_obj["change_id"], "change_id")
        _event_id(payload_obj["request_event_id"], "request_event_id")
        _parse_scope(payload_obj["desired_scope"], "desired_scope")
        _oid(payload_obj["registry_commit_oid"], "registry_commit_oid")
        _nonnegative(payload_obj["registry_generation"], "registry_generation")
    elif event_type == "enforcement_scope_abandoned":
        _string(target_obj["change_id"], "change_id")
        _event_id(payload_obj["request_event_id"], "request_event_id")
        _string(payload_obj["reason_code"], "reason_code")
    elif event_type == "override":
        _positive(target_obj["repository_id"], "repository_id")
        _positive(target_obj["pull_request_number"], "pull_request_number")
        _oid(target_obj["tree_oid"], "tree_oid")
        _parse_subjects(payload_obj["subjects"], "override.subjects")
        _string(payload_obj["reason"], "override.reason")
        if payload_obj["instrument_ref"] is not None:
            _string(payload_obj["instrument_ref"], "override.instrument_ref")
    elif event_type == "override_withdrawn":
        _event_id(target_obj["override_event_id"], "override_event_id")
        _string(payload_obj["reason"], "override_withdrawn.reason")
        if payload_obj["instrument_ref"] is not None:
            _string(payload_obj["instrument_ref"], "override_withdrawn.instrument_ref")
    elif event_type == "retry_requested":
        _positive(target_obj["repository_id"], "repository_id")
        kind = target_obj["check_kind"]
        if kind not in {"pull_request", "merge_group"}:
            _error("check_kind is unsupported")
        if kind == "pull_request":
            _positive(target_obj["check_identity"], "check_identity")
        else:
            _oid(target_obj["check_identity"], "check_identity")
        if payload_obj["github_delivery_id"] is not None:
            _string(payload_obj["github_delivery_id"], "github_delivery_id")
    elif event_type == "exemption":
        _parse_subject(target_obj["subject"])
        source_kind = payload_obj["source_kind"]
        if source_kind not in {"bot", "individual"}:
            _error("exemption source_kind is unsupported")
        if source_kind == "bot":
            for key in ("basis", "instrument_ref"):
                if payload_obj[key] is not None:
                    _string(payload_obj[key], f"exemption.{key}")
        else:
            _string(payload_obj["basis"], "exemption.basis")
            _string(payload_obj["instrument_ref"], "exemption.instrument_ref")
    elif event_type == "exemption_snapshot":
        _parse_subjects(target_obj["subjects"], "exemption_snapshot.subjects")
        _parse_team(payload_obj["team"])
        _string(payload_obj["basis"], "exemption_snapshot.basis")
        _string(payload_obj["instrument_ref"], "exemption_snapshot.instrument_ref")
    elif event_type == "exemption_source_withdrawn":
        _event_id(target_obj["source_event_id"], "source_event_id")
        _parse_subject(target_obj["subject"])
    elif event_type == "exemption_rule_configured":
        _parse_team(target_obj["team"])
        _string(payload_obj["basis"], "exemption_rule_configured.basis")
        _string(payload_obj["instrument_ref"], "exemption_rule_configured.instrument_ref")
    elif event_type == "exemption_rule_withdrawn":
        _event_id(target_obj["rule_event_id"], "rule_event_id")
    elif event_type in {"exemption_materialized", "records_reader_materialized"}:
        _event_id(target_obj["rule_event_id"], "rule_event_id")
        subject = _parse_subject(target_obj["subject"])
        result = payload_obj["result"]
        if result not in {"add", "withdraw"}:
            _error("materialization result is unsupported")
        team = _parse_team(payload_obj["team"])
        membership = _parse_membership(payload_obj["membership_evidence"])
        if (membership.organization_id, membership.team_id, membership.github_user_id) != (team.organization_id, team.team_id, subject.github_user_id):
            _error("membership evidence does not match materialization target")
        if (result == "add") != (membership.state == "member"):
            _error("materialization result does not match membership state")
        if payload_obj["prior_materialization_event_id"] is not None:
            _event_id(payload_obj["prior_materialization_event_id"], "prior_materialization_event_id")
    elif event_type == "records_reader_authorized":
        _parse_subject(target_obj["subject"])
    elif event_type == "records_reader_snapshot_authorized":
        _parse_subjects(target_obj["subjects"], "records_reader_snapshot_authorized.subjects")
        _parse_team(payload_obj["team"])
    elif event_type == "records_reader_withdrawn":
        _event_id(target_obj["source_event_id"], "source_event_id")
        _parse_subject(target_obj["subject"])
    elif event_type == "records_reader_rule_configured":
        _parse_team(target_obj["team"])
    else:
        _event_id(target_obj["rule_event_id"], "rule_event_id")
    return _freeze(target_obj), _freeze(payload_obj)


@dataclass(frozen=True, slots=True)
class ValidatedEvent:
    """An immutable, semantically validated canonical event."""

    schema_version: int
    project_id: str
    event_id: str
    idempotency_key: str
    operation_nonce: str
    operation_sha256: str
    type: str
    recorded_at: str
    dracla_version: str
    actor: Mapping[str, Any]
    authorizations: tuple[AuthorizationEvidence, ...]
    confirmed_canonical_oid: str | None
    target: Mapping[str, Any]
    payload: Mapping[str, Any]
    identity: EventIdentity

    @property
    def event_path(self) -> str:
        return self.identity.path

    @property
    def path(self) -> str:
        return self.identity.path

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "event_id": self.event_id,
            "idempotency_key": self.idempotency_key,
            "operation_nonce": self.operation_nonce,
            "operation_sha256": self.operation_sha256,
            "type": self.type,
            "recorded_at": self.recorded_at,
            "dracla_version": self.dracla_version,
            "actor": _thaw(self.actor),
            "authorizations": [item.to_dict() for item in self.authorizations],
            "confirmed_canonical_oid": self.confirmed_canonical_oid,
            "target": _thaw(self.target),
            "payload": _thaw(self.payload),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class PreconditionRequirement:
    """A history-owned relation that must be resolved before preparation."""

    name: str
    artifact_kind: str
    repository_role: str
    branch: str
    path: str
    binding_mode: str
    relation: str
    expected_head: str


@dataclass(frozen=True, slots=True)
class EventsHeadBinding:
    """Evidence binding for a value read from the canonical events head."""

    events_head: str

    def __post_init__(self) -> None:
        _binding_field(_oid, self.events_head, "events head")

    @property
    def mode(self) -> str:
        return "events-head"


@dataclass(frozen=True, slots=True)
class GenerationBinding:
    """Evidence binding for a derived generation read at an events head."""

    events_head: str
    canonical_generation: str
    derived_generation: str

    def __post_init__(self) -> None:
        _binding_field(_oid, self.events_head, "generation events head")
        _binding_field(_event_id, self.canonical_generation, "canonical generation")
        _binding_field(_event_id, self.derived_generation, "derived generation")

    @property
    def mode(self) -> str:
        return "generation"


@dataclass(frozen=True, slots=True)
class CanonicalShaBinding:
    """Evidence binding for coverage state linked by source.canonical_sha."""

    coverage_commit_oid: str
    canonical_sha: str

    def __post_init__(self) -> None:
        _binding_field(_oid, self.coverage_commit_oid, "coverage commit")
        _binding_field(_oid, self.canonical_sha, "canonical sha")

    @property
    def mode(self) -> str:
        return "canonical-sha"


@dataclass(frozen=True, slots=True)
class CrossProjectBinding:
    """Evidence binding for a successor project's independently resolved state."""

    successor_project_id: str
    successor_events_head: str
    repository_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        _binding_field(_string, self.successor_project_id, "successor project ID")
        _binding_field(_oid, self.successor_events_head, "successor events head")
        if type(self.repository_ids) is not tuple or not self.repository_ids:
            _error("cross-project repository IDs are malformed", PreconditionValidationError)
        repository_ids = tuple(
            _binding_field(_positive, repository_id, "successor repository ID")
            for repository_id in self.repository_ids
        )
        if len(set(repository_ids)) != len(repository_ids):
            _error("cross-project repository IDs contain duplicates", PreconditionValidationError)

    @property
    def mode(self) -> str:
        return "cross-project"


@dataclass(frozen=True, slots=True)
class RegistryGenerationBinding:
    """Evidence binding for a signed-registry entry and generation."""

    registry_commit_oid: str
    registry_generation: int

    def __post_init__(self) -> None:
        _binding_field(_oid, self.registry_commit_oid, "registry commit")
        _binding_field(_nonnegative, self.registry_generation, "registry generation")

    @property
    def mode(self) -> str:
        return "registry-generation"


PreconditionBinding = (
    EventsHeadBinding
    | GenerationBinding
    | CanonicalShaBinding
    | CrossProjectBinding
    | RegistryGenerationBinding
)

_PRECONDITION_MATRIX: dict[str, tuple[str, ...]] = {
    "project_connected": ("generations-absence",),
    "acceptance": ("project-lifecycle", "active-agreement", "current-configuration", "prior-generations"),
    "revocation": ("project-lifecycle", "coverage-state", "prior-generations"),
    "agreement_published": ("project-lifecycle", "current-project-agreement", "publication-snapshot-absence", "publication-metadata-absence"),
    "agreement_activated": ("project-lifecycle", "published-agreement", "active-agreement"),
    "agreement_activation_restored": ("project-lifecycle", "target-activation", "active-agreement"),
    "project_repository_owner_changed": ("project-lifecycle", "current-repository-owner"),
    "project_succeeded": ("project-lifecycle", "successor-project"),
    "config_updated": ("project-lifecycle",),
    "keyring_activated": ("project-lifecycle", "keyring-affected-repositories"),
    "enforcement_scope_requested": ("project-lifecycle", "current-scope"),
    "enforcement_scope_activated": ("project-lifecycle", "current-scope", "scope-request", "scope-terminal-activation-absence", "scope-terminal-abandonment-absence"),
    "enforcement_scope_abandoned": ("project-lifecycle", "current-scope", "scope-request", "scope-terminal-activation-absence", "scope-terminal-abandonment-absence"),
    "override": ("project-lifecycle", "coverage-state"),
    "override_withdrawn": ("project-lifecycle", "override-grant"),
    "retry_requested": ("project-lifecycle",),
    "exemption": ("project-lifecycle", "current-exemption-union", "prior-generations"),
    "exemption_snapshot": ("project-lifecycle", "current-exemption-union", "prior-generations"),
    "exemption_source_withdrawn": ("project-lifecycle", "source-event", "current-exemption-union", "prior-generations"),
    "exemption_rule_configured": ("project-lifecycle", "current-derived-state", "prior-generations"),
    "exemption_rule_withdrawn": ("project-lifecycle", "rule-event", "current-exemption-union", "prior-generations"),
    "exemption_materialized": ("project-lifecycle", "rule-event", "active-exemption-rule-state", "current-exemption-union", "materialization-cursor", "prior-generations"),
    "records_reader_authorized": ("project-lifecycle", "current-reader-authority", "prior-generations"),
    "records_reader_snapshot_authorized": ("project-lifecycle", "current-reader-authority", "prior-generations"),
    "records_reader_withdrawn": ("project-lifecycle", "source-event", "reader-authority-state", "prior-generations"),
    "records_reader_rule_configured": ("project-lifecycle", "current-derived-state", "active-reader-rules", "prior-generations"),
    "records_reader_rule_withdrawn": ("project-lifecycle", "rule-event", "reader-authority-state", "prior-generations"),
    "records_reader_materialized": ("project-lifecycle", "rule-event", "current-reader-authority", "materialization-cursor", "prior-generations"),
}


def _event_name(event: Any) -> str:
    if not isinstance(event, ValidatedEvent):
        _error("event must be a ValidatedEvent")
    return event.type

def _requirement(
    name: str,
    *,
    kind: str,
    role: str,
    branch: str,
    path: str,
    binding: str,
    relation: str,
    expected_head: str,
) -> PreconditionRequirement:
    if binding not in {"events-head", "generation", "canonical-sha", "cross-project", "registry-generation"}:
        _error("precondition binding mode is not closed", PreconditionValidationError)
    return PreconditionRequirement(name, kind, role, branch, path, binding, relation, expected_head)


def _coverage_shard_path(user_id: int) -> str:
    return f"users/{user_id % 32:02d}.enc.json"

def _agreement_version_path(agreement_id: str, version: str, suffix: str) -> str:
    return f"agreements/{segment(agreement_id)}/{segment(version)}{suffix}"

def _reader_shard_path(source_event_id: str) -> str:
    """Return the reader shard selected by the first five digest bits."""

    shard = hashlib.sha256(source_event_id.encode("ascii")).digest()[0] >> 3
    return f"derived/reader-authority/{shard:02d}.enc.json"


def _scope_terminal_child_event_id(project_id: str, request_event_id: str, terminal_type: str) -> str:
    """Derive a terminal child ID without inventing its payload or actor.

    M1-4 defines the event ID as a function of the project and operation
    nonce.  The terminal nonce is itself request/type bound, so the sibling
    path is derivable even though its eventual event payload is not known at
    this validation boundary.
    """

    nonce = derive_scope_terminal_nonce(request_event_id, terminal_type)
    idempotency_digest = hashlib.sha256(
        b"dracla-idempotency-v1\0"
        + canonical_json({"project_id": project_id, "operation_nonce": nonce})
    ).digest()
    event_digest = hashlib.sha256(b"dracla-event-v1\0" + idempotency_digest).digest()
    return base64url_encode(event_digest)

def _scope_terminal_child_path(project_id: str, request_event_id: str, terminal_type: str) -> str:
    return event_path(_scope_terminal_child_event_id(project_id, request_event_id, terminal_type))


def _subject_shards(event: ValidatedEvent, *, relation: str) -> tuple[int, ...]:
    """Return every shard whose authenticated projection relation is needed."""

    if relation == "coverage-state":
        if event.type == "revocation":
            users = [event.target["coverage_tuple"]["github_user_id"]]
        else:
            users = [subject["github_user_id"] for subject in event.payload["subjects"]]
    elif relation == "current-exemption-union":
        if event.type == "exemption_rule_withdrawn":
            return tuple(range(32))
        if "subject" in event.target:
            users = [event.target["subject"]["github_user_id"]]
        else:
            users = [subject["github_user_id"] for subject in event.target["subjects"]]
    else:
        _error("unsupported subject-shard relation", PreconditionValidationError)
    return tuple(sorted({user_id % 32 for user_id in users}))


def _registry_entry_path(project_id: str) -> str:
    # Registry paths are owned by the separate signed registry namespace, not
    # the records/coverage artifact resolver.
    return f"projects/{segment(project_id)}.json"

def _validate_head(value: Any) -> str:
    return _oid(value, "expected_head")


def required_preconditions(event: ValidatedEvent, *, expected_head: str) -> tuple[PreconditionRequirement, ...]:
    """Describe all history-dependent relations needed before preparation."""

    expected_head = _validate_head(expected_head)
    event_type = _event_name(event)
    if event.confirmed_canonical_oid is not None and event.confirmed_canonical_oid != expected_head:
        _error("event confirmed head does not match expected head", PreconditionValidationError)
    source_id = event.target.get("source_event_id", event.target.get("rule_event_id", event.event_id))
    coverage_shards = _subject_shards(event, relation="coverage-state") if "coverage-state" in _PRECONDITION_MATRIX[event_type] else ()
    exemption_shards = _subject_shards(event, relation="current-exemption-union") if "current-exemption-union" in _PRECONDITION_MATRIX[event_type] else ()
    specs = {
        "project-lifecycle": ("coverage-source", "coverage", "coverage", "source.enc.json", "canonical-sha", "project-lifecycle-policy"),
        "active-agreement": ("active-agreement", "coverage", "coverage", "agreements/active.enc.json", "canonical-sha", "active-agreement-matches-target"),
        "current-configuration": ("project-config", "records", "events", "config/project.enc.json", "events-head", "acceptance-fields-and-confirmations-match-configuration"),
        "current-project-agreement": ("canonical-project-state", "records", "events", "", "events-head", "project-agreement-and-recipient-are-current"),
        "prior-generations": ("materialization-generations", "records", "events", "config/materialization-generations.enc.json", "events-head", "prior-generations-at-head"),
        "coverage-state": ("coverage-shard", "coverage", "coverage", "", "canonical-sha", "coverage-row-matches-target"),
        "superseded-acceptance": ("canonical-event", "records", "events", "", "events-head", "superseded-acceptance-exists-and-matches-correction"),
        "current-acceptance-basis": ("status-detail", "records", "derived", "", "generation", "current-acceptance-basis-matches-superseded-acceptance"),
        "published-agreement": ("canonical-event", "records", "events", "", "events-head", "published-event-exists-and-matches-target"),
        "target-activation": ("canonical-event", "records", "events", "", "events-head", "target-activation-exists-and-matches-restore"),
        "publication-snapshot-absence": ("agreement-snapshot", "records", "events", "", "events-head", "agreement-snapshot-is-absent"),
        "publication-metadata-absence": ("agreement-metadata", "records", "events", "", "events-head", "agreement-metadata-is-absent"),
        "current-repository-owner": ("signed-registry-entry", "registry", "main", _registry_entry_path(event.project_id), "registry-generation", "repository-owner-and-set-are-current"),
        "keyring-affected-repositories": ("canonical-project-state", "records", "events", "", "events-head", "affected-repository-ids-equal-authorization-resources"),
        "current-scope": ("signed-registry-entry", "registry", "main", _registry_entry_path(event.project_id), "registry-generation", "scope-is-current"),
        "scope-request": ("canonical-event", "records", "events", "", "events-head", "request-exists-and-matches-terminal"),
        "scope-terminal-activation-absence": ("canonical-event", "records", "events", "", "events-head", "activation-terminal-child-is-absent"),
        "scope-terminal-abandonment-absence": ("canonical-event", "records", "events", "", "events-head", "abandonment-terminal-child-is-absent"),
        "override-grant": ("canonical-event", "records", "events", event_path(event.target.get("override_event_id", event.event_id)), "events-head", "override-grant-event-matches-target"),
        "current-exemption-union": ("status-detail", "records", "derived", "", "generation", "exemption-union-provenance-is-current"),
        "current-derived-state": ("derived-state", "records", "derived", "derived/state.enc.json", "generation", "standing-rules-and-installed-profile-are-current"),
        "active-exemption-rule-state": ("derived-state", "records", "derived", "derived/state.enc.json", "generation", "referenced-standing-rule-is-current"),
        "source-event": ("canonical-event", "records", "events", "", "events-head", "source-event-exists-and-matches-target"),
        "rule-event": ("canonical-event", "records", "events", "", "events-head", "rule-event-exists-and-matches-target"),
        "materialization-cursor": ("reader-authority", "records", "derived", _reader_shard_path(source_id), "generation", "prior-materialization-cursor-is-current"),
        "current-reader-authority": ("reader-authority", "records", "derived", _reader_shard_path(source_id), "generation", "reader-source-and-rule-state-is-current"),
        "active-reader-rules": ("reader-authority", "records", "derived", "", "generation", "active-continuous-reader-rules-are-current"),
        "reader-authority-state": ("reader-authority", "records", "derived", _reader_shard_path(source_id), "generation", "reader-class-currentness-and-source-state"),
        "successor-project": ("canonical-event", "records", "events", "", "cross-project", f"successor-connected-reciprocal:{event.target.get('successor_project_id', '')}"),
    }
    if event_type == "agreement_activated":
        specs["active-agreement"] = (*specs["active-agreement"][:5], "prior-active-agreement-and-prospective-activation-match")
    elif event_type == "agreement_activation_restored":
        specs["active-agreement"] = (*specs["active-agreement"][:5], "prior-active-agreement-and-prospective-restore-match")
    if "published-agreement" in _PRECONDITION_MATRIX[event_type]:
        specs["published-agreement"] = (*specs["published-agreement"][:3], event_path(event.payload["published_event_id"]), *specs["published-agreement"][4:])
    if "target-activation" in _PRECONDITION_MATRIX[event_type]:
        specs["target-activation"] = (*specs["target-activation"][:3], event_path(event.target["activation_event_id"]), *specs["target-activation"][4:])
    if "scope-request" in _PRECONDITION_MATRIX[event_type]:
        specs["scope-request"] = (*specs["scope-request"][:3], event_path(event.payload["request_event_id"]), *specs["scope-request"][4:])
    if "source-event" in _PRECONDITION_MATRIX[event_type]:
        specs["source-event"] = (*specs["source-event"][:3], event_path(event.target["source_event_id"]), *specs["source-event"][4:])
    if "rule-event" in _PRECONDITION_MATRIX[event_type]:
        specs["rule-event"] = (*specs["rule-event"][:3], event_path(event.target["rule_event_id"]), *specs["rule-event"][4:])
    if "successor-project" in _PRECONDITION_MATRIX[event_type]:
        specs["successor-project"] = (*specs["successor-project"][:3], event_path(event.payload["successor_connected_event_id"]), *specs["successor-project"][4:])
    if event_type == "exemption_materialized":
        specs["materialization-cursor"] = (
            "status-detail",
            "records",
            "derived",
            f"derived/status-detail/{event.target['subject']['github_user_id'] % 32:02d}.enc.json",
            "generation",
            "prior-materialization-cursor-is-current",
        )
    names: list[str] = []
    matrix_names = list(_PRECONDITION_MATRIX[event_type])
    if event_type == "acceptance" and event.payload["supersedes"] is not None:
        insertion = matrix_names.index("current-configuration") + 1
        matrix_names[insertion:insertion] = ["superseded-acceptance", "current-acceptance-basis"]
    for name in matrix_names:
        if name == "coverage-state":
            names.extend(f"coverage-state-{shard:02d}" for shard in coverage_shards)
        elif name == "current-exemption-union":
            names.extend(f"current-exemption-union-{shard:02d}" for shard in exemption_shards)
        elif name == "active-reader-rules":
            names.extend(f"active-reader-rules-{shard:02d}" for shard in range(32))
        else:
            names.append(name)

    result: list[PreconditionRequirement] = []
    for name in names:
        if name == "generations-absence":
            spec = ("materialization-generations", "records", "events", "config/materialization-generations.enc.json", "events-head", "artifact-absent-at-head")
        elif name.startswith("coverage-state-"):
            shard = int(name.rsplit("-", 1)[1])
            spec = (*specs["coverage-state"][:3], _coverage_shard_path(shard), *specs["coverage-state"][4:])
        elif name.startswith("current-exemption-union-"):
            shard = int(name.rsplit("-", 1)[1])
            spec = (*specs["current-exemption-union"][:3], f"derived/status-detail/{shard:02d}.enc.json", *specs["current-exemption-union"][4:])
        elif name.startswith("active-reader-rules-"):
            shard = int(name.rsplit("-", 1)[1])
            spec = (*specs["active-reader-rules"][:3], f"derived/reader-authority/{shard:02d}.enc.json", *specs["active-reader-rules"][4:])
        elif name == "superseded-acceptance":
            spec = (*specs[name][:3], event_path(event.payload["supersedes"]), *specs[name][4:])
        elif name == "current-acceptance-basis":
            spec = (*specs[name][:3], f"derived/status-detail/{event.target['coverage_tuple']['github_user_id'] % 32:02d}.enc.json", *specs[name][4:])
        elif name == "publication-snapshot-absence":
            spec = (*specs[name][:3], _agreement_version_path(event.target["agreement_id"], event.target["version"], ".md"), *specs[name][4:])
        elif name == "publication-metadata-absence":
            spec = (*specs[name][:3], _agreement_version_path(event.target["agreement_id"], event.target["version"], ".meta.json"), *specs[name][4:])
        elif name == "scope-terminal-activation-absence":
            spec = (*specs[name][:3], _scope_terminal_child_path(event.project_id, event.payload["request_event_id"], "enforcement_scope_activated"), *specs[name][4:])
        elif name == "scope-terminal-abandonment-absence":
            spec = (*specs[name][:3], _scope_terminal_child_path(event.project_id, event.payload["request_event_id"], "enforcement_scope_abandoned"), *specs[name][4:])
        else:
            spec = specs[name]
        result.append(_requirement(name, kind=spec[0], role=spec[1], branch=spec[2], path=spec[3], binding=spec[4], relation=spec[5], expected_head=expected_head))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class PreconditionEvidence:
    """Authenticated, already-decoded evidence supplied by a history owner."""

    name: str
    artifact_kind: str
    repository_role: str
    branch: str
    path: str
    binding_mode: str
    binding: PreconditionBinding
    value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.binding, (EventsHeadBinding, GenerationBinding, CanonicalShaBinding, CrossProjectBinding, RegistryGenerationBinding)):
            _error("precondition evidence binding is unsupported", PreconditionValidationError)
        if self.binding_mode != self.binding.mode:
            _error("precondition evidence binding mode is inconsistent", PreconditionValidationError)
        if type(self.value) not in (dict, list, tuple, str, int, bool, type(None)):
            _error("precondition evidence has an unsupported value", PreconditionValidationError)
        object.__setattr__(self, "value", _freeze(self.value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "artifact_kind": self.artifact_kind,
            "repository_role": self.repository_role,
            "branch": self.branch,
            "path": self.path,
            "binding_mode": self.binding_mode,
            "binding": _binding_to_dict(self.binding),
            "value": _thaw(self.value),
        }


@dataclass(frozen=True, slots=True)
class SideArtifactRequirement:
    """One deterministic side artifact required by an event."""

    kind: str
    path: str
    relation: str
    affected_classes: tuple[str, ...] = ()


_AFFECTED_CLASSES: dict[str, tuple[str, ...]] = {
    "project_connected": ("derived_index", "status_detail", "reader_authority"),
    "acceptance": ("derived_index", "status_detail"),
    "revocation": ("derived_index", "status_detail"),
    "exemption": ("derived_index", "status_detail"),
    "exemption_snapshot": ("derived_index", "status_detail"),
    "exemption_source_withdrawn": ("derived_index", "status_detail"),
    "exemption_materialized": ("derived_index", "status_detail"),
    "exemption_rule_configured": ("status_detail",),
    "exemption_rule_withdrawn": ("status_detail",),
    "records_reader_authorized": ("reader_authority",),
    "records_reader_snapshot_authorized": ("reader_authority",),
    "records_reader_withdrawn": ("reader_authority",),
    "records_reader_rule_configured": ("reader_authority",),
    "records_reader_rule_withdrawn": ("reader_authority",),
    "records_reader_materialized": ("reader_authority",),
}


def _affected_classes_for(event: ValidatedEvent, evidence: Mapping[str, PreconditionEvidence]) -> tuple[str, ...]:
    """Resolve effect-based generation classes from authenticated facts."""

    if event.type == "exemption_rule_withdrawn":
        rule_id = event.target["rule_event_id"]
        provenance = {
            subject_id: sources
            for name, item in evidence.items()
            if name.startswith("current-exemption-union-")
            for subject_id, sources in item.value["provenance"].items()
        }
        flips = any(isinstance(sources, Sequence) and rule_id in sources and len(sources) == 1 for sources in provenance.values())
        return ("derived_index", "status_detail") if flips else ("status_detail",)
    if event.type in {"records_reader_withdrawn", "records_reader_rule_withdrawn"}:
        fact = evidence["reader-authority-state"].value
        source_id = event.target["source_event_id"] if event.type == "records_reader_withdrawn" else event.target["rule_event_id"]
        sources = fact["source_event_ids"]
        observation = evidence["reader-authority-state"].binding
        state = "current" if observation.canonical_generation == observation.derived_generation else "stale"
        if state == "stale" or source_id in sources:
            return ("reader_authority",)
        return ()
    return _AFFECTED_CLASSES.get(event.type, ())


def _binding_to_dict(binding: PreconditionBinding) -> dict[str, Any]:
    if isinstance(binding, EventsHeadBinding):
        return {"mode": binding.mode, "events_head": binding.events_head}
    if isinstance(binding, GenerationBinding):
        return {
            "mode": binding.mode,
            "events_head": binding.events_head,
            "canonical_generation": binding.canonical_generation,
            "derived_generation": binding.derived_generation,
        }
    if isinstance(binding, CanonicalShaBinding):
        return {
            "mode": binding.mode,
            "coverage_commit_oid": binding.coverage_commit_oid,
            "canonical_sha": binding.canonical_sha,
        }
    if isinstance(binding, RegistryGenerationBinding):
        return {
            "mode": binding.mode,
            "registry_commit_oid": binding.registry_commit_oid,
            "registry_generation": binding.registry_generation,
        }
    return {
        "mode": binding.mode,
        "successor_project_id": binding.successor_project_id,
        "successor_events_head": binding.successor_events_head,
        "repository_ids": list(binding.repository_ids),
    }


def _parse_binding(value: Any, *, mode: str) -> PreconditionBinding:
    if type(value) is not dict or value.get("mode") != mode:
        _error("precondition binding is malformed", PreconditionValidationError)
    if mode == "events-head":
        if set(value) != {"mode", "events_head"}:
            _error("events-head binding has missing or extra fields", PreconditionValidationError)
        try:
            return EventsHeadBinding(_oid(value["events_head"], "events head"))
        except EventValidationError:
            _error("events-head binding is malformed", PreconditionValidationError)
    if mode == "generation":
        if set(value) != {"mode", "events_head", "canonical_generation", "derived_generation"}:
            _error("generation binding has missing or extra fields", PreconditionValidationError)
        try:
            return GenerationBinding(
                _oid(value["events_head"], "generation events head"),
                _event_id(value["canonical_generation"], "canonical generation"),
                _event_id(value["derived_generation"], "derived generation"),
            )
        except EventValidationError:
            _error("generation binding is malformed", PreconditionValidationError)
    if mode == "canonical-sha":
        if set(value) != {"mode", "coverage_commit_oid", "canonical_sha"}:
            _error("canonical-sha binding has missing or extra fields", PreconditionValidationError)
        try:
            return CanonicalShaBinding(_oid(value["coverage_commit_oid"], "coverage commit"), _oid(value["canonical_sha"], "canonical sha"))
        except EventValidationError:
            _error("canonical-sha binding is malformed", PreconditionValidationError)
    if mode == "cross-project":
        if set(value) != {"mode", "successor_project_id", "successor_events_head", "repository_ids"}:
            _error("cross-project binding has missing or extra fields", PreconditionValidationError)
        repository_ids = value["repository_ids"]
        if isinstance(repository_ids, (str, bytes, bytearray)) or type(repository_ids) is not list or not repository_ids:
            _error("cross-project repository IDs are malformed", PreconditionValidationError)
        parsed_ids = tuple(_positive(item, "successor repository ID") for item in repository_ids)
        if len(set(parsed_ids)) != len(parsed_ids):
            _error("cross-project repository IDs contain duplicates", PreconditionValidationError)
        try:
            return CrossProjectBinding(_string(value["successor_project_id"], "successor project ID"), _oid(value["successor_events_head"], "successor events head"), parsed_ids)
        except EventValidationError:
            _error("cross-project binding is malformed", PreconditionValidationError)
    if mode == "registry-generation":
        if set(value) != {"mode", "registry_commit_oid", "registry_generation"}:
            _error("registry-generation binding has missing or extra fields", PreconditionValidationError)
        try:
            return RegistryGenerationBinding(
                _oid(value["registry_commit_oid"], "registry commit"),
                _nonnegative(value["registry_generation"], "registry generation"),
            )
        except EventValidationError:
            _error("registry-generation binding is malformed", PreconditionValidationError)
    _error("precondition binding mode is unsupported", PreconditionValidationError)


def _coerce_precondition(value: Any) -> PreconditionEvidence:
    if isinstance(value, PreconditionEvidence):
        return value
    if type(value) is not dict:
        _error("precondition evidence entry must be an object", PreconditionValidationError)
    name = value.get("name")
    required = {"name", "artifact_kind", "repository_role", "branch", "path", "binding_mode", "binding", "value"}
    if set(value) != required:
        _error("precondition evidence has missing or extra fields", PreconditionValidationError)
    if type(name) is not str or not name:
        _error("precondition evidence name is invalid", PreconditionValidationError)
    if any(type(value.get(key)) is not str or not value.get(key) for key in ("artifact_kind", "repository_role", "branch", "binding_mode")):
        _error("precondition evidence descriptor is malformed", PreconditionValidationError)
    if type(value["path"]) is not str or (not value["path"] and value["artifact_kind"] != "canonical-project-state"):
        _error("precondition evidence descriptor is malformed", PreconditionValidationError)
    binding = _parse_binding(value["binding"], mode=value["binding_mode"])
    return PreconditionEvidence(name, value["artifact_kind"], value["repository_role"], value["branch"], value["path"], value["binding_mode"], binding, value["value"])


def _precondition_map(value: Any) -> dict[str, PreconditionEvidence]:
    if isinstance(value, Mapping):
        entries = []
        for name, item in value.items():
            if isinstance(item, PreconditionEvidence):
                if item.name != name:
                    _error("precondition mapping key does not match embedded name", PreconditionValidationError)
                entries.append(item)
            elif type(item) is dict:
                if "name" in item and item["name"] != name:
                    _error("precondition mapping key does not match embedded name", PreconditionValidationError)
                if "name" not in item:
                    item = {"name": name, **item}
                entries.append(_coerce_precondition(item))
            else:
                entries.append(_coerce_precondition(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        entries = [_coerce_precondition(item) for item in value]
    else:
        _error("preconditions must be an ordered sequence or mapping", PreconditionValidationError)
    result: dict[str, PreconditionEvidence] = {}
    for item in entries:
        if item.name in result:
            _error("preconditions contain a duplicate requirement", PreconditionValidationError)
        result[item.name] = item
    return result


def _validate_binding(binding: PreconditionBinding, requirement: PreconditionRequirement, expected_head: str) -> None:
    if binding.mode != requirement.binding_mode:
        _error("precondition binding mode does not match requirement", PreconditionValidationError)
    if isinstance(binding, EventsHeadBinding):
        if binding.events_head != expected_head:
            _error("events-head evidence is stale", PreconditionValidationError)
    elif isinstance(binding, GenerationBinding):
        if binding.events_head != expected_head:
            _error("generation evidence is stale or inconsistent", PreconditionValidationError)
        if requirement.name == "reader-authority-state":
            # Shrink-only withdrawals may observe a stale derived class.  The
            # unequal generation pair is the authenticated stale marker; all
            # ordinary generation-bound requirements retain equality.
            return
        if binding.canonical_generation != binding.derived_generation:
            _error("generation evidence is stale or inconsistent", PreconditionValidationError)
    elif isinstance(binding, CanonicalShaBinding):
        if binding.canonical_sha != expected_head:
            _error("coverage canonical SHA does not match expected head", PreconditionValidationError)
    elif isinstance(binding, CrossProjectBinding):
        expected_project = requirement.relation.split(":", 1)[1] if ":" in requirement.relation else None
        if expected_project is None or binding.successor_project_id != expected_project:
            _error("cross-project binding names the wrong successor", PreconditionValidationError)
    elif isinstance(binding, RegistryGenerationBinding):
        # Registry generations are signed evidence from a separate repository;
        # neither its commit nor generation is an events-head value.
        pass


def _validate_generation_join(
    event: ValidatedEvent,
    requirement: PreconditionRequirement,
    evidence: PreconditionEvidence,
    values: Mapping[str, PreconditionEvidence],
) -> None:
    """Join a generation-bound observation to its authenticated prior class."""

    if requirement.binding_mode != "generation":
        return
    prior = values.get("prior-generations")
    if prior is None:
        _error("generation evidence has no authenticated prior generation", PreconditionValidationError)
    prior_fact = _relation_object(
        prior.value,
        ("derived_index", "status_detail", "reader_authority"),
        "prior generations",
    )
    if event.type == "records_reader_rule_configured" and requirement.name == "current-derived-state":
        # The reader profile is stored in derived/state.enc.json, but the
        # reader-rule count is consumed against reader-authority shards.  Its
        # generation join therefore follows the reader class rather than the
        # status-detail class used by other derived-state consumers.
        generation_class = "reader_authority"
    else:
        generation_class = {
            "status-detail": "status_detail",
            "derived-state": "status_detail",
            "reader-authority": "reader_authority",
        }.get(requirement.artifact_kind)
    if generation_class is None:
        _error("generation evidence has an unsupported artifact class", PreconditionValidationError)
    expected_generation = prior_fact[generation_class]
    try:
        _event_id(expected_generation, "prior generation")
    except EventValidationError:
        _error("prior generations evidence is malformed", PreconditionValidationError)
    binding = evidence.binding
    if not isinstance(binding, GenerationBinding):
        _error("generation evidence has an invalid binding", PreconditionValidationError)
    if binding.canonical_generation != expected_generation:
        _error("generation evidence does not join the authenticated prior generation", PreconditionValidationError)


def _relation_object(value: Any, keys: Sequence[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        _error(f"{label} evidence has missing or extra facts", PreconditionValidationError)
    return value


def _version_set(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _error(f"{label} is malformed", PreconditionValidationError)
    result = tuple(value)
    if not allow_empty and not result:
        _error(f"{label} must not be empty", PreconditionValidationError)
    if any(type(version) is not str or not version for version in result):
        _error(f"{label} is malformed", PreconditionValidationError)
    if len(set(result)) != len(result):
        _error(f"{label} contains duplicates", PreconditionValidationError)
    encoded = tuple(canonical_json(version) for version in result)
    if encoded != tuple(sorted(encoded)):
        _error(f"{label} is not in JCS lexical order", PreconditionValidationError)
    return result


def _ordered_version_union(*values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(set().union(*values), key=canonical_json))


def _registry_entry(value: Any, label: str) -> Mapping[str, Any]:
    """Validate the closed local portion of a signed project registry entry."""

    if not isinstance(value, Mapping):
        _error(f"{label} evidence is not a registry entry", PreconditionValidationError)
    entry = value.get("project_entry", value)
    required = {
        "project_id", "project_slug", "repository_owner", "repository_ids",
        "registry_generation", "enforcement_scope", "request_event_links",
    }
    if not isinstance(entry, Mapping) or not required.issubset(set(entry)):
        _error(f"{label} registry entry is incomplete", PreconditionValidationError)
    _string(entry["project_id"], f"{label}.project_id")
    if type(entry["project_slug"]) is not str or _PROJECT_SLUG.fullmatch(entry["project_slug"]) is None:
        _error(f"{label}.project_slug is malformed", PreconditionValidationError)
    _parse_owner(entry["repository_owner"], f"{label}.repository_owner")
    _parse_repo_ids(entry["repository_ids"], f"{label}.repository_ids")
    _nonnegative(entry["registry_generation"], f"{label}.registry_generation")
    if not isinstance(entry["enforcement_scope"], Sequence) or isinstance(entry["enforcement_scope"], (str, bytes, bytearray)):
        _error(f"{label}.enforcement_scope is malformed", PreconditionValidationError)
    _parse_scope(entry["enforcement_scope"], f"{label}.enforcement_scope")
    links = entry["request_event_links"]
    if not isinstance(links, Mapping):
        _error(f"{label}.request_event_links is malformed", PreconditionValidationError)
    for linked_id in links.values():
        try:
            _event_id(linked_id, f"{label} request event link")
        except EventValidationError:
            _error(f"{label}.request_event_links is malformed", PreconditionValidationError)
    return entry


def _registry_entries(value: Any, fields: Sequence[str], label: str) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        _error(f"{label} registry transition is missing or has extra entries", PreconditionValidationError)
    return {field: _registry_entry(value[field], f"{label}.{field}") for field in fields}


def _validate_link_fact(event: ValidatedEvent, name: str, value: Any) -> None:
    link_keys = ("event_id", "type", "project_id", "target", "payload", "authorizations") if name == "scope-request" else ("event_id", "type", "project_id", "target", "payload")
    fact = _relation_object(value, link_keys, f"{name} link")
    _event_id(fact["event_id"], f"{name} event_id")
    if fact["project_id"] != event.project_id:
        _error(f"{name} link belongs to another project", PreconditionValidationError)
    if name == "active-publication":
        if fact["type"] != "agreement_published" or fact["project_id"] != event.project_id:
            _error("active publication fact is not an agreement publication", PreconditionValidationError)
        if fact["target"] != {"agreement_id": event.target["coverage_tuple"]["agreement_id"], "version": event.target["version"]}:
            _error("active publication target does not match acceptance", PreconditionValidationError)
        payload = fact["payload"]
        if not isinstance(payload, Mapping) or set(payload) != {
            "recipient", "ref", "content_commit_oid", "digest",
            "snapshot_content_path", "snapshot_metadata_path", "snapshot_sha256",
        }:
            _error("active publication payload is malformed", PreconditionValidationError)
        _parse_recipient(payload["recipient"])
        _string(payload["ref"], "active publication ref")
        _oid(payload["content_commit_oid"], "active publication content commit")
        _digest(payload["digest"], "active publication digest")
        _digest(payload["snapshot_sha256"], "active publication snapshot digest")
        if payload["recipient"] != event.target["recipient"] or payload["digest"] != event.target["digest"]:
            _error("active publication recipient or digest does not match acceptance", PreconditionValidationError)
    elif name == "published-agreement":
        if fact["event_id"] != event.payload["published_event_id"] or fact["type"] != "agreement_published" or fact["target"] != {"agreement_id": event.target["agreement_id"], "version": event.target["version"]}:
            _error("published agreement fact does not match activation", PreconditionValidationError)
        publication = fact["payload"]
        if not isinstance(publication, Mapping) or set(publication) != {
            "recipient", "ref", "content_commit_oid", "digest",
            "snapshot_content_path", "snapshot_metadata_path", "snapshot_sha256",
        }:
            _error("published agreement fact payload is malformed", PreconditionValidationError)
        _parse_recipient(publication["recipient"])
        _string(publication["ref"], "published agreement ref")
        _oid(publication["content_commit_oid"], "published agreement content commit")
        _digest(publication["digest"], "published agreement digest")
        _digest(publication["snapshot_sha256"], "published agreement snapshot digest")
    elif name == "target-activation":
        if fact["event_id"] != event.target["activation_event_id"] or fact["type"] != "agreement_activated":
            _error("target activation fact does not name an ordinary activation", PreconditionValidationError)
        target = fact["target"]
        if not isinstance(target, Mapping) or set(target) != {"agreement_id", "version"}:
            _error("target activation target is malformed", PreconditionValidationError)
        if target["agreement_id"] != event.target["agreement_id"]:
            _error("target activation belongs to another agreement", PreconditionValidationError)
        _string(target["version"], "target activation version")
        payload = fact["payload"]
        if not isinstance(payload, Mapping) or set(payload) != {"published_event_id", "supersedes_coverage", "accepted_versions"}:
            _error("target activation payload is malformed", PreconditionValidationError)
        _event_id(payload["published_event_id"], "target activation publication")
        if type(payload["supersedes_coverage"]) is not bool:
            _error("target activation supersedes flag is malformed", PreconditionValidationError)
        accepted_versions = _version_set(payload["accepted_versions"], "target activation accepted versions", allow_empty=False)
        if target["version"] not in accepted_versions:
            _error("target activation version is not accepted", PreconditionValidationError)
        if tuple(event.payload["accepted_versions"]) != accepted_versions:
            _error("restore does not copy the target activation accepted versions", PreconditionValidationError)
    elif name == "scope-request":
        if fact["event_id"] != event.payload["request_event_id"] or fact["type"] != "enforcement_scope_requested" or fact["target"] != {"change_id": event.target["change_id"]}:
            _error("scope request fact does not match terminal", PreconditionValidationError)
        try:
            request_authorizations = _parse_auth_structure(_thaw(fact["authorizations"]), "enforcement_scope_requested")
        except (KeyError, EventValidationError):
            _error("scope request authorization fact is malformed", PreconditionValidationError)
        terminal_identity = tuple(
            (item.operation, item.resource_kind, item.resource_id, item.required_authority)
            for item in event.authorizations
        )
        request_identity = tuple(
            (item.operation, item.resource_kind, item.resource_id, item.required_authority)
            for item in request_authorizations
        )
        if request_identity != terminal_identity:
            _error("scope terminal authorization does not repeat the request", PreconditionValidationError)
        if not isinstance(fact["payload"], Mapping) or set(fact["payload"]) != {"prior_scope", "desired_scope", "prior_registry_generation"}:
            _error("scope request fact payload is malformed", PreconditionValidationError)
        try:
            _parse_scope(fact["payload"]["prior_scope"], "scope request prior scope")
            desired = _parse_scope(fact["payload"]["desired_scope"], "scope request desired scope")
            _nonnegative(fact["payload"]["prior_registry_generation"], "scope request prior registry generation")
        except EventValidationError:
            _error("scope request fact payload is malformed", PreconditionValidationError)
        expected_desired = event.payload.get("desired_scope")
        if expected_desired is not None and desired != _parse_scope(expected_desired, "terminal desired scope"):
            _error("scope request desired scope does not match terminal", PreconditionValidationError)
    elif name == "source-event":
        allowed = (
            {"exemption", "exemption_snapshot"}
            if event.type == "exemption_source_withdrawn"
            else {"records_reader_authorized", "records_reader_snapshot_authorized"}
        )
        if fact["type"] not in allowed:
            _error("source event fact has an unsupported type", PreconditionValidationError)
        if event.target["source_event_id"] != fact["event_id"]:
            _error("source event fact does not match withdrawal", PreconditionValidationError)
        subject = event.target["subject"]
        if fact["type"] in {"exemption", "records_reader_authorized"}:
            if fact["target"] != {"subject": subject}:
                _error("source event subject does not match withdrawal", PreconditionValidationError)
        elif not isinstance(fact["target"], Mapping) or set(fact["target"]) != {"subjects"} or subject not in fact["target"]["subjects"]:
            _error("source event subject is not in snapshot", PreconditionValidationError)
    elif name == "rule-event":
        allowed = (
            {"exemption_rule_configured"}
            if event.type in {"exemption_rule_withdrawn", "exemption_materialized"}
            else {"records_reader_rule_configured"}
        )
        if fact["type"] not in allowed:
            _error("rule event fact has an unsupported type", PreconditionValidationError)
        if event.target["rule_event_id"] != fact["event_id"]:
            _error("rule event fact does not match transition", PreconditionValidationError)
        if not isinstance(fact["target"], Mapping) or set(fact["target"]) != {"team"}:
            _error("rule event target is malformed", PreconditionValidationError)
        if event.type in {"exemption_materialized", "records_reader_materialized"}:
            try:
                expected_team = _parse_team(event.payload["team"])
                actual_team = _parse_team(fact["target"]["team"])
            except EventValidationError:
                _error("rule event team is malformed", PreconditionValidationError)
            if actual_team != expected_team:
                _error("rule event team does not match materialization", PreconditionValidationError)


def _validate_terminal_observation(value: Any, expected_path: str) -> bool:
    """Validate one authenticated exact-path terminal presence observation."""

    if not isinstance(value, Mapping) or set(value) != {"path", "present"}:
        _error("scope terminal observation is malformed", PreconditionValidationError)
    if value["path"] != expected_path or type(value["present"]) is not bool:
        _error("scope terminal observation is not bound to its path", PreconditionValidationError)
    return value["present"]


def _validate_project_agreement_fact(event: ValidatedEvent, value: Any) -> None:
    """Validate the canonical project identity and publication catalog."""

    fact = _relation_object(
        value,
        ("project_id", "recipient", "agreement_id", "published_versions"),
        "current project agreement",
    )
    if fact["project_id"] != event.project_id:
        _error("current project agreement belongs to another project", PreconditionValidationError)
    try:
        observed_recipient = _parse_recipient(fact["recipient"])
        event_recipient = _parse_recipient(event.payload["recipient"])
    except EventValidationError:
        _error("current project recipient is malformed", PreconditionValidationError)
    if observed_recipient != event_recipient:
        _error("current project recipient does not match publication", PreconditionValidationError)

    agreement_id = fact["agreement_id"]
    if agreement_id is not None:
        try:
            _string(agreement_id, "current project agreement ID")
        except EventValidationError:
            _error("current project agreement ID is malformed", PreconditionValidationError)
        if agreement_id != event.target["agreement_id"]:
            _error("current project agreement does not match publication", PreconditionValidationError)

    versions = fact["published_versions"]
    if isinstance(versions, (str, bytes, bytearray)) or not isinstance(versions, Sequence):
        _error("published version catalog is malformed", PreconditionValidationError)
    seen: set[tuple[str, str]] = set()
    for version_entry in versions:
        entry = _relation_object(version_entry, ("agreement_id", "version"), "published version")
        try:
            entry_agreement_id = _string(entry["agreement_id"], "published version agreement ID")
            version = _string(entry["version"], "published version")
        except EventValidationError:
            _error("published version catalog is malformed", PreconditionValidationError)
        if agreement_id is None or entry_agreement_id != agreement_id:
            _error("published version catalog has an inconsistent agreement", PreconditionValidationError)
        identity = (entry_agreement_id, version)
        if identity in seen:
            _error("published version catalog contains duplicates", PreconditionValidationError)
        seen.add(identity)
        if identity == (event.target["agreement_id"], event.target["version"]):
            _error("published version catalog already contains the proposed version", PreconditionValidationError)


def _validate_superseded_acceptance_fact(event: ValidatedEvent, value: Any) -> None:
    """Validate the canonical acceptance named by a correction."""

    fact = _relation_object(
        value,
        ("event_id", "type", "project_id", "target", "payload"),
        "superseded acceptance",
    )
    try:
        _event_id(fact["event_id"], "superseded acceptance event")
        target, payload = _parse_target_payload("acceptance", _thaw(fact["target"]), _thaw(fact["payload"]))
        current_coverage = _parse_coverage(event.target["coverage_tuple"])
        prior_coverage = _parse_coverage(target["coverage_tuple"])
        current_recipient = _parse_recipient(event.target["recipient"])
        prior_recipient = _parse_recipient(target["recipient"])
    except EventValidationError:
        _error("superseded acceptance fact is malformed", PreconditionValidationError)
    if fact["event_id"] != event.payload["supersedes"]:
        _error("superseded acceptance fact does not match correction", PreconditionValidationError)
    if fact["type"] != "acceptance" or fact["project_id"] != event.project_id:
        _error("superseded acceptance fact has the wrong identity", PreconditionValidationError)
    if prior_coverage != current_coverage or prior_recipient != current_recipient:
        _error("superseded acceptance fact does not match correction coverage", PreconditionValidationError)
    if target["version"] != event.target["version"] or target["digest"] != event.target["digest"]:
        _error("superseded acceptance fact does not match correction target", PreconditionValidationError)


def _validate_acceptance_basis_fact(event: ValidatedEvent, value: Any) -> None:
    """Validate the generation-bound status-detail basis for a correction."""

    fact = _relation_object(value, ("project_id", "github_user_id", "agreement_id", "basis"), "current acceptance basis")
    basis = _relation_object(fact["basis"], ("event_id", "kind"), "current acceptance basis")
    try:
        _event_id(basis["event_id"], "current acceptance basis event")
        github_user_id = _positive(fact["github_user_id"], "current acceptance basis github user ID")
        agreement_id = _string(fact["agreement_id"], "current acceptance basis agreement ID")
    except EventValidationError:
        _error("current acceptance basis is malformed", PreconditionValidationError)
    if (
        fact["project_id"] != event.project_id
        or github_user_id != event.target["coverage_tuple"]["github_user_id"]
        or agreement_id != event.target["coverage_tuple"]["agreement_id"]
        or basis["kind"] != "acceptance"
        or basis["event_id"] != event.payload["supersedes"]
    ):
        _error("current acceptance basis does not match correction", PreconditionValidationError)


def _validate_preconditions_impl(event: ValidatedEvent, preconditions: Any, expected_head: str) -> dict[str, PreconditionEvidence]:
    _event_name(event)
    if event.confirmed_canonical_oid is not None and event.confirmed_canonical_oid != expected_head:
        _error("event confirmed head does not match expected head", PreconditionValidationError)
    expected = required_preconditions(event, expected_head=expected_head)
    values = _precondition_map(preconditions)
    if set(values) != {item.name for item in expected}:
        _error("precondition evidence does not exactly match requirements", PreconditionValidationError)
    by_name = {item.name: item for item in expected}
    for name, evidence in values.items():
        requirement = by_name[name]
        if (evidence.artifact_kind, evidence.repository_role, evidence.branch, evidence.path, evidence.binding_mode) != (requirement.artifact_kind, requirement.repository_role, requirement.branch, requirement.path, requirement.binding_mode):
            _error("precondition evidence is stale or bound to the wrong artifact", PreconditionValidationError)
        _validate_binding(evidence.binding, requirement, expected_head)
        if name == "materialization-cursor":
            fact = _relation_object(evidence.value, ("cursor_event_id", "prior_materialization_event_id", "rule_event_id", "subject"), "materialization cursor")
            try:
                if fact["cursor_event_id"] is not None:
                    _event_id(fact["cursor_event_id"], "materialization cursor")
                if fact["prior_materialization_event_id"] is not None:
                    _event_id(fact["prior_materialization_event_id"], "prior materialization event")
                if fact["rule_event_id"] != event.target["rule_event_id"] or _parse_subject(fact["subject"], "materialization cursor subject") != _parse_subject(event.target["subject"], "materialization target subject"):
                    _error("materialization cursor identity does not match event", PreconditionValidationError)
                if fact["cursor_event_id"] != event.payload["prior_materialization_event_id"]:
                    _error("materialization cursor does not match event prior cursor", PreconditionValidationError)
            except EventValidationError:
                _error("materialization cursor is malformed", PreconditionValidationError)
            continue
        if name == "reader-authority-state":
            identity_keys = (
                ("source_event_id", "subject")
                if event.type == "records_reader_withdrawn"
                else ("rule_event_id",)
            )
            fact = _relation_object(
                evidence.value,
                ("project_id", "class_state", "source_event_ids", "cursor_event_id", *identity_keys),
                "reader authority state",
            )
            if fact["project_id"] != event.project_id or fact["class_state"] not in {"current", "stale"} or isinstance(fact["source_event_ids"], (str, bytes, bytearray)) or not isinstance(fact["source_event_ids"], Sequence) or any(type(source) is not str for source in fact["source_event_ids"]):
                _error("reader authority state is inconsistent", PreconditionValidationError)
            observed_state = "current" if evidence.binding.canonical_generation == evidence.binding.derived_generation else "stale"
            if fact["class_state"] != observed_state:
                _error("reader authority state does not match generation observation", PreconditionValidationError)
            try:
                _event_id(fact["cursor_event_id"], "reader authority cursor")
                if fact["cursor_event_id"] != evidence.binding.derived_generation:
                    _error("reader authority cursor does not match observed generation", PreconditionValidationError)
                for source in fact["source_event_ids"]:
                    _event_id(source, "reader authority source")
                if event.type == "records_reader_withdrawn":
                    _event_id(fact["source_event_id"], "reader authority source event")
                    if fact["source_event_id"] != event.target["source_event_id"]:
                        _error("reader authority source event does not match withdrawal", PreconditionValidationError)
                    if _parse_subject(fact["subject"], "reader authority withdrawal subject") != _parse_subject(event.target["subject"], "reader withdrawal subject"):
                        _error("reader authority withdrawal subject does not match withdrawal", PreconditionValidationError)
                else:
                    _event_id(fact["rule_event_id"], "reader authority rule event")
                    if fact["rule_event_id"] != event.target["rule_event_id"]:
                        _error("reader authority rule event does not match withdrawal", PreconditionValidationError)
            except EventValidationError:
                _error("reader authority state is inconsistent", PreconditionValidationError)
            if len(set(fact["source_event_ids"])) != len(fact["source_event_ids"]):
                _error("reader authority state is inconsistent", PreconditionValidationError)
            continue
        if name == "current-reader-authority":
            reader_authority_keys = ("project_id", "class_state", "sources", "cursor_event_id")
            if event.type == "records_reader_materialized":
                reader_authority_keys += ("rule_event_id", "subject", "source_record_present")
            fact = _relation_object(evidence.value, reader_authority_keys, "reader authority")
            if fact["project_id"] != event.project_id or fact["class_state"] not in {"current", "stale"} or isinstance(fact["sources"], (str, bytes, bytearray)) or not isinstance(fact["sources"], Sequence) or any(type(source) is not str for source in fact["sources"]):
                _error("reader authority fact is inconsistent", PreconditionValidationError)
            _event_id(fact["cursor_event_id"], "reader authority cursor")
            try:
                for source in fact["sources"]:
                    _event_id(source, "reader authority source")
            except EventValidationError:
                _error("reader authority fact is inconsistent", PreconditionValidationError)
            if len(set(fact["sources"])) != len(fact["sources"]):
                _error("reader authority fact is inconsistent", PreconditionValidationError)
            if event.type == "records_reader_materialized":
                source_id = event.target["rule_event_id"]
                try:
                    _event_id(fact["rule_event_id"], "reader materialization rule event")
                except EventValidationError:
                    _error("reader authority fact is inconsistent", PreconditionValidationError)
                if fact["rule_event_id"] != source_id:
                    _error("reader authority rule event does not match materialization", PreconditionValidationError)
                try:
                    subject = _parse_subject(fact["subject"], "reader materialization subject")
                except EventValidationError:
                    _error("reader authority fact is inconsistent", PreconditionValidationError)
                if subject != _parse_subject(event.target["subject"], "reader materialization target subject"):
                    _error("reader authority subject does not match materialization", PreconditionValidationError)
                if type(fact["source_record_present"]) is not bool:
                    _error("reader authority source record presence is malformed", PreconditionValidationError)
                present = source_id in fact["sources"]
                if present and not fact["source_record_present"]:
                    _error("reader authority source record presence is inconsistent", PreconditionValidationError)
                if event.payload["result"] == "add" and not fact["source_record_present"]:
                    _error("reader materialization add observes an inactive rule", PreconditionValidationError)
                if event.payload["result"] == "add" and present:
                    _error("reader materialization add observes an already-present rule", PreconditionValidationError)
                if event.payload["result"] == "withdraw" and not present:
                    _error("reader materialization withdrawal observes a missing rule", PreconditionValidationError)
            if event.type == "records_reader_materialized" and event.payload["result"] == "withdraw" and fact["class_state"] == "stale":
                _error("reader materialization withdrawal cannot use a stale authority class", PreconditionValidationError)
            continue
        if name == "active-exemption-rule-state":
            fact = _relation_object(
                evidence.value,
                ("project_id", "standing_rule_event_ids"),
                "active exemption rule state",
            )
            rule_event_ids = fact["standing_rule_event_ids"]
            if (
                fact["project_id"] != event.project_id
                or isinstance(rule_event_ids, (str, bytes, bytearray))
                or not isinstance(rule_event_ids, Sequence)
                or any(type(rule_event_id) is not str for rule_event_id in rule_event_ids)
            ):
                _error("active exemption rule state is malformed", PreconditionValidationError)
            try:
                for rule_event_id in rule_event_ids:
                    _event_id(rule_event_id, "active standing rule event")
            except EventValidationError:
                _error("active exemption rule state is malformed", PreconditionValidationError)
            if len(set(rule_event_ids)) != len(rule_event_ids):
                _error("active exemption rule state contains duplicates", PreconditionValidationError)
            if event.target["rule_event_id"] not in rule_event_ids:
                _error("active exemption rule state does not contain the referenced rule", PreconditionValidationError)
            continue
        if name == "current-derived-state":
            expected_keys = (
                "project_id",
                "standing_rule_event_ids",
                "max_continuous_exemption_rules",
                "max_state_ciphertext_bytes",
            )
            if event.type == "records_reader_rule_configured":
                expected_keys += ("max_continuous_reader_rules",)
            fact = _relation_object(
                evidence.value,
                expected_keys,
                "derived state",
            )
            rule_event_ids = fact["standing_rule_event_ids"]
            if (
                fact["project_id"] != event.project_id
                or isinstance(rule_event_ids, (str, bytes, bytearray))
                or not isinstance(rule_event_ids, Sequence)
                or any(type(rule_event_id) is not str for rule_event_id in rule_event_ids)
            ):
                _error("derived state standing rules are malformed", PreconditionValidationError)
            try:
                for rule_event_id in rule_event_ids:
                    _event_id(rule_event_id, "standing rule event")
                max_rules = _positive(fact["max_continuous_exemption_rules"], "max continuous exemption rules")
                _positive(fact["max_state_ciphertext_bytes"], "max state ciphertext bytes")
                if event.type == "records_reader_rule_configured":
                    _positive(fact["max_continuous_reader_rules"], "max continuous reader rules")
            except EventValidationError:
                _error("derived state standing rules or profile is malformed", PreconditionValidationError)
            if len(set(rule_event_ids)) != len(rule_event_ids):
                _error("derived state standing rules contain duplicates", PreconditionValidationError)
            if event.type != "records_reader_rule_configured" and len(rule_event_ids) >= max_rules:
                _error("derived state already has the maximum continuous exemption rules", PreconditionValidationError)
            continue
        if name.startswith("active-reader-rules-"):
            shard = int(name.rsplit("-", 1)[1])
            fact = _relation_object(evidence.value, ("project_id", "rule_event_ids"), name)
            rule_event_ids = fact["rule_event_ids"]
            if (
                fact["project_id"] != event.project_id
                or isinstance(rule_event_ids, (str, bytes, bytearray))
                or not isinstance(rule_event_ids, Sequence)
                or any(type(rule_event_id) is not str for rule_event_id in rule_event_ids)
            ):
                _error(f"{name} fact is inconsistent", PreconditionValidationError)
            try:
                for rule_event_id in rule_event_ids:
                    _event_id(rule_event_id, f"{name} rule event")
            except EventValidationError:
                _error(f"{name} fact is inconsistent", PreconditionValidationError)
            if len(set(rule_event_ids)) != len(rule_event_ids):
                _error(f"{name} fact contains duplicate rule events", PreconditionValidationError)
            expected_path = f"derived/reader-authority/{shard:02d}.enc.json"
            if any(_reader_shard_path(rule_event_id) != expected_path for rule_event_id in rule_event_ids):
                _error(f"{name} rule event is bound to the wrong shard", PreconditionValidationError)
            continue
        if name.startswith("current-exemption-union-"):
            shard = int(name.rsplit("-", 1)[1])
            fact = _relation_object(evidence.value, ("project_id", "subjects", "provenance"), "exemption union")
            if fact["project_id"] != event.project_id or isinstance(fact["subjects"], (str, bytes, bytearray)) or not isinstance(fact["subjects"], Sequence) or not isinstance(fact["provenance"], Mapping): _error("exemption union fact is inconsistent", PreconditionValidationError)
            subjects = () if not fact["subjects"] else _parse_subjects(fact["subjects"], "exemption union subjects")
            if set(fact["provenance"]) != {str(subject.github_user_id) for subject in subjects}:
                _error("exemption provenance does not cover the union subjects", PreconditionValidationError)
            for subject in subjects:
                if subject.github_user_id % 32 != shard:
                    _error("exemption union subject is bound to the wrong or duplicate shard", PreconditionValidationError)
            for subject_id, sources in fact["provenance"].items():
                if type(subject_id) is not str or not subject_id.isdecimal() or int(subject_id) % 32 != shard or isinstance(sources, (str, bytes, bytearray)) or not isinstance(sources, Sequence) or not sources or any(type(source) is not str for source in sources):
                    _error("exemption provenance fact is inconsistent", PreconditionValidationError)
                try:
                    for source in sources:
                        _event_id(source, "exemption provenance source")
                except EventValidationError:
                    _error("exemption provenance fact is inconsistent", PreconditionValidationError)
                if len(set(sources)) != len(sources):
                    _error("exemption provenance fact is inconsistent", PreconditionValidationError)
            if event.type == "exemption_materialized":
                subject_id = str(event.target["subject"]["github_user_id"])
                source_id = event.target["rule_event_id"]
                sources = fact["provenance"].get(subject_id, ())
                present = source_id in sources
                if event.payload["result"] == "add" and present:
                    _error("exemption materialization add observes an already-present rule", PreconditionValidationError)
                if event.payload["result"] == "withdraw" and not present:
                    _error("exemption materialization withdrawal observes a missing rule", PreconditionValidationError)
            continue
        if name == "override-grant":
            fact = _relation_object(evidence.value, ("event", "active"), "override grant")
            grant = _relation_object(fact["event"], ("event_id", "type", "project_id", "target", "payload"), "override grant event")
            if grant["event_id"] != event.target["override_event_id"] or grant["type"] != "override" or grant["project_id"] != event.project_id or fact["active"] is not True:
                _error("override grant does not match withdrawal", PreconditionValidationError)
            try:
                grant_target = grant["target"]
                if set(grant_target) != {"repository_id", "pull_request_number", "tree_oid"}:
                    raise ValueError
                _positive(grant_target["repository_id"], "override repository ID")
                _positive(grant_target["pull_request_number"], "override pull request")
                _oid(grant_target["tree_oid"], "override tree OID")
                grant_payload = grant["payload"]
                if set(grant_payload) != {"subjects", "reason", "instrument_ref"}:
                    raise ValueError
                _parse_subjects(grant_payload["subjects"], "override subjects")
                _string(grant_payload["reason"], "override reason")
                if grant_payload["instrument_ref"] is not None:
                    _string(grant_payload["instrument_ref"], "override instrument reference")
            except (EventValidationError, TypeError, ValueError):
                _error("override grant event is malformed", PreconditionValidationError)
            continue
        if name.startswith("scope-terminal-"):
            if _validate_terminal_observation(evidence.value, requirement.path):
                _error("scope terminal child already exists", PreconditionValidationError)
        elif name == "generations-absence":
            if evidence.value not in (None, {"absent": True}):
                _error("project connection requires absent generations evidence", PreconditionValidationError)
        elif name == "prior-generations":
            if not isinstance(evidence.value, Mapping) or set(evidence.value) != {"derived_index", "status_detail", "reader_authority"}: _error("prior generations evidence is malformed", PreconditionValidationError)
            for generation in evidence.value.values():
                try:
                    _event_id(generation, "prior generation")
                except EventValidationError:
                    _error("prior generations evidence is malformed", PreconditionValidationError)
        elif name == "keyring-affected-repositories":
            fact = _relation_object(
                evidence.value,
                ("project_id", "repository_ids"),
                "keyring repository set",
            )
            if fact["project_id"] != event.project_id:
                _error("keyring repository-set evidence is malformed", PreconditionValidationError)
            try:
                repository_ids = _parse_repo_ids(fact["repository_ids"], "keyring repository set")
            except EventValidationError:
                _error("keyring repository-set evidence is malformed", PreconditionValidationError)
            auth_ids = [item.resource_id for item in event.authorizations]
            if {repository_ids.records, repository_ids.coverage, repository_ids.control} != set(auth_ids) or len(auth_ids) != 3:
                _error("keyring repository set does not equal authorization resources", PreconditionValidationError)
        elif name == "current-project-agreement":
            _validate_project_agreement_fact(event, evidence.value)
        elif name == "superseded-acceptance":
            _validate_superseded_acceptance_fact(event, evidence.value)
        elif name == "current-acceptance-basis":
            _validate_acceptance_basis_fact(event, evidence.value)
        elif name in {"publication-snapshot-absence", "publication-metadata-absence"}:
            if _validate_terminal_observation(evidence.value, requirement.path):
                _error("publication artifact is already present", PreconditionValidationError)
        elif name == "current-configuration":
            if not isinstance(evidence.value, Mapping): _error("current configuration evidence is malformed", PreconditionValidationError)
            try:
                configuration = _parse_configuration(_thaw(evidence.value))
            except EventValidationError:
                _error("current configuration evidence is malformed", PreconditionValidationError)
            acceptance_fields = event.payload["fields"]
            if set(acceptance_fields) != {field.name for field in configuration.required_fields}:
                _error("acceptance fields do not match current configuration", PreconditionValidationError)
            if tuple(item["label"] for item in event.payload["confirmations"]) != configuration.confirmation_labels:
                _error("acceptance confirmations do not match current configuration", PreconditionValidationError)
        elif name in {"published-agreement", "target-activation", "scope-request", "source-event", "rule-event"}:
            _validate_link_fact(event, name, evidence.value)
        elif name == "successor-project":
            fact = _relation_object(evidence.value, ("event", "active_agreement"), "successor")
            successor = _relation_object(fact["event"], ("event_id", "type", "project_id", "target", "payload"), "successor event")
            if successor["event_id"] != event.payload["successor_connected_event_id"] or successor["type"] != "project_connected" or successor["project_id"] != event.target["successor_project_id"]:
                _error("successor connection fact does not match target project", PreconditionValidationError)
            if successor["payload"].get("successor_of") != event.project_id:
                _error("successor connection is not reciprocal", PreconditionValidationError)
            try:
                repository_ids = _parse_repo_ids(successor["payload"]["repository_ids"], "successor repository_ids")
            except (KeyError, EventValidationError):
                _error("successor repository set is malformed", PreconditionValidationError)
            binding = values["successor-project"].binding
            if not isinstance(binding, CrossProjectBinding) or set(binding.repository_ids) != {repository_ids.records, repository_ids.coverage, repository_ids.control}:
                _error("successor repository set is not registry-bound", PreconditionValidationError)
            agreement = _relation_object(fact["active_agreement"], ("project_id", "agreement_id", "version", "state"), "successor active agreement")
            if agreement["project_id"] != successor["project_id"] or agreement["state"] != "active":
                _error("successor active agreement is not active", PreconditionValidationError)
        elif name == "project-lifecycle":
            fact = _relation_object(evidence.value, ("project_id", "state", "successor_project_id"), "project lifecycle")
            if fact["project_id"] != event.project_id or fact["state"] not in {"active", "succeeded"}:
                _error("project lifecycle fact is inconsistent", PreconditionValidationError)
            if fact["state"] == "active" and fact["successor_project_id"] is not None:
                _error("active project cannot name a successor", PreconditionValidationError)
            if fact["state"] == "succeeded":
                if not isinstance(fact["successor_project_id"], str) or not fact["successor_project_id"]:
                    _error("succeeded project must name a successor", PreconditionValidationError)
                removable_scope = False
                if event.type in {"enforcement_scope_requested", "enforcement_scope_activated"}:
                    removable_scope = any(
                        item.operation in {
                            "enforcement_scope_repository_remove",
                            "enforcement_scope_organization_remove",
                        }
                        for item in event.authorizations
                    )
                removable_automation = event.type in {"exemption_materialized", "records_reader_materialized"} and event.payload.get("result") == "withdraw"
                allowed = event.type in {
                    "revocation", "keyring_activated", "retry_requested", "enforcement_scope_abandoned",
                    "records_reader_authorized", "records_reader_snapshot_authorized", "records_reader_withdrawn",
                    "records_reader_rule_configured", "records_reader_rule_withdrawn",
                } or removable_scope or removable_automation
                if not allowed:
                    _error("event is forbidden after project success", PreconditionValidationError)
        elif name == "active-agreement":
            if not isinstance(evidence.value, Mapping):
                _error("active agreement fact is malformed", PreconditionValidationError)
            if event.type == "acceptance":
                required = {
                    "project_id", "agreement_id", "version", "recipient", "digest",
                    "state", "accepted_versions", "retired_versions", "active_version",
                    "activation_event_id", "supersedes_coverage", "publication",
                }
                if set(evidence.value) != required:
                    _error("active agreement fact is missing publication evidence", PreconditionValidationError)
                fact = evidence.value
                if fact["project_id"] != event.project_id or fact["state"] != "active":
                    _error("active agreement fact is inconsistent", PreconditionValidationError)
                if (fact["agreement_id"], fact["version"], fact["active_version"]) != (
                    event.target["coverage_tuple"]["agreement_id"], event.target["version"], event.target["version"]
                ):
                    _error("active agreement does not match event target", PreconditionValidationError)
                if fact["recipient"] != event.target["recipient"] or fact["digest"] != event.target["digest"]:
                    _error("active agreement publication does not match event", PreconditionValidationError)
                accepted_versions = _version_set(fact["accepted_versions"], "active agreement accepted versions", allow_empty=False)
                retired_versions = _version_set(fact["retired_versions"], "active agreement retired versions")
                if set(accepted_versions) & set(retired_versions):
                    _error("active agreement accepted and retired versions overlap", PreconditionValidationError)
                if fact["version"] not in accepted_versions or fact["version"] in retired_versions or type(fact["supersedes_coverage"]) is not bool:
                    _error("active agreement accepted-version relation is inconsistent", PreconditionValidationError)
                _event_id(fact["activation_event_id"], "active agreement activation event")
                publication = fact["publication"]
                _validate_link_fact(event, "active-publication", publication)
            else:
                required = {
                    "agreement_id", "active_version",
                    "activation_event_id", "accepted_versions", "retired_versions",
                    "projection_format", "shard_count",
                }
                if set(evidence.value) != required:
                    _error("active agreement projection is missing or has extra fields", PreconditionValidationError)
                fact = evidence.value
                if type(fact["projection_format"]) is not int or fact["projection_format"] != 1:
                    _error("active agreement projection format is unsupported", PreconditionValidationError)
                if type(fact["shard_count"]) is not int or fact["shard_count"] != 32:
                    _error("active agreement projection shard count is unsupported", PreconditionValidationError)
                accepted_versions = _version_set(fact["accepted_versions"], "active agreement projection accepted versions")
                retired_versions = _version_set(fact["retired_versions"], "active agreement projection retired versions")
                if set(accepted_versions) & set(retired_versions):
                    _error("active agreement accepted and retired versions overlap", PreconditionValidationError)
                agreement_id = fact["agreement_id"]
                active_version = fact["active_version"]
                activation_event_id = fact["activation_event_id"]
                if not accepted_versions:
                    if agreement_id is not None or active_version is not None or activation_event_id is not None or retired_versions:
                        _error("active agreement empty projection is inconsistent", PreconditionValidationError)
                else:
                    if type(agreement_id) is not str or not agreement_id:
                        _error("active agreement projection agreement ID is malformed", PreconditionValidationError)
                    if type(active_version) is not str or not active_version:
                        _error("active agreement projection active version is malformed", PreconditionValidationError)
                    try:
                        _event_id(activation_event_id, "active agreement activation event")
                    except EventValidationError:
                        _error("active agreement projection activation event is malformed", PreconditionValidationError)
                    if active_version not in accepted_versions:
                        _error("active agreement projection active version is not accepted", PreconditionValidationError)
                    if agreement_id != event.target["agreement_id"]:
                        _error("active agreement projection does not match event agreement", PreconditionValidationError)
                if event.type == "agreement_activated":
                    target_version = event.target["version"]
                    if target_version in retired_versions:
                        _error("ordinary activation cannot revive a retired version", PreconditionValidationError)
                    expected_accepted = (
                        (target_version,)
                        if event.payload["supersedes_coverage"]
                        else _ordered_version_union(accepted_versions, (target_version,))
                    )
                    if tuple(event.payload["accepted_versions"]) != expected_accepted:
                        _error("activation accepted versions do not match the exact transition", PreconditionValidationError)
        elif name == "current-repository-owner":
            entries = _registry_entries(evidence.value, ("prior_entry", "staged_entry"), "repository owner")
            prior = entries["prior_entry"]
            staged = entries["staged_entry"]
            if prior["project_id"] != event.project_id or staged["project_id"] != event.project_id:
                _error("repository owner fact does not match event", PreconditionValidationError)
            if _parse_owner(prior["repository_owner"]) != _parse_owner(event.target["prior_repository_owner"]):
                _error("repository owner prior entry does not match event", PreconditionValidationError)
            if _parse_owner(staged["repository_owner"]) != _parse_owner(event.payload["new_repository_owner"]):
                _error("repository owner staged entry does not match event", PreconditionValidationError)
            if prior["project_slug"] != staged["project_slug"] or _parse_repo_ids(prior["repository_ids"]) != _parse_repo_ids(staged["repository_ids"]):
                _error("repository owner transition changed project routing", PreconditionValidationError)
            if prior["registry_generation"] >= staged["registry_generation"]:
                _error("repository owner transition must advance registry generation", PreconditionValidationError)
            if _parse_repo_ids(staged["repository_ids"]) != _parse_repo_ids(event.payload["repository_ids"]):
                _error("repository owner repository set does not match event", PreconditionValidationError)
            binding = evidence.binding
            if not isinstance(binding, RegistryGenerationBinding) or binding.registry_commit_oid != event.payload["registry_commit_oid"] or binding.registry_generation != event.payload["registry_generation"]:
                _error("repository owner evidence is not bound to event registry generation", PreconditionValidationError)
            if staged["project_slug"] != event.payload["project_slug"]:
                _error("repository owner project slug does not match event", PreconditionValidationError)
            if staged["registry_generation"] != event.payload["registry_generation"]:
                _error("repository owner registry entry generation does not match event", PreconditionValidationError)
        elif name == "current-scope":
            binding = evidence.binding
            if event.type == "enforcement_scope_requested":
                entries = _registry_entries(evidence.value, ("prior_entry", "current_entry"), "scope")
                prior = entries["prior_entry"]
                current = entries["current_entry"]
                expected_scope = _parse_scope(event.payload["prior_scope"], "requested prior scope")
                for entry in (prior, current):
                    if entry["project_id"] != event.project_id or _parse_scope(entry["enforcement_scope"], "current scope") != expected_scope or entry["registry_generation"] != event.payload["prior_registry_generation"]:
                        _error("scope request does not match current registry entry", PreconditionValidationError)
                if prior["project_slug"] != current["project_slug"] or _parse_repo_ids(prior["repository_ids"]) != _parse_repo_ids(current["repository_ids"]):
                    _error("scope request registry entries changed routing", PreconditionValidationError)
                expected_generation = event.payload["prior_registry_generation"]
            elif event.type == "enforcement_scope_activated":
                staged = _registry_entries(evidence.value, ("staged_entry",), "scope")["staged_entry"]
                if staged["project_id"] != event.project_id or _parse_scope(staged["enforcement_scope"], "staged scope") != _parse_scope(event.payload["desired_scope"], "activated desired scope") or staged["registry_generation"] != event.payload["registry_generation"]:
                    _error("scope activation does not match staged registry entry", PreconditionValidationError)
                if staged["request_event_links"].get(event.target["change_id"]) != event.payload["request_event_id"]:
                    _error("scope registry entry lacks the referenced request link", PreconditionValidationError)
                if not isinstance(binding, RegistryGenerationBinding) or binding.registry_commit_oid != event.payload["registry_commit_oid"] or binding.registry_generation != event.payload["registry_generation"]:
                    _error("scope activation evidence is not bound to event registry generation", PreconditionValidationError)
                expected_generation = event.payload["registry_generation"]
            else:
                current = _registry_entries(evidence.value, ("current_entry",), "scope")["current_entry"]
                request_fact = values["scope-request"]
                request_payload = request_fact.value["payload"]
                if current["project_id"] != event.project_id or _parse_scope(current["enforcement_scope"], "abandoned current scope") != _parse_scope(request_payload["prior_scope"], "abandoned prior scope") or current["registry_generation"] != request_payload["prior_registry_generation"]:
                    _error("scope abandonment does not match current registry entry", PreconditionValidationError)
                expected_generation = request_payload["prior_registry_generation"]
            if binding.registry_generation != expected_generation:
                _error("scope evidence has the wrong registry generation", PreconditionValidationError)
        elif name.startswith("coverage-state-"):
            fact = _relation_object(evidence.value, ("project_id", "state", "resource", "subject_ids"), name)
            if fact["project_id"] != event.project_id or fact["state"] not in {"current", "active"} or not isinstance(fact["resource"], Mapping):
                _error(f"{name} fact is inconsistent", PreconditionValidationError)
            if event.type in {"revocation", "override"} and fact["resource"] != event.target:
                _error(f"{name} fact does not match event target", PreconditionValidationError)
            if isinstance(fact["subject_ids"], (str, bytes, bytearray)) or not isinstance(fact["subject_ids"], Sequence) or any(type(subject_id) is not int or not 0 < subject_id <= MAX_SAFE_INTEGER for subject_id in fact["subject_ids"]):
                _error(f"{name} fact has malformed subject IDs", PreconditionValidationError)
            if len(set(fact["subject_ids"])) != len(fact["subject_ids"]) or tuple(fact["subject_ids"]) != tuple(sorted(fact["subject_ids"])):
                _error(f"{name} fact has duplicate or unordered subject IDs", PreconditionValidationError)
            shard = int(name.rsplit("-", 1)[1])
            expected_subjects = (
                {event.target["coverage_tuple"]["github_user_id"]}
                if event.type == "revocation"
                else {subject["github_user_id"] for subject in event.payload["subjects"]}
            )
            expected_shard_subjects = {subject_id for subject_id in expected_subjects if subject_id % 32 == shard}
            if set(fact["subject_ids"]) != expected_shard_subjects or any(subject_id % 32 != shard for subject_id in fact["subject_ids"]):
                _error(f"{name} fact does not authenticate the event subjects", PreconditionValidationError)
        else:
            _error("unknown precondition descriptor", PreconditionValidationError)
    for requirement in expected:
        evidence = values[requirement.name]
        _validate_generation_join(event, requirement, evidence, values)
    if event.type == "records_reader_rule_configured":
        reader_limit = values["current-derived-state"].value["max_continuous_reader_rules"]
        active_reader_rule_count = sum(
            len(values[name].value["rule_event_ids"])
            for name in values
            if name.startswith("active-reader-rules-")
        )
        if active_reader_rule_count >= reader_limit:
            _error("derived state already has the maximum continuous reader rules", PreconditionValidationError)
    if event.type in {"agreement_activated", "agreement_activation_restored"}:
        _expected_active_agreement(event, values)
    return values


def _validate_preconditions(event: ValidatedEvent, preconditions: Any, expected_head: str) -> dict[str, PreconditionEvidence]:
    """Validate evidence without leaking raw mapping/key errors."""

    try:
        return _validate_preconditions_impl(event, preconditions, expected_head)
    except KeyError as error:
        _error("precondition evidence is missing a required relation fact", PreconditionValidationError)


def _expected_active_agreement(
    event: ValidatedEvent,
    evidence: Mapping[str, PreconditionEvidence],
) -> dict[str, Any]:
    """Derive the exact active-agreement projection after a currency event."""

    if event.type not in {"agreement_activated", "agreement_activation_restored"}:
        _error("active agreement transition requires a currency event", PreconditionValidationError)
    current = evidence["active-agreement"].value
    current_accepted = tuple(current["accepted_versions"])
    current_retired = tuple(current["retired_versions"])
    accepted_versions = tuple(event.payload["accepted_versions"])
    if event.type == "agreement_activated":
        active_version = event.target["version"]
        retired_versions = (
            tuple(
                version
                for version in _ordered_version_union(current_retired, current_accepted)
                if version != active_version
            )
            if event.payload["supersedes_coverage"]
            else current_retired
        )
    else:
        active_version = evidence["target-activation"].value["target"]["version"]
        restored = set(accepted_versions)
        retired_versions = tuple(
            version
            for version in _ordered_version_union(current_retired, current_accepted)
            if version not in restored
        )
    return {
        "agreement_id": event.target["agreement_id"],
        "active_version": active_version,
        "accepted_versions": list(accepted_versions),
        "retired_versions": list(retired_versions),
        "activation_event_id": event.event_id,
        "projection_format": 1,
        "shard_count": 32,
    }


def _side_artifact_requirements(
    event: ValidatedEvent,
    evidence: Mapping[str, PreconditionEvidence],
) -> tuple[SideArtifactRequirement, ...]:
    """Build the exact side-artifact set from validated precondition facts."""

    event_type = _event_name(event)
    result: list[SideArtifactRequirement] = []
    if event_type == "agreement_published":
        payload = event.payload
        result.extend(
            (
                SideArtifactRequirement("agreement_snapshot", payload["snapshot_content_path"], "recomputed-digest"),
                SideArtifactRequirement("agreement_metadata", payload["snapshot_metadata_path"], "event-determined"),
            )
        )
    if event_type in {"agreement_activated", "agreement_activation_restored"}:
        result.append(
            SideArtifactRequirement(
                "active_agreement",
                "agreements/active.enc.json",
                "event-and-prior-state-determined",
            )
        )
    if event_type in {"project_connected", "config_updated"}:
        result.append(SideArtifactRequirement("project_config", "config/project.enc.json", "event-determined"))
    affected_classes = _affected_classes_for(event, evidence)
    if affected_classes:
        result.append(
            SideArtifactRequirement(
                "materialization_generations",
                "config/materialization-generations.enc.json",
                "event-determined",
                affected_classes,
            )
        )
    return tuple(sorted(result, key=lambda item: item.path))


def required_side_artifacts(
    event: ValidatedEvent,
    *,
    preconditions: Any,
    expected_head: str,
) -> tuple[SideArtifactRequirement, ...]:
    """Validate resolved evidence, then return the exact artifact set."""

    expected_head = _validate_head(expected_head)
    evidence = _validate_preconditions(event, preconditions, expected_head)
    return _side_artifact_requirements(event, evidence)

def _parse_event_fields(value: Any) -> tuple[int, str, str, str, str, str, str, str, Mapping[str, Any], tuple[AuthorizationEvidence, ...], str | None, Mapping[str, Any], Mapping[str, Any]]:
    obj = _object(value, "event")
    expected = ("schema_version", "project_id", "event_id", "idempotency_key", "operation_nonce", "operation_sha256", "type", "recorded_at", "dracla_version", "actor", "authorizations", "confirmed_canonical_oid", "target", "payload")
    _exact_object(obj, expected, "event")
    if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        _error("schema_version is not supported")
    project_id = _string(obj["project_id"], "project_id")
    event_type = obj["type"]
    if event_type not in EVENT_TYPES:
        _error("event type is not in the closed v1 vocabulary")
    event_id = _event_id(obj["event_id"], "event_id")
    idempotency_key = obj["idempotency_key"]
    try:
        base64url_decode(idempotency_key, expected_length=32, label="idempotency_key")
    except (Base64UrlError, TypeError):
        _error("idempotency_key must be canonical base64url for 32 bytes")
    operation_nonce = obj["operation_nonce"]
    try:
        base64url_decode(operation_nonce, expected_length=16, label="operation_nonce")
    except (Base64UrlError, TypeError):
        _error("operation_nonce must be canonical base64url for 16 bytes")
    operation_sha256 = _digest(obj["operation_sha256"], "operation_sha256")
    recorded_at = _timestamp(obj["recorded_at"], "recorded_at")
    dracla_version = _string(obj["dracla_version"], "dracla_version")
    actor = _parse_actor(obj["actor"], event_type)
    authorizations = _parse_auth_structure(obj["authorizations"], event_type)
    confirmed = obj["confirmed_canonical_oid"]
    if event_type in {"acceptance", "revocation"}:
        if confirmed is None:
            _error("acceptance and revocation require confirmed_canonical_oid")
        _oid(confirmed, "confirmed_canonical_oid")
    elif confirmed is not None:
        _error("confirmed_canonical_oid is only valid for acceptance and revocation")
    target, payload = _parse_target_payload(event_type, obj["target"], obj["payload"])
    return (event_id, project_id, idempotency_key, operation_nonce, operation_sha256, event_type, recorded_at, dracla_version, actor, authorizations, confirmed, target, payload)


def validate_event(
    value: Any,
    *,
    expected_project_id: str | None = None,
    expected_path: str | None = None,
) -> ValidatedEvent:
    """Validate one complete event and recompute all of its identity fields."""

    if isinstance(value, ValidatedEvent):
        value = value.to_dict()
    try:
        (
            event_id,
            project_id,
            idempotency_key,
            operation_nonce,
            operation_sha256,
            event_type,
            recorded_at,
            dracla_version,
            actor,
            authorizations,
            confirmed,
            target,
            payload,
        ) = _parse_event_fields(value)
        target_value = _thaw(target)
        payload_value = _thaw(payload)
        actor_value = _thaw(actor)

        # The event identity boundary intentionally has no repository-set
        # parameter.  Keyring rows are checked structurally here; all other
        # authorization rows go through the M1-4 validator.
        if event_type == "keyring_activated":
            validated_auth = authorizations
        else:
            validated_auth = validate_authorizations(
                event_type,
                target_value,
                payload_value,
                actor_value,
                [item.to_dict() for item in authorizations],
            )
        identity = derive_event_identity(
            project_id,
            operation_nonce,
            actor_value,
            event_type,
            target_value,
            payload_value,
            confirmed,
        )
        if identity.event_id != event_id or identity.idempotency_key != idempotency_key or identity.operation_sha256 != operation_sha256:
            _error("event identity fields do not match recomputed identity")
        if event_type in _AUTOMATION_TYPES:
            expected_nonce = derive_automation_nonce(
                target_value["rule_event_id"],
                payload_value["membership_evidence"]["github_user_id"],
                payload_value["result"],
                payload_value["prior_materialization_event_id"],
            )
            if operation_nonce != expected_nonce:
                _error("automation operation nonce does not match transition")
        elif event_type in {"enforcement_scope_activated", "enforcement_scope_abandoned"}:
            expected_nonce = derive_scope_terminal_nonce(payload_value["request_event_id"], event_type)
            if operation_nonce != expected_nonce:
                _error("scope terminal operation nonce does not match request")
        elif event_type == "retry_requested":
            expected_nonce = derive_github_retry_nonce(
                target_value["repository_id"],
                target_value["check_kind"],
                target_value["check_identity"],
                payload_value["github_delivery_id"],
            )
            if operation_nonce != expected_nonce:
                _error("retry operation nonce does not match delivery")
        if expected_project_id is not None and project_id != expected_project_id:
            _error("event project_id does not match expected project")
        if expected_path is not None and (type(expected_path) is not str or identity.path != expected_path):
            _error("event path does not match expected path")

        # Cross-field relations that are decidable without history.
        if event_type == "acceptance":
            coverage = _parse_coverage(target_value["coverage_tuple"])
            recipient = _parse_recipient(target_value["recipient"])
            if coverage.project_id != project_id or coverage.recipient_id != recipient.recipient_id or coverage.github_user_id != actor_value["github_user_id"]:
                _error("acceptance coverage tuple does not match event project, actor, or recipient")
        if event_type == "revocation":
            coverage = _parse_coverage(target_value["coverage_tuple"])
            if coverage.project_id != project_id or coverage.github_user_id != actor_value["github_user_id"]:
                _error("revocation coverage tuple does not match event project or actor")
        if event_type == "project_connected":
            payload_ids = _parse_repo_ids(payload_value["repository_ids"])
            bootstrap = _parse_bootstrap(payload_value["bootstrap"])
            if bootstrap.repository_ids != payload_ids:
                _error("bootstrap repository IDs do not match project connection")
        if event_type == "project_repository_owner_changed":
            prior = _parse_owner(target_value["prior_repository_owner"], "prior_repository_owner")
            new = _parse_owner(payload_value["new_repository_owner"], "new_repository_owner")
            if prior.github_account_id == new.github_account_id:
                _error("repository owner change must identify a different owner")
    except EventValidationError:
        raise
    except (EventIdentityError, TypeError, ValueError, KeyError, RecursionError):
        _error("event failed semantic validation")
    return ValidatedEvent(
        1,
        project_id,
        event_id,
        idempotency_key,
        operation_nonce,
        operation_sha256,
        event_type,
        recorded_at,
        dracla_version,
        actor,
        tuple(validated_auth),
        confirmed,
        target,
        payload,
        identity,
    )


def parse_event_jcs(
    data: bytes,
    *,
    expected_project_id: str | None = None,
    expected_path: str | None = None,
) -> ValidatedEvent:
    """Parse only exact JCS event bytes, then apply semantic validation."""

    try:
        value = parse_canonical_json(data)
    except (TypeError, ValueError, RecursionError):
        _error("event bytes are not canonical JSON")
    return validate_event(value, expected_project_id=expected_project_id, expected_path=expected_path)


__all__ = [
    "Bootstrap",
    "ConfigurationField",
    "CoverageTuple",
    "CurrentKids",
    "EVENT_TYPES",
    "EventValidationError",
    "EventsHeadBinding",
    "GenerationBinding",
    "CanonicalShaBinding",
    "CrossProjectBinding",
    "RegistryGenerationBinding",
    "PreconditionBinding",
    "PreconditionRequirement",
    "PreconditionEvidence",
    "PreconditionValidationError",
    "SideArtifactRequirement",
    "MembershipEvidence",
    "ProjectConfiguration",
    "Recipient",
    "RepositoryIds",
    "RepositoryOwner",
    "ScopeSelector",
    "Subject",
    "Team",
    "ValidatedEvent",
    "parse_event_jcs",
    "required_preconditions",
    "required_side_artifacts",
    "validate_event",
]
