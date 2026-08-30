"""Closed revision-14 event models and event identity validation.

This module is deliberately a local boundary.  It validates complete events
and recomputes their byte-level identity.  It never fetches repositories,
decrypts artifacts, or folds events.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from .artifacts import segment
from .canonical import MAX_SAFE_INTEGER, canonical_json, parse_canonical_json
from .encoding import Base64UrlError, base64url_decode
from .event_identity import (
    AuthorizationEvidence,
    EventIdentity,
    EventIdentityError,
    derive_event_identity,
    derive_automation_nonce,
    derive_github_retry_nonce,
    derive_scope_terminal_nonce,
    stable_actor_identity,
    validate_authorizations,
)


class EventValidationError(ValueError):
    """An event is not a closed, semantically valid v1 event."""


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
    "validate_event",
]
