"""Canonical, transport-independent replay for the M1-6 event subset.

Replay is deliberately a small state machine.  The records branch is ordered
by the commit ancestry supplied by its caller; this module neither discovers
Git history nor sorts events by a timestamp or an event identifier.  M1-7
events are rejected here so that a partially implemented fold cannot silently
give administrative events weaker semantics.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

from .canonical import canonical_json
from .events import ValidatedEvent, validate_event


_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_M1_6_TYPES = frozenset(
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
    }
)
_M1_7_TYPES = frozenset(
    {
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


class ReplayError(ValueError):
    """Base class for malformed replay inputs and rejected transitions."""


class ReplayCorruptionError(ReplayError):
    """A canonical record cannot be part of the requested complete fold."""


def _oid(value: Any, label: str) -> str:
    if type(value) is not str or _OID.fullmatch(value) is None:
        raise ReplayError(f"{label} must be a lowercase Git object ID")
    return value


def _project_id(value: Any) -> str:
    if type(value) is not str or not value:
        raise ReplayError("project_id must be a non-empty string")
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    if isinstance(value, frozenset):
        return [
            _thaw(item)
            for item in sorted(value, key=lambda item: canonical_json(_thaw(item)))
        ]
    return value


def _ordered_versions(values: Sequence[str]) -> tuple[str, ...]:
    result = tuple(values)
    if len(set(result)) != len(result):
        raise ReplayCorruptionError("agreement version set contains duplicates")
    if tuple(sorted(result, key=canonical_json)) != result:
        raise ReplayCorruptionError("agreement version set is not canonical")
    return result


def _ordered_union(*values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(set().union(*values), key=canonical_json))


@dataclass(frozen=True, slots=True)
class CanonicalEventRecord:
    """One validated event and its immutable single-parent commit binding."""

    event: ValidatedEvent
    commit_oid: str
    parent_oid: str

    def __post_init__(self) -> None:
        if not isinstance(self.event, ValidatedEvent):
            raise ReplayError("canonical record event must be a ValidatedEvent")
        _oid(self.commit_oid, "commit_oid")
        _oid(self.parent_oid, "parent_oid")
        if self.commit_oid == self.parent_oid:
            raise ReplayError("canonical record commit and parent must differ")

    @property
    def validated_event(self) -> ValidatedEvent:
        """Descriptive alias for callers that use the model's full name."""

        return self.event

    @property
    def event_id(self) -> str:
        return self.event.event_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "commit_oid": self.commit_oid,
            "parent_oid": self.parent_oid,
        }


@dataclass(frozen=True, slots=True)
class AgreementPublication:
    """Immutable publication evidence retained by the replay fold."""

    event_id: str
    agreement_id: str
    version: str
    recipient: Mapping[str, Any]
    ref: str
    content_commit_oid: str
    digest: str
    snapshot_content_path: str
    snapshot_metadata_path: str
    snapshot_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "recipient", _freeze(self.recipient))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agreement_id": self.agreement_id,
            "version": self.version,
            "recipient": _thaw(self.recipient),
            "ref": self.ref,
            "content_commit_oid": self.content_commit_oid,
            "digest": self.digest,
            "snapshot_content_path": self.snapshot_content_path,
            "snapshot_metadata_path": self.snapshot_metadata_path,
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True, slots=True)
class AgreementActivation:
    """An ordinary agreement activation that a later restore may name."""

    event_id: str
    agreement_id: str
    version: str
    published_event_id: str
    supersedes_coverage: bool
    accepted_versions: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "accepted_versions", _ordered_versions(self.accepted_versions))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agreement_id": self.agreement_id,
            "version": self.version,
            "published_event_id": self.published_event_id,
            "supersedes_coverage": self.supersedes_coverage,
            "accepted_versions": list(self.accepted_versions),
        }


@dataclass(frozen=True, slots=True)
class ActiveAgreement:
    """The O(1) agreement currency state reconstructed by replay."""

    agreement_id: str
    active_version: str
    accepted_versions: tuple[str, ...]
    retired_versions: tuple[str, ...]
    activation_event_id: str
    supersedes_coverage: bool

    def __post_init__(self) -> None:
        accepted = _ordered_versions(self.accepted_versions)
        retired = _ordered_versions(self.retired_versions)
        if not accepted or self.active_version not in accepted:
            raise ReplayError("active agreement has no accepted active version")
        if set(accepted) & set(retired):
            raise ReplayError("active agreement accepted and retired sets overlap")
        object.__setattr__(self, "accepted_versions", accepted)
        object.__setattr__(self, "retired_versions", retired)

    @property
    def version(self) -> str:
        return self.active_version

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agreement_id": self.agreement_id,
            "active_version": self.active_version,
            "accepted_versions": list(self.accepted_versions),
            "retired_versions": list(self.retired_versions),
            "activation_event_id": self.activation_event_id,
            "supersedes_coverage": self.supersedes_coverage,
        }


@dataclass(frozen=True, slots=True)
class ContributorTupleDecision:
    """Latest canonical acceptance/revocation for one immutable tuple."""

    github_user_id: int
    project_id: str
    agreement_id: str
    recipient_id: str
    decision: str
    event_id: str
    version: str | None = None
    digest: str | None = None
    supersedes: str | None = None

    def __post_init__(self) -> None:
        if self.decision not in {"covered", "uncovered"}:
            raise ReplayError("tuple decision is unsupported")
        if self.decision == "covered" and (not self.version or not self.digest):
            raise ReplayError("covered tuple decision lacks its acceptance basis")
        if self.decision == "uncovered" and (self.version is not None or self.digest is not None):
            raise ReplayError("uncovered tuple decision carries an acceptance basis")

    @property
    def is_covered(self) -> bool:
        return self.decision == "covered"

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    @property
    def tuple_key(self) -> tuple[int, str, str]:
        return (self.github_user_id, self.agreement_id, self.recipient_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "github_user_id": self.github_user_id,
            "project_id": self.project_id,
            "agreement_id": self.agreement_id,
            "recipient_id": self.recipient_id,
            "decision": self.decision,
            "event_id": self.event_id,
            "version": self.version,
            "digest": self.digest,
            "supersedes": self.supersedes,
        }


@dataclass(frozen=True, slots=True)
class ProjectLifecycle:
    """Project state and the immutable successor closure, if any."""

    project_id: str
    state: str
    successor_project_id: str | None = None
    successor_connected_event_id: str | None = None

    def __post_init__(self) -> None:
        if self.state not in {"unconnected", "active", "succeeded"}:
            raise ReplayError("project lifecycle state is unsupported")
        if self.state == "unconnected" and self.successor_project_id is not None:
            raise ReplayError("unconnected project cannot have a successor")
        if self.state == "succeeded" and not self.successor_project_id:
            raise ReplayError("succeeded project must name a successor")

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "state": self.state,
            "successor_project_id": self.successor_project_id,
            "successor_connected_event_id": self.successor_connected_event_id,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass(frozen=True, slots=True)
class ReplayState:
    """Immutable state after a canonical prefix has been folded."""

    project_id: str
    base_commit_oid: str
    current_head_oid: str
    project_state: str = "unconnected"
    successor_project_id: str | None = None
    successor_connected_event_id: str | None = None
    successor_of: str | None = None
    connected_event_id: str | None = None
    recipient: Mapping[str, Any] | None = None
    repository_owner: Mapping[str, Any] | None = None
    project_slug: str | None = None
    repository_ids: Mapping[str, Any] | None = None
    bootstrap: Mapping[str, Any] | None = None
    configuration: Mapping[str, Any] | None = None
    current_kids: Mapping[str, Any] | None = None
    keyring_generation: int | None = None
    agreement_id: str | None = None
    publications: Mapping[tuple[str, str], AgreementPublication] = field(default_factory=dict)
    activations: Mapping[str, AgreementActivation] = field(default_factory=dict)
    active_version: str | None = None
    accepted_versions: tuple[str, ...] = ()
    retired_versions: tuple[str, ...] = ()
    activation_event_id: str | None = None
    supersedes_coverage: bool | None = None
    latest_currency_transition_event_id: str | None = None
    tuple_decisions: Mapping[tuple[int, str, str], ContributorTupleDecision] = field(default_factory=dict)
    event_records: Mapping[str, CanonicalEventRecord] = field(default_factory=dict)
    unresolved: frozenset[Any] = frozenset()
    last_event_id: str | None = None
    last_commit_oid: str | None = None

    def __post_init__(self) -> None:
        _project_id(self.project_id)
        _oid(self.base_commit_oid, "base_commit_oid")
        _oid(self.current_head_oid, "current_head_oid")
        if self.project_state not in {"unconnected", "active", "succeeded"}:
            raise ReplayError("project lifecycle state is unsupported")
        if self.project_state == "unconnected" and self.event_records:
            raise ReplayError("unconnected replay state cannot contain events")
        if self.project_state == "succeeded" and not self.successor_project_id:
            raise ReplayError("succeeded replay state must name a successor")
        object.__setattr__(self, "recipient", _freeze(self.recipient) if self.recipient is not None else None)
        object.__setattr__(self, "repository_owner", _freeze(self.repository_owner) if self.repository_owner is not None else None)
        object.__setattr__(self, "repository_ids", _freeze(self.repository_ids) if self.repository_ids is not None else None)
        object.__setattr__(self, "bootstrap", _freeze(self.bootstrap) if self.bootstrap is not None else None)
        object.__setattr__(self, "configuration", _freeze(self.configuration) if self.configuration is not None else None)
        object.__setattr__(self, "current_kids", _freeze(self.current_kids) if self.current_kids is not None else None)
        object.__setattr__(self, "accepted_versions", _ordered_versions(self.accepted_versions))
        object.__setattr__(self, "retired_versions", _ordered_versions(self.retired_versions))
        if set(self.accepted_versions) & set(self.retired_versions):
            raise ReplayError("replay state accepted and retired sets overlap")
        maps = {
            "publications": self.publications,
            "activations": self.activations,
            "tuple_decisions": self.tuple_decisions,
            "event_records": self.event_records,
        }
        for name, value in maps.items():
            if not isinstance(value, Mapping):
                raise ReplayError(f"replay state {name} must be a mapping")
            object.__setattr__(self, name, MappingProxyType(dict(value)))
        if isinstance(self.unresolved, Mapping):
            # Accept the convenient ``{(subject, agreement): event_id}``
            # spelling while retaining the specified set of tuple/event
            # pairs in the immutable model.
            unresolved = frozenset((key, value) for key, value in self.unresolved.items())
            object.__setattr__(self, "unresolved", unresolved)
        elif not isinstance(self.unresolved, frozenset):
            object.__setattr__(self, "unresolved", frozenset(self.unresolved))

    @property
    def head_oid(self) -> str:
        return self.current_head_oid

    @property
    def events_head_oid(self) -> str:
        return self.current_head_oid

    @property
    def lifecycle(self) -> ProjectLifecycle:
        return project_lifecycle(self)

    @property
    def current_configuration(self) -> Mapping[str, Any] | None:
        return self.configuration

    @property
    def active_agreement(self) -> ActiveAgreement | None:
        return active_agreement(self)

    @property
    def active_agreement_id(self) -> str | None:
        return self.agreement_id

    @property
    def accepted_version_set(self) -> tuple[str, ...]:
        return self.accepted_versions

    @property
    def retired_version_set(self) -> tuple[str, ...]:
        return self.retired_versions

    @property
    def published_agreements(self) -> Mapping[tuple[str, str], AgreementPublication]:
        return self.publications

    @property
    def latest_decisions(self) -> Mapping[tuple[int, str, str], ContributorTupleDecision]:
        return self.tuple_decisions

    @property
    def currency_transition_event_id(self) -> str | None:
        return self.latest_currency_transition_event_id

    @property
    def last_event_identity(self) -> str | None:
        return self.last_event_id

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(self.event_records)

    @property
    def idempotency_keys(self) -> Mapping[str, str]:
        return MappingProxyType({record.event.idempotency_key: event_id for event_id, record in self.event_records.items()})

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "base_commit_oid": self.base_commit_oid,
            "current_head_oid": self.current_head_oid,
            "project_state": self.project_state,
            "successor_project_id": self.successor_project_id,
            "successor_connected_event_id": self.successor_connected_event_id,
            "successor_of": self.successor_of,
            "connected_event_id": self.connected_event_id,
            "recipient": _thaw(self.recipient),
            "repository_owner": _thaw(self.repository_owner),
            "project_slug": self.project_slug,
            "repository_ids": _thaw(self.repository_ids),
            "configuration": _thaw(self.configuration),
            "bootstrap": _thaw(self.bootstrap),
            "current_kids": _thaw(self.current_kids),
            "keyring_generation": self.keyring_generation,
            "agreement_id": self.agreement_id,
            "active_agreement": self.active_agreement.to_dict() if self.active_agreement else None,
            "publications": [
                item.to_dict()
                for item in sorted(self.publications.values(), key=lambda value: (value.agreement_id, value.version))
            ],
            "activations": [
                item.to_dict()
                for item in sorted(self.activations.values(), key=lambda value: value.event_id)
            ],
            "tuple_decisions": [
                decision.to_dict()
                for decision in sorted(self.tuple_decisions.values(), key=lambda value: value.tuple_key)
            ],
            "last_event_id": self.last_event_id,
            "last_commit_oid": self.last_commit_oid,
            "unresolved": [
                _thaw(item)
                for item in sorted(self.unresolved, key=lambda value: canonical_json(_thaw(value)))
            ],
        }


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Result of folding all supplied records, including whole-fold corruption."""

    state: ReplayState | None
    corruption: ReplayCorruptionError | None = None
    last_event_id: str | None = None
    last_commit_oid: str | None = None

    @property
    def valid(self) -> bool:
        return self.state is not None and self.corruption is None

    @property
    def ok(self) -> bool:
        return self.valid

    @property
    def is_valid(self) -> bool:
        return self.valid

    @property
    def corrupted(self) -> bool:
        return self.corruption is not None

    @property
    def is_corrupt(self) -> bool:
        return self.corrupted

    @property
    def error(self) -> ReplayCorruptionError | None:
        return self.corruption

    @property
    def reason(self) -> str | None:
        return str(self.corruption) if self.corruption is not None else None

    @property
    def corruption_reason(self) -> str | None:
        return self.reason

    @property
    def last_event_identity(self) -> str | None:
        return self.last_event_id

    def to_dict(self) -> dict[str, Any]:
        """Return deterministic diagnostic/result data without partial state."""

        return {
            "valid": self.valid,
            "corrupted": self.corrupted,
            "state": self.state.to_dict() if self.state is not None else None,
            "reason": self.reason,
            "last_event_id": self.last_event_id,
            "last_commit_oid": self.last_commit_oid,
        }


def initial_replay_state(project_id: str, base_commit_oid: str) -> ReplayState:
    """Create the immutable empty state rooted at the caller's commit OID."""

    return ReplayState(_project_id(project_id), _oid(base_commit_oid, "base_commit_oid"), _oid(base_commit_oid, "base_commit_oid"))


def _corrupt(message: str) -> None:
    raise ReplayCorruptionError(message)


def _tuple_key(event: ValidatedEvent) -> tuple[int, str, str]:
    coverage = event.target["coverage_tuple"]
    return (coverage["github_user_id"], coverage["agreement_id"], coverage["recipient_id"])


def _require_active(state: ReplayState, event: ValidatedEvent) -> None:
    if state.project_state == "unconnected":
        _corrupt(f"{event.type} precedes project connection")
    if state.project_state == "succeeded":
        _corrupt(f"{event.type} is forbidden after project success")


def _require_project_agreement(state: ReplayState, event: ValidatedEvent, agreement_id: str) -> None:
    if state.agreement_id is None or state.agreement_id != agreement_id:
        _corrupt("event names a second or unknown agreement")
    if state.recipient is None:
        _corrupt("project has no immutable recipient")


def _require_records_authorization(state: ReplayState, event: ValidatedEvent, operation: str) -> None:
    """Bind records-repository actions to the connected project set."""

    if state.repository_ids is None:
        _corrupt("project has no repository set")
    expected = state.repository_ids["records"]
    rows = [item for item in event.authorizations if item.operation == operation]
    if len(rows) != 1 or rows[0].resource_id != expected:
        _corrupt("records-repository authorization is not bound to this project")


def _require_keyring_authorizations(state: ReplayState, event: ValidatedEvent) -> None:
    """Require one key activation authorization for each project repository."""

    if state.repository_ids is None:
        _corrupt("project has no repository set")
    expected = {state.repository_ids["records"], state.repository_ids["coverage"], state.repository_ids["control"]}
    rows = [item for item in event.authorizations if item.operation == "keyring_activate"]
    if len(rows) != 3 or {item.resource_id for item in rows} != expected:
        _corrupt("keyring authorization set does not match this project")


def _record_state(state: ReplayState, record: CanonicalEventRecord, **changes: Any) -> ReplayState:
    records = dict(state.event_records)
    records[record.event.event_id] = record
    changes.update(
        current_head_oid=record.commit_oid,
        last_event_id=record.event.event_id,
        last_commit_oid=record.commit_oid,
        event_records=records,
    )
    return replace(state, **changes)


def _check_record(state: ReplayState, record: CanonicalEventRecord) -> ValidatedEvent:
    if not isinstance(record, CanonicalEventRecord):
        _corrupt("replay input is not a CanonicalEventRecord")
    event = record.event
    try:
        validated = validate_event(event)
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
        _corrupt("canonical record contains an invalid event")
    if validated != event:
        _corrupt("canonical record event validation changed its value")
    if event.project_id != state.project_id:
        _corrupt("event belongs to another project")
    if record.parent_oid != state.current_head_oid:
        _corrupt("canonical event ancestry does not continue the current head")
    if record.commit_oid == state.base_commit_oid:
        _corrupt("canonical event reuses the replay base commit identity")
    for previous in state.event_records.values():
        if previous.commit_oid == record.commit_oid:
            _corrupt("duplicate commit identity")
        if previous.event.idempotency_key == event.idempotency_key:
            if previous.event.operation_sha256 != event.operation_sha256:
                _corrupt("idempotency key has a conflicting operation fingerprint")
            if previous.event_id == event.event_id:
                _corrupt("duplicate event identity")
            _corrupt("duplicate idempotency identity")
    if event.event_id in state.event_records:
        _corrupt("duplicate event identity")
    if event.type in _M1_7_TYPES:
        _corrupt("M1-7 event is outside the M1-6 replay scope")
    if event.type not in _M1_6_TYPES:
        _corrupt("event type is outside the replay scope")
    if event.type in {"acceptance", "revocation"} and event.confirmed_canonical_oid != record.parent_oid:
        _corrupt("contributor event was not confirmed at its canonical parent")
    return event


def _apply_connected(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    if state.project_state != "unconnected" or state.event_records:
        _corrupt("project_connected is not the replay genesis event")
    payload = event.payload
    if payload["successor_of"] == state.project_id:
        _corrupt("project connection cannot name itself as a successor")
    bootstrap = payload["bootstrap"]
    return _record_state(
        state,
        record,
        project_state="active",
        connected_event_id=event.event_id,
        successor_of=payload["successor_of"],
        recipient=payload["recipient"],
        repository_owner=payload["repository_owner"],
        project_slug=payload["project_slug"],
        repository_ids=payload["repository_ids"],
        bootstrap=bootstrap,
        configuration=payload["project_configuration"],
        current_kids=bootstrap["current_kids"],
    )


def _apply_owner_changed(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    _require_active(state, event)
    if state.repository_owner != event.target["prior_repository_owner"]:
        _corrupt("owner transfer does not start at the current owner")
    if state.project_slug != event.payload["project_slug"]:
        _corrupt("owner transfer changes the project slug")
    if state.repository_ids != event.payload["repository_ids"]:
        _corrupt("owner transfer changes the repository set")
    return _record_state(state, record, repository_owner=event.payload["new_repository_owner"])


def _apply_succeeded(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    if state.project_state != "active":
        _corrupt("project_succeeded requires an active connected project")
    _require_records_authorization(state, record.event, "project_succeed")
    successor = event.target["successor_project_id"]
    if successor == state.project_id or state.successor_project_id is not None:
        _corrupt("project successor closure conflicts with existing lifecycle")
    return _record_state(
        state,
        record,
        project_state="succeeded",
        successor_project_id=successor,
        successor_connected_event_id=event.payload["successor_connected_event_id"],
    )


def _apply_config(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    _require_active(state, record.event)
    _require_records_authorization(state, record.event, "project_config_update")
    return _record_state(state, record, configuration=record.event.payload["project_configuration"])


def _apply_keyring(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    if state.project_state == "unconnected":
        _corrupt("keyring activation precedes project connection")
    _require_keyring_authorizations(state, record.event)
    generation = event.payload["generation"]
    if state.keyring_generation is not None and generation <= state.keyring_generation:
        _corrupt("keyring generation does not advance")
    return _record_state(
        state,
        record,
        keyring_generation=generation,
        current_kids=event.payload["current_kids"],
    )


def _apply_publication(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    _require_active(state, event)
    _require_records_authorization(state, event, "agreement_publish")
    agreement_id = event.target["agreement_id"]
    version = event.target["version"]
    if state.agreement_id is not None and state.agreement_id != agreement_id:
        _corrupt("project cannot publish a second agreement")
    if state.recipient is not None and event.payload["recipient"] != state.recipient:
        _corrupt("agreement publication changes the immutable legal recipient")
    key = (agreement_id, version)
    if key in state.publications:
        _corrupt("agreement version was published more than once")
    payload = event.payload
    publication = AgreementPublication(
        event.event_id,
        agreement_id,
        version,
        payload["recipient"],
        payload["ref"],
        payload["content_commit_oid"],
        payload["digest"],
        payload["snapshot_content_path"],
        payload["snapshot_metadata_path"],
        payload["snapshot_sha256"],
    )
    publications = dict(state.publications)
    publications[key] = publication
    return _record_state(state, record, agreement_id=agreement_id, publications=publications)


def _apply_activation(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    _require_active(state, event)
    _require_records_authorization(state, event, "agreement_activate")
    agreement_id = event.target["agreement_id"]
    version = event.target["version"]
    _require_project_agreement(state, event, agreement_id)
    publication = state.publications.get((agreement_id, version))
    if publication is None or publication.event_id != event.payload["published_event_id"]:
        _corrupt("agreement activation does not name its canonical publication")
    if publication.recipient != state.recipient:
        _corrupt("agreement activation publication has the wrong recipient")
    if version in state.retired_versions:
        _corrupt("ordinary activation cannot revive a retired version")
    supersedes = event.payload["supersedes_coverage"]
    expected = (version,) if supersedes else _ordered_union(state.accepted_versions, (version,))
    accepted = _ordered_versions(event.payload["accepted_versions"])
    if accepted != expected:
        _corrupt("activation accepted versions do not match the exact transition")
    retired = state.retired_versions
    if supersedes:
        retired = _ordered_versions(_ordered_union(state.retired_versions, state.accepted_versions))
        retired = tuple(item for item in retired if item != version)
    activation = AgreementActivation(
        event.event_id,
        agreement_id,
        version,
        event.payload["published_event_id"],
        supersedes,
        accepted,
    )
    activations = dict(state.activations)
    activations[event.event_id] = activation
    return _record_state(
        state,
        record,
        activations=activations,
        active_version=version,
        accepted_versions=accepted,
        retired_versions=retired,
        activation_event_id=event.event_id,
        supersedes_coverage=supersedes,
        latest_currency_transition_event_id=event.event_id,
    )


def _apply_restore(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    _require_active(state, event)
    _require_records_authorization(state, event, "agreement_activation_restore")
    agreement_id = event.target["agreement_id"]
    _require_project_agreement(state, event, agreement_id)
    target = state.activations.get(event.target["activation_event_id"])
    if target is None or target.agreement_id != agreement_id:
        _corrupt("restore target is not an earlier ordinary activation")
    accepted = _ordered_versions(event.payload["accepted_versions"])
    if accepted != target.accepted_versions:
        _corrupt("restore does not copy the target activation accepted versions")
    if state.active_version == target.version and state.accepted_versions == accepted:
        _corrupt("agreement restore is an unrecorded currency no-op")
    retired = _ordered_union(state.retired_versions, state.accepted_versions)
    retired = tuple(item for item in retired if item not in accepted)
    return _record_state(
        state,
        record,
        active_version=target.version,
        accepted_versions=accepted,
        retired_versions=retired,
        activation_event_id=event.event_id,
        supersedes_coverage=target.supersedes_coverage,
        latest_currency_transition_event_id=event.event_id,
    )


def _apply_acceptance(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    _require_active(state, event)
    coverage = event.target["coverage_tuple"]
    agreement_id = coverage["agreement_id"]
    _require_project_agreement(state, event, agreement_id)
    if state.active_version is None or event.target["version"] != state.active_version:
        _corrupt("acceptance targets an inactive agreement version")
    if event.target["recipient"] != state.recipient:
        _corrupt("acceptance changes the immutable legal recipient")
    publication = state.publications.get((agreement_id, event.target["version"]))
    if publication is None or publication.recipient != event.target["recipient"] or publication.digest != event.target["digest"]:
        _corrupt("acceptance does not match the published agreement")
    if state.configuration is None:
        _corrupt("acceptance precedes project configuration")
    fields = event.payload["fields"]
    expected_fields = {item["name"] for item in state.configuration["required_fields"]}
    if set(fields) != expected_fields:
        _corrupt("acceptance fields do not match current configuration")
    labels = tuple(item["label"] for item in event.payload["confirmations"])
    if labels != tuple(state.configuration["confirmation_labels"]):
        _corrupt("acceptance confirmations do not match current configuration")
    key = _tuple_key(event)
    prior = state.tuple_decisions.get(key)
    supersedes = event.payload["supersedes"]
    if supersedes is not None:
        previous = state.event_records.get(supersedes)
        if previous is None or previous.event.type != "acceptance" or prior is None or prior.event_id != supersedes:
            _corrupt("acceptance supersession does not name the current tuple acceptance")
        if _tuple_key(previous.event) != key:
            _corrupt("acceptance supersession names another contributor tuple")
    elif (
        prior is not None
        and prior.decision == "covered"
        and prior.version in state.accepted_versions
    ):
        _corrupt("covered contributor acceptance requires a correction link")
    decisions = dict(state.tuple_decisions)
    decisions[key] = ContributorTupleDecision(
        coverage["github_user_id"],
        state.project_id,
        agreement_id,
        coverage["recipient_id"],
        "covered",
        event.event_id,
        event.target["version"],
        event.target["digest"],
        supersedes,
    )
    return _record_state(state, record, tuple_decisions=decisions)


def _apply_revocation(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    event = record.event
    if state.project_state == "unconnected":
        _corrupt("revocation precedes project connection")
    coverage = event.target["coverage_tuple"]
    _require_project_agreement(state, event, coverage["agreement_id"])
    if event.target["coverage_tuple"]["recipient_id"] != state.recipient["recipient_id"]:
        _corrupt("revocation changes the immutable legal recipient")
    key = _tuple_key(event)
    prior = state.tuple_decisions.get(key)
    if prior is None:
        _corrupt("revocation has no prior contributor acceptance")
    if prior.decision == "uncovered":
        _corrupt("duplicate revocation has no canonical effect")
    decisions = dict(state.tuple_decisions)
    decisions[key] = ContributorTupleDecision(
        coverage["github_user_id"],
        state.project_id,
        coverage["agreement_id"],
        coverage["recipient_id"],
        "uncovered",
        event.event_id,
    )
    return _record_state(state, record, tuple_decisions=decisions)


def apply_event(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    """Apply one record, rejecting any invalid transition as corruption."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    _check_record(state, record)
    event_type = record.event.type
    if event_type == "project_connected":
        return _apply_connected(state, record)
    if event_type == "project_repository_owner_changed":
        return _apply_owner_changed(state, record)
    if event_type == "project_succeeded":
        return _apply_succeeded(state, record)
    if event_type == "config_updated":
        return _apply_config(state, record)
    if event_type == "keyring_activated":
        return _apply_keyring(state, record)
    if event_type == "agreement_published":
        return _apply_publication(state, record)
    if event_type == "agreement_activated":
        return _apply_activation(state, record)
    if event_type == "agreement_activation_restored":
        return _apply_restore(state, record)
    if event_type == "acceptance":
        return _apply_acceptance(state, record)
    if event_type == "revocation":
        return _apply_revocation(state, record)
    _corrupt("event type is not implemented by M1-6 replay")


def replay_events(project_id: str, base_commit_oid: str, records: Iterable[CanonicalEventRecord]) -> ReplayResult:
    """Fold records in caller-supplied ancestry order.

    Corruption is returned as a whole-fold result with no partially replayed
    state.  The last successfully folded event identity remains available for
    diagnostics and generation bindings.
    """

    state = initial_replay_state(project_id, base_commit_oid)
    if isinstance(records, (str, bytes, bytearray)) or not isinstance(records, Iterable):
        raise ReplayError("records must be an ordered sequence")
    for record in records:
        try:
            state = apply_event(state, record)
        except ReplayCorruptionError as error:
            return ReplayResult(None, error, state.last_event_id, state.last_commit_oid)
    return ReplayResult(state, None, state.last_event_id, state.last_commit_oid)


def project_lifecycle(state: ReplayState) -> ProjectLifecycle:
    """Return the immutable project lifecycle reconstructed by replay."""

    return ProjectLifecycle(
        state.project_id,
        state.project_state,
        state.successor_project_id,
        state.successor_connected_event_id,
    )


def current_configuration(state: ReplayState) -> Mapping[str, Any] | None:
    """Return the current configuration without exposing mutable state."""

    return state.configuration


def active_agreement(state: ReplayState) -> ActiveAgreement | None:
    """Return current agreement currency, or ``None`` before activation."""

    if state.agreement_id is None or state.active_version is None or state.activation_event_id is None:
        return None
    return ActiveAgreement(
        state.agreement_id,
        state.active_version,
        state.accepted_versions,
        state.retired_versions,
        state.activation_event_id,
        bool(state.supersedes_coverage),
    )


def _coerce_tuple(
    value: Any,
    *,
    project_id: str,
    agreement_id: str | None = None,
    recipient_id: str | None = None,
) -> tuple[int, str, str]:
    if isinstance(value, Mapping):
        if value.get("project_id", project_id) != project_id:
            raise ReplayError("contributor tuple query belongs to another project")
        return (value["github_user_id"], value["agreement_id"], value["recipient_id"])
    if hasattr(value, "github_user_id") and hasattr(value, "agreement_id") and hasattr(value, "recipient_id"):
        if getattr(value, "project_id", project_id) != project_id:
            raise ReplayError("contributor tuple query belongs to another project")
        return (value.github_user_id, value.agreement_id, value.recipient_id)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) and len(value) == 3:
        return tuple(value)  # type: ignore[return-value]
    if agreement_id is not None and recipient_id is not None:
        return (value, agreement_id, recipient_id)
    raise ReplayError("contributor tuple query requires a coverage tuple")


def latest_contributor_tuple_decision(
    state: ReplayState,
    coverage_tuple: Any = None,
    agreement_id: str | None = None,
    recipient_id: str | None = None,
    github_user_id: int | None = None,
) -> ContributorTupleDecision | None:
    """Return the latest acceptance/revocation for one tuple.

    The result is the canonical tuple decision, before the active agreement's
    bounded accepted-version test.  Callers that need effective coverage can
    additionally require an acceptance version in ``accepted_versions``.
    """

    if coverage_tuple is None:
        if github_user_id is None:
            raise ReplayError("contributor tuple query requires github_user_id")
        key = _coerce_tuple(
            github_user_id,
            project_id=state.project_id,
            agreement_id=agreement_id,
            recipient_id=recipient_id,
        )
    else:
        key = _coerce_tuple(
            coverage_tuple,
            project_id=state.project_id,
            agreement_id=agreement_id,
            recipient_id=recipient_id,
        )
    return state.tuple_decisions.get(key)


def effective_contributor_tuple_decision(
    state: ReplayState,
    coverage_tuple: Any,
) -> ContributorTupleDecision | None:
    """Return the tuple decision after the active-version cutoff is applied."""

    decision = latest_contributor_tuple_decision(state, coverage_tuple)
    if decision is None or decision.decision == "uncovered":
        return decision
    if decision.version not in state.accepted_versions:
        return replace(decision, decision="uncovered", version=None, digest=None)
    return decision


__all__ = [
    "ActiveAgreement",
    "AgreementActivation",
    "AgreementPublication",
    "CanonicalEventRecord",
    "ContributorTupleDecision",
    "ProjectLifecycle",
    "ReplayCorruptionError",
    "ReplayError",
    "ReplayResult",
    "ReplayState",
    "active_agreement",
    "apply_event",
    "current_configuration",
    "effective_contributor_tuple_decision",
    "initial_replay_state",
    "latest_contributor_tuple_decision",
    "project_lifecycle",
    "replay_events",
]
