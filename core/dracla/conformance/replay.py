"""Canonical, transport-independent replay for revision-14 events.

Replay is deliberately a small state machine.  The records branch is ordered
by the commit ancestry supplied by its caller; this module neither discovers
Git history nor sorts events by a timestamp or an event identifier.  During
the stacked M1-7 delivery, event families not yet implemented remain rejected
so a partial fold cannot silently assign them weaker semantics.
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
_M1_7_A_TYPES = frozenset(
    {
        "enforcement_scope_requested",
        "enforcement_scope_activated",
        "enforcement_scope_abandoned",
        "override",
        "override_withdrawn",
        "retry_requested",
    }
)
_M1_7_B_TYPES = frozenset(
    {
        "exemption",
        "exemption_snapshot",
        "exemption_source_withdrawn",
        "exemption_rule_configured",
        "exemption_rule_withdrawn",
        "exemption_materialized",
    }
)
_IMPLEMENTED_TYPES = _M1_6_TYPES | _M1_7_A_TYPES | _M1_7_B_TYPES


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
class ScopeRequest:
    """Durable scope intent and its optional terminal outcome."""

    event_id: str
    change_id: str
    prior_scope: tuple[Mapping[str, Any], ...]
    desired_scope: tuple[Mapping[str, Any], ...]
    prior_registry_generation: int
    authorization_relation: tuple[str, str, int, str]
    terminal_event_id: str | None = None
    terminal_kind: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "prior_scope", tuple(_freeze(item) for item in self.prior_scope))
        object.__setattr__(self, "desired_scope", tuple(_freeze(item) for item in self.desired_scope))
        if (self.terminal_event_id is None) != (self.terminal_kind is None):
            raise ReplayError("scope request terminal identity is incomplete")
        if self.terminal_kind not in {None, "activated", "abandoned"}:
            raise ReplayError("scope request terminal kind is unsupported")

    @property
    def pending(self) -> bool:
        return self.terminal_event_id is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "change_id": self.change_id,
            "prior_scope": [_thaw(item) for item in self.prior_scope],
            "desired_scope": [_thaw(item) for item in self.desired_scope],
            "prior_registry_generation": self.prior_registry_generation,
            "authorization_relation": list(self.authorization_relation),
            "terminal_event_id": self.terminal_event_id,
            "terminal_kind": self.terminal_kind,
        }


@dataclass(frozen=True, slots=True)
class EffectiveEnforcementScope:
    """The activated scope and registry generation reconstructed by replay."""

    selectors: tuple[Mapping[str, Any], ...] = ()
    registry_generation: int | None = None
    activation_event_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "selectors", tuple(_freeze(item) for item in self.selectors))
        if self.activation_event_id is not None and self.registry_generation is None:
            raise ReplayError("effective scope activation lacks a registry generation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "selectors": [_thaw(item) for item in self.selectors],
            "registry_generation": self.registry_generation,
            "activation_event_id": self.activation_event_id,
        }


@dataclass(frozen=True, slots=True)
class OverrideGrant:
    """One head-specific grant and its optional whole-grant withdrawal."""

    event_id: str
    repository_id: int
    pull_request_number: int
    tree_oid: str
    subjects: tuple[Mapping[str, Any], ...]
    reason: str
    instrument_ref: str | None
    withdrawal_event_id: str | None = None
    withdrawal_reason: str | None = None
    withdrawal_instrument_ref: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "subjects", tuple(_freeze(item) for item in self.subjects))
        if self.withdrawal_event_id is None and (
            self.withdrawal_reason is not None or self.withdrawal_instrument_ref is not None
        ):
            raise ReplayError("override withdrawal evidence lacks an event identity")

    @property
    def active(self) -> bool:
        return self.withdrawal_event_id is None

    @property
    def key_inputs(self) -> tuple[int, int, str]:
        return (self.repository_id, self.pull_request_number, self.tree_oid)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "repository_id": self.repository_id,
            "pull_request_number": self.pull_request_number,
            "tree_oid": self.tree_oid,
            "subjects": [_thaw(item) for item in self.subjects],
            "reason": self.reason,
            "instrument_ref": self.instrument_ref,
            "withdrawal_event_id": self.withdrawal_event_id,
            "withdrawal_reason": self.withdrawal_reason,
            "withdrawal_instrument_ref": self.withdrawal_instrument_ref,
        }


@dataclass(frozen=True, slots=True)
class ExemptionSource:
    """One independently withdrawable member of a subject exemption union."""

    source_event_id: str
    subject: Mapping[str, Any]
    source_kind: str
    team: Mapping[str, Any] | None
    basis: str | None
    instrument_ref: str | None
    rule_event_id: str | None
    added_event_id: str
    sequence: int

    def __post_init__(self) -> None:
        if self.source_kind not in {"bot", "individual", "snapshot", "continuous_team"}:
            raise ReplayError("exemption source kind is unsupported")
        object.__setattr__(self, "subject", _freeze(self.subject))
        object.__setattr__(self, "team", _freeze(self.team) if self.team is not None else None)

    @property
    def github_user_id(self) -> int:
        return self.subject["github_user_id"]

    @property
    def source_key(self) -> tuple[str, int]:
        return (self.source_event_id, self.github_user_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_event_id": self.source_event_id,
            "subject": _thaw(self.subject),
            "source_kind": self.source_kind,
            "team": _thaw(self.team),
            "basis": self.basis,
            "instrument_ref": self.instrument_ref,
            "rule_event_id": self.rule_event_id,
            "added_event_id": self.added_event_id,
            "sequence": self.sequence,
        }


@dataclass(frozen=True, slots=True)
class ExemptionRule:
    """A continuous-team rule and its per-subject transition cursors."""

    event_id: str
    team: Mapping[str, Any]
    basis: str
    instrument_ref: str
    materialization_cursors: Mapping[int, str] = field(default_factory=dict)
    withdrawal_event_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "team", _freeze(self.team))
        object.__setattr__(
            self,
            "materialization_cursors",
            MappingProxyType(dict(self.materialization_cursors)),
        )

    @property
    def active(self) -> bool:
        return self.withdrawal_event_id is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "team": _thaw(self.team),
            "basis": self.basis,
            "instrument_ref": self.instrument_ref,
            "materialization_cursors": {
                str(key): value for key, value in self.materialization_cursors.items()
            },
            "withdrawal_event_id": self.withdrawal_event_id,
        }


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
    scope_requests: Mapping[str, ScopeRequest] = field(default_factory=dict)
    enforcement_scope: tuple[Mapping[str, Any], ...] = ()
    enforcement_scope_registry_generation: int | None = None
    enforcement_scope_activation_event_id: str | None = None
    override_grants: Mapping[str, OverrideGrant] = field(default_factory=dict)
    retry_events: tuple[str, ...] = ()
    exemption_source_records: Mapping[tuple[str, int], ExemptionSource] = field(default_factory=dict)
    exemption_rules: Mapping[str, ExemptionRule] = field(default_factory=dict)
    known_exemption_sources: frozenset[tuple[str, int]] = frozenset()
    exemption_sequence_next: Mapping[int, int] = field(default_factory=dict)
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
        object.__setattr__(self, "enforcement_scope", tuple(_freeze(item) for item in self.enforcement_scope))
        object.__setattr__(self, "retry_events", tuple(self.retry_events))
        object.__setattr__(self, "known_exemption_sources", frozenset(self.known_exemption_sources))
        if set(self.accepted_versions) & set(self.retired_versions):
            raise ReplayError("replay state accepted and retired sets overlap")
        if self.enforcement_scope_activation_event_id is not None and self.enforcement_scope_registry_generation is None:
            raise ReplayError("effective scope activation lacks a registry generation")
        maps = {
            "publications": self.publications,
            "activations": self.activations,
            "tuple_decisions": self.tuple_decisions,
            "scope_requests": self.scope_requests,
            "override_grants": self.override_grants,
            "exemption_source_records": self.exemption_source_records,
            "exemption_rules": self.exemption_rules,
            "exemption_sequence_next": self.exemption_sequence_next,
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
            "scope_requests": [item.to_dict() for item in self.scope_requests.values()],
            "effective_enforcement_scope": self.effective_enforcement_scope.to_dict(),
            "override_grants": [item.to_dict() for item in self.override_grants.values()],
            "retry_events": list(self.retry_events),
            "exemption_sources": [item.to_dict() for item in self.exemption_source_records.values()],
            "exemption_rules": [item.to_dict() for item in self.exemption_rules.values()],
            "known_exemption_sources": [list(item) for item in sorted(self.known_exemption_sources)],
            "exemption_sequence_next": {
                str(key): value for key, value in sorted(self.exemption_sequence_next.items())
            },
            "last_event_id": self.last_event_id,
            "last_commit_oid": self.last_commit_oid,
            "unresolved": [
                _thaw(item)
                for item in sorted(self.unresolved, key=lambda value: canonical_json(_thaw(value)))
            ],
        }

    @property
    def effective_enforcement_scope(self) -> EffectiveEnforcementScope:
        return EffectiveEnforcementScope(
            self.enforcement_scope,
            self.enforcement_scope_registry_generation,
            self.enforcement_scope_activation_event_id,
        )


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


class _ReplayAccumulator:
    """Mutable working state used only while folding a complete replay."""

    __slots__ = (
        "project_id",
        "base_commit_oid",
        "current_head_oid",
        "project_state",
        "successor_project_id",
        "successor_connected_event_id",
        "successor_of",
        "connected_event_id",
        "recipient",
        "repository_owner",
        "project_slug",
        "repository_ids",
        "bootstrap",
        "configuration",
        "current_kids",
        "keyring_generation",
        "agreement_id",
        "publications",
        "activations",
        "active_version",
        "accepted_versions",
        "retired_versions",
        "activation_event_id",
        "supersedes_coverage",
        "latest_currency_transition_event_id",
        "tuple_decisions",
        "scope_requests",
        "enforcement_scope",
        "enforcement_scope_registry_generation",
        "enforcement_scope_activation_event_id",
        "override_grants",
        "retry_events",
        "exemption_source_records",
        "exemption_rules",
        "known_exemption_sources",
        "exemption_sequence_next",
        "event_records",
        "unresolved",
        "last_event_id",
        "last_commit_oid",
        "_commit_index",
        "_idempotency_index",
        "_owner_transfer_commit_index",
        "_last_owner_transfer_generation",
        "_scope_change_index",
        "_scope_registry_commit_index",
    )

    def __init__(self, state: ReplayState) -> None:
        self.project_id = state.project_id
        self.base_commit_oid = state.base_commit_oid
        self.current_head_oid = state.current_head_oid
        self.project_state = state.project_state
        self.successor_project_id = state.successor_project_id
        self.successor_connected_event_id = state.successor_connected_event_id
        self.successor_of = state.successor_of
        self.connected_event_id = state.connected_event_id
        self.recipient = state.recipient
        self.repository_owner = state.repository_owner
        self.project_slug = state.project_slug
        self.repository_ids = state.repository_ids
        self.bootstrap = state.bootstrap
        self.configuration = state.configuration
        self.current_kids = state.current_kids
        self.keyring_generation = state.keyring_generation
        self.agreement_id = state.agreement_id
        self.publications = dict(state.publications)
        self.activations = dict(state.activations)
        self.active_version = state.active_version
        self.accepted_versions = state.accepted_versions
        self.retired_versions = state.retired_versions
        self.activation_event_id = state.activation_event_id
        self.supersedes_coverage = state.supersedes_coverage
        self.latest_currency_transition_event_id = state.latest_currency_transition_event_id
        self.tuple_decisions = dict(state.tuple_decisions)
        self.scope_requests = dict(state.scope_requests)
        self.enforcement_scope = state.enforcement_scope
        self.enforcement_scope_registry_generation = state.enforcement_scope_registry_generation
        self.enforcement_scope_activation_event_id = state.enforcement_scope_activation_event_id
        self.override_grants = dict(state.override_grants)
        self.retry_events = state.retry_events
        self.exemption_source_records = dict(state.exemption_source_records)
        self.exemption_rules = dict(state.exemption_rules)
        self.known_exemption_sources = state.known_exemption_sources
        self.exemption_sequence_next = dict(state.exemption_sequence_next)
        self.event_records = dict(state.event_records)
        self.unresolved = state.unresolved
        self.last_event_id = state.last_event_id
        self.last_commit_oid = state.last_commit_oid
        self._commit_index: dict[str, CanonicalEventRecord] = {}
        self._idempotency_index: dict[str, CanonicalEventRecord] = {}
        self._owner_transfer_commit_index: dict[str, CanonicalEventRecord] = {}
        self._last_owner_transfer_generation: int | None = None
        self._scope_change_index = {
            request.change_id: request.event_id for request in state.scope_requests.values()
        }
        self._scope_registry_commit_index = {
            record.event.payload["registry_commit_oid"]: record.event_id
            for record in state.event_records.values()
            if record.event.type == "enforcement_scope_activated"
        }

    def freeze(self) -> ReplayState:
        """Materialize one immutable public state after a successful fold."""

        return ReplayState(
            self.project_id,
            self.base_commit_oid,
            self.current_head_oid,
            project_state=self.project_state,
            successor_project_id=self.successor_project_id,
            successor_connected_event_id=self.successor_connected_event_id,
            successor_of=self.successor_of,
            connected_event_id=self.connected_event_id,
            recipient=self.recipient,
            repository_owner=self.repository_owner,
            project_slug=self.project_slug,
            repository_ids=self.repository_ids,
            bootstrap=self.bootstrap,
            configuration=self.configuration,
            current_kids=self.current_kids,
            keyring_generation=self.keyring_generation,
            agreement_id=self.agreement_id,
            publications=self.publications,
            activations=self.activations,
            active_version=self.active_version,
            accepted_versions=self.accepted_versions,
            retired_versions=self.retired_versions,
            activation_event_id=self.activation_event_id,
            supersedes_coverage=self.supersedes_coverage,
            latest_currency_transition_event_id=self.latest_currency_transition_event_id,
            tuple_decisions=self.tuple_decisions,
            scope_requests=self.scope_requests,
            enforcement_scope=self.enforcement_scope,
            enforcement_scope_registry_generation=self.enforcement_scope_registry_generation,
            enforcement_scope_activation_event_id=self.enforcement_scope_activation_event_id,
            override_grants=self.override_grants,
            retry_events=self.retry_events,
            exemption_source_records=self.exemption_source_records,
            exemption_rules=self.exemption_rules,
            known_exemption_sources=self.known_exemption_sources,
            exemption_sequence_next=self.exemption_sequence_next,
            event_records=self.event_records,
            unresolved=self.unresolved,
            last_event_id=self.last_event_id,
            last_commit_oid=self.last_commit_oid,
        )


def initial_replay_state(project_id: str, base_commit_oid: str) -> ReplayState:
    """Create the immutable empty state rooted at the caller's commit OID."""

    return ReplayState(_project_id(project_id), _oid(base_commit_oid, "base_commit_oid"), _oid(base_commit_oid, "base_commit_oid"))


def _corrupt(message: str) -> None:
    raise ReplayCorruptionError(message)


def _tuple_key(event: ValidatedEvent) -> tuple[int, str, str]:
    coverage = event.target["coverage_tuple"]
    return (coverage["github_user_id"], coverage["agreement_id"], coverage["recipient_id"])


def _require_active(state: ReplayState | _ReplayAccumulator, event: ValidatedEvent) -> None:
    if state.project_state == "unconnected":
        _corrupt(f"{event.type} precedes project connection")
    if state.project_state == "succeeded":
        _corrupt(f"{event.type} is forbidden after project success")


def _require_project_agreement(
    state: ReplayState | _ReplayAccumulator,
    event: ValidatedEvent,
    agreement_id: str,
) -> None:
    if state.agreement_id is None or state.agreement_id != agreement_id:
        _corrupt("event names a second or unknown agreement")
    if state.recipient is None:
        _corrupt("project has no immutable recipient")


def _require_records_authorization(
    state: ReplayState | _ReplayAccumulator,
    event: ValidatedEvent,
    operation: str,
) -> None:
    """Bind records-repository actions to the connected project set."""

    if state.repository_ids is None:
        _corrupt("project has no repository set")
    expected = state.repository_ids["records"]
    rows = [item for item in event.authorizations if item.operation == operation]
    if len(rows) != 1 or rows[0].resource_id != expected:
        _corrupt("records-repository authorization is not bound to this project")


def _require_keyring_authorizations(
    state: ReplayState | _ReplayAccumulator,
    event: ValidatedEvent,
) -> None:
    """Require one key activation authorization for each project repository."""

    if state.repository_ids is None:
        _corrupt("project has no repository set")
    expected = {state.repository_ids["records"], state.repository_ids["coverage"], state.repository_ids["control"]}
    rows = [item for item in event.authorizations if item.operation == "keyring_activate"]
    if len(rows) != 3 or {item.resource_id for item in rows} != expected:
        _corrupt("keyring authorization set does not match this project")


def _authorization_relation(event: ValidatedEvent) -> tuple[str, str, int, str]:
    """Return the one-row administrative authorization relation."""

    if len(event.authorizations) != 1:
        _corrupt(f"{event.type} does not carry one authorization relation")
    item = event.authorizations[0]
    return (item.operation, item.resource_kind, item.resource_id, item.required_authority)


def _require_authorized_repository(event: ValidatedEvent, repository_id: int) -> None:
    relation = _authorization_relation(event)
    if relation[1] != "repository" or relation[2] != repository_id:
        _corrupt(f"{event.type} authorization is not bound to its target repository")


def _require_m17_lifecycle(
    state: ReplayState | _ReplayAccumulator,
    event: ValidatedEvent,
) -> None:
    """Apply the closed post-success allowlist shared with preconditions."""

    if state.project_state == "unconnected":
        _corrupt(f"{event.type} precedes project connection")
    if state.project_state != "succeeded":
        return
    if event.type in {"retry_requested", "enforcement_scope_abandoned"}:
        return
    if event.type == "exemption_materialized" and event.payload["result"] == "withdraw":
        return
    if event.type in {"enforcement_scope_requested", "enforcement_scope_activated"}:
        operation = _authorization_relation(event)[0]
        if operation.endswith(("_narrow", "_remove")):
            return
    _corrupt(f"{event.type} is forbidden after project success")


def _scope_tuple(value: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    return tuple(_freeze(item) for item in value)


def _scope_identity(selector: Mapping[str, Any]) -> tuple[str, int]:
    if selector["kind"] == "repository":
        return ("repository", selector["repository_id"])
    return ("organization", selector["organization_id"])


def _check_scope_change(event: ValidatedEvent) -> tuple[str, str, int, str]:
    """Bind a scope operation to the one selector identity it changes."""

    prior = {_scope_identity(item): item for item in event.payload["prior_scope"]}
    desired = {_scope_identity(item): item for item in event.payload["desired_scope"]}
    if prior == desired:
        _corrupt("scope request is an unrecorded semantic no-op")
    changed = set(prior) ^ set(desired)
    if len(changed) != 1:
        _corrupt("scope request must change exactly one selector identity")
    relation = _authorization_relation(event)
    operation, resource_kind, resource_id, _ = relation
    changed_kind, changed_id = next(iter(changed))
    if (resource_kind, resource_id) != (changed_kind, changed_id):
        _corrupt("scope authorization does not name the changed selector")
    if f"enforcement_scope_{resource_kind}_" not in operation:
        _corrupt("scope operation does not match the changed selector kind")
    added = (changed_kind, changed_id) in desired
    if operation.endswith(("_bind", "_widen")) != added:
        _corrupt("scope operation direction does not match the selector change")
    return relation


def _find_scope_change(
    state: ReplayState | _ReplayAccumulator,
    change_id: str,
) -> str | None:
    if isinstance(state, _ReplayAccumulator):
        return state._scope_change_index.get(change_id)
    for request in state.scope_requests.values():
        if request.change_id == change_id:
            return request.event_id
    return None


def _scope_registry_commit_used(
    state: ReplayState | _ReplayAccumulator,
    commit_oid: str,
) -> bool:
    if isinstance(state, _ReplayAccumulator):
        return commit_oid in state._scope_registry_commit_index
    return any(
        record.event.type == "enforcement_scope_activated"
        and record.event.payload["registry_commit_oid"] == commit_oid
        for record in state.event_records.values()
    )


def _subject_id(subject: Mapping[str, Any]) -> int:
    return subject["github_user_id"]


def _make_exemption_source(
    *,
    source_event_id: str,
    subject: Mapping[str, Any],
    source_kind: str,
    team: Mapping[str, Any] | None,
    basis: str | None,
    instrument_ref: str | None,
    rule_event_id: str | None,
    added_event_id: str,
    sequence: int,
) -> ExemptionSource:
    return ExemptionSource(
        source_event_id,
        subject,
        source_kind,
        team,
        basis,
        instrument_ref,
        rule_event_id,
        added_event_id,
        sequence,
    )


def _manual_exemption_subject(
    state: ReplayState | _ReplayAccumulator,
    source_event_id: str,
    subject: Mapping[str, Any],
) -> bool:
    """Return whether a manual/snapshot source created the exact subject."""

    origin = state.event_records.get(source_event_id)
    if origin is None:
        return False
    event = origin.event
    if event.type == "exemption":
        return event.target["subject"] == subject
    if event.type == "exemption_snapshot":
        return subject in event.target["subjects"]
    return False


def _record_state(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
    **changes: Any,
) -> ReplayState | _ReplayAccumulator:
    if isinstance(state, _ReplayAccumulator):
        state.event_records[record.event.event_id] = record
        state._commit_index[record.commit_oid] = record
        state._idempotency_index[record.event.idempotency_key] = record
        if record.event.type == "project_repository_owner_changed":
            state._owner_transfer_commit_index[record.event.payload["registry_commit_oid"]] = record
            state._last_owner_transfer_generation = record.event.payload["registry_generation"]
        elif record.event.type == "enforcement_scope_requested":
            state._scope_change_index[record.event.target["change_id"]] = record.event_id
        elif record.event.type == "enforcement_scope_activated":
            state._scope_registry_commit_index[record.event.payload["registry_commit_oid"]] = record.event_id
        state.current_head_oid = record.commit_oid
        state.last_event_id = record.event.event_id
        state.last_commit_oid = record.commit_oid
        for name, value in changes.items():
            setattr(state, name, value)
        return state
    records = dict(state.event_records)
    records[record.event.event_id] = record
    changes.update(
        current_head_oid=record.commit_oid,
        last_event_id=record.event.event_id,
        last_commit_oid=record.commit_oid,
        event_records=records,
    )
    return replace(state, **changes)


def _check_record(state: ReplayState | _ReplayAccumulator, record: CanonicalEventRecord) -> ValidatedEvent:
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
    if isinstance(state, _ReplayAccumulator):
        previous_commit = state._commit_index.get(record.commit_oid)
        if previous_commit is not None:
            _corrupt("duplicate commit identity")
        previous_idempotency = state._idempotency_index.get(event.idempotency_key)
        if previous_idempotency is not None:
            if previous_idempotency.event.operation_sha256 != event.operation_sha256:
                _corrupt("idempotency key has a conflicting operation fingerprint")
            if previous_idempotency.event_id == event.event_id:
                _corrupt("duplicate event identity")
            _corrupt("duplicate idempotency identity")
    else:
        duplicate_commit = False
        previous_idempotency = None
        for previous in state.event_records.values():
            if previous.commit_oid == record.commit_oid:
                duplicate_commit = True
            if previous.event.idempotency_key == event.idempotency_key:
                previous_idempotency = previous
        if duplicate_commit:
            _corrupt("duplicate commit identity")
        if previous_idempotency is not None:
            if previous_idempotency.event.operation_sha256 != event.operation_sha256:
                _corrupt("idempotency key has a conflicting operation fingerprint")
            if previous_idempotency.event_id == event.event_id:
                _corrupt("duplicate event identity")
            _corrupt("duplicate idempotency identity")
    if event.event_id in state.event_records:
        _corrupt("duplicate event identity")
    if event.type in _M1_7_TYPES - _M1_7_A_TYPES - _M1_7_B_TYPES:
        _corrupt("M1-7 event family is not enabled by this replay slice")
    if event.type not in _IMPLEMENTED_TYPES:
        _corrupt("event type is outside the replay scope")
    if event.type in {"acceptance", "revocation"} and event.confirmed_canonical_oid != record.parent_oid:
        _corrupt("contributor event was not confirmed at its canonical parent")
    return event


def _map_item(
    state: ReplayState | _ReplayAccumulator,
    name: str,
    key: Any,
    value: Any,
) -> Mapping[Any, Any]:
    """Set one internal map item, copying only on the public immutable path."""

    current = getattr(state, name)
    if isinstance(state, _ReplayAccumulator):
        current[key] = value
        return current
    updated = dict(current)
    updated[key] = value
    return updated


def _check_owner_transfer_binding(
    state: ReplayState | _ReplayAccumulator,
    event: ValidatedEvent,
) -> None:
    """Require monotonic owner-transfer registry evidence after the first one."""

    registry_commit_oid = event.payload["registry_commit_oid"]
    registry_generation = event.payload["registry_generation"]
    if isinstance(state, _ReplayAccumulator):
        if registry_commit_oid in state._owner_transfer_commit_index:
            _corrupt("owner transfer reuses a registry commit binding")
        previous_generation = state._last_owner_transfer_generation
    else:
        previous_generation = None
        for previous in state.event_records.values():
            if previous.event.type != "project_repository_owner_changed":
                continue
            if previous.event.payload["registry_commit_oid"] == registry_commit_oid:
                _corrupt("owner transfer reuses a registry commit binding")
            previous_generation = previous.event.payload["registry_generation"]
    if previous_generation is not None and registry_generation <= previous_generation:
        _corrupt("owner transfer registry generation does not advance")


def _apply_connected(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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


def _apply_owner_changed(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_active(state, event)
    if state.repository_owner != event.target["prior_repository_owner"]:
        _corrupt("owner transfer does not start at the current owner")
    if state.project_slug != event.payload["project_slug"]:
        _corrupt("owner transfer changes the project slug")
    if state.repository_ids != event.payload["repository_ids"]:
        _corrupt("owner transfer changes the repository set")
    _check_owner_transfer_binding(state, event)
    return _record_state(state, record, repository_owner=event.payload["new_repository_owner"])


def _apply_succeeded(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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


def _apply_config(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    _require_active(state, record.event)
    _require_records_authorization(state, record.event, "project_config_update")
    configuration = record.event.payload["project_configuration"]
    if configuration == state.configuration:
        _corrupt("configuration update is an unrecorded semantic no-op")
    return _record_state(state, record, configuration=configuration)


def _apply_keyring(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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


def _apply_publication(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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
    publications = _map_item(state, "publications", key, publication)
    return _record_state(state, record, agreement_id=agreement_id, publications=publications)


def _apply_activation(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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
    if (
        state.active_version == version
        and state.accepted_versions == accepted
        and state.retired_versions == retired
    ):
        _corrupt("agreement activation is an unrecorded currency no-op")
    activation = AgreementActivation(
        event.event_id,
        agreement_id,
        version,
        event.payload["published_event_id"],
        supersedes,
        accepted,
    )
    activations = _map_item(state, "activations", event.event_id, activation)
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


def _apply_restore(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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


def _apply_acceptance(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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
        if (
            previous.event.target["version"] != event.target["version"]
            or previous.event.target["digest"] != event.target["digest"]
        ):
            _corrupt("acceptance supersession changes the prior acceptance basis")
    elif (
        prior is not None
        and prior.decision == "covered"
        and prior.version in state.accepted_versions
    ):
        _corrupt("covered contributor acceptance requires a correction link")
    decision = ContributorTupleDecision(
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
    decisions = _map_item(state, "tuple_decisions", key, decision)
    return _record_state(state, record, tuple_decisions=decisions)


def _apply_revocation(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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
    decision = ContributorTupleDecision(
        coverage["github_user_id"],
        state.project_id,
        coverage["agreement_id"],
        coverage["recipient_id"],
        "uncovered",
        event.event_id,
    )
    decisions = _map_item(state, "tuple_decisions", key, decision)
    return _record_state(state, record, tuple_decisions=decisions)


def _apply_scope_requested(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    relation = _check_scope_change(event)
    change_id = event.target["change_id"]
    if _find_scope_change(state, change_id) is not None:
        _corrupt("scope change ID was already requested")
    prior_scope = _scope_tuple(event.payload["prior_scope"])
    desired_scope = _scope_tuple(event.payload["desired_scope"])
    prior_generation = event.payload["prior_registry_generation"]
    current_generation = state.enforcement_scope_registry_generation
    if current_generation is None:
        if state.enforcement_scope or prior_scope:
            _corrupt("first scope request does not start from the empty scope")
        current_generation = prior_generation
    if prior_scope != state.enforcement_scope:
        _corrupt("scope request prior scope is not the effective scope")
    if prior_generation != current_generation:
        _corrupt("scope request prior registry generation is stale")
    request = ScopeRequest(
        event.event_id,
        change_id,
        prior_scope,
        desired_scope,
        prior_generation,
        relation,
    )
    requests = _map_item(state, "scope_requests", event.event_id, request)
    return _record_state(
        state,
        record,
        scope_requests=requests,
        enforcement_scope_registry_generation=current_generation,
    )


def _scope_terminal_request(
    state: ReplayState | _ReplayAccumulator,
    event: ValidatedEvent,
) -> ScopeRequest:
    request = state.scope_requests.get(event.payload["request_event_id"])
    if request is None:
        _corrupt("scope terminal does not name an earlier request")
    if request.change_id != event.target["change_id"]:
        _corrupt("scope terminal change ID does not match its request")
    if not request.pending:
        _corrupt("scope request has more than one terminal event")
    if _authorization_relation(event) != request.authorization_relation:
        _corrupt("scope terminal authorization relation does not match its request")
    if request.prior_scope != state.enforcement_scope:
        _corrupt("scope terminal request no longer starts at the effective scope")
    if request.prior_registry_generation != state.enforcement_scope_registry_generation:
        _corrupt("scope terminal request registry generation is stale")
    return request


def _settle_scope_request(
    state: ReplayState | _ReplayAccumulator,
    request: ScopeRequest,
    terminal_event_id: str,
    terminal_kind: str,
) -> Mapping[str, ScopeRequest]:
    settled = replace(
        request,
        terminal_event_id=terminal_event_id,
        terminal_kind=terminal_kind,
    )
    return _map_item(state, "scope_requests", request.event_id, settled)


def _apply_scope_activated(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    request = _scope_terminal_request(state, event)
    desired_scope = _scope_tuple(event.payload["desired_scope"])
    if desired_scope != request.desired_scope:
        _corrupt("scope activation desired scope does not match its request")
    generation = event.payload["registry_generation"]
    if generation <= request.prior_registry_generation:
        _corrupt("scope activation registry generation does not advance")
    registry_commit_oid = event.payload["registry_commit_oid"]
    if _scope_registry_commit_used(state, registry_commit_oid):
        _corrupt("scope activation reuses a registry commit binding")
    requests = _settle_scope_request(state, request, event.event_id, "activated")
    return _record_state(
        state,
        record,
        scope_requests=requests,
        enforcement_scope=desired_scope,
        enforcement_scope_registry_generation=generation,
        enforcement_scope_activation_event_id=event.event_id,
    )


def _apply_scope_abandoned(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    request = _scope_terminal_request(state, event)
    requests = _settle_scope_request(state, request, event.event_id, "abandoned")
    return _record_state(state, record, scope_requests=requests)


def _apply_override(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    repository_id = event.target["repository_id"]
    _require_authorized_repository(event, repository_id)
    grant = OverrideGrant(
        event.event_id,
        repository_id,
        event.target["pull_request_number"],
        event.target["tree_oid"],
        tuple(event.payload["subjects"]),
        event.payload["reason"],
        event.payload["instrument_ref"],
    )
    grants = _map_item(state, "override_grants", event.event_id, grant)
    return _record_state(state, record, override_grants=grants)


def _apply_override_withdrawn(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    grant_id = event.target["override_event_id"]
    grant = state.override_grants.get(grant_id)
    if grant is None:
        _corrupt("override withdrawal does not name an earlier grant")
    _require_authorized_repository(event, grant.repository_id)
    if not grant.active:
        _corrupt("override grant has more than one withdrawal")
    withdrawn = replace(
        grant,
        withdrawal_event_id=event.event_id,
        withdrawal_reason=event.payload["reason"],
        withdrawal_instrument_ref=event.payload["instrument_ref"],
    )
    grants = _map_item(state, "override_grants", grant.event_id, withdrawn)
    return _record_state(state, record, override_grants=grants)


def _apply_retry_requested(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    _require_authorized_repository(event, event.target["repository_id"])
    return _record_state(state, record, retry_events=(*state.retry_events, event.event_id))


def _apply_exemption(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    source_kind = event.payload["source_kind"]
    _require_records_authorization(state, event, f"exemption_{source_kind}_add")
    subject = event.target["subject"]
    github_user_id = _subject_id(subject)
    sequence = state.exemption_sequence_next.get(github_user_id, 0)
    source = _make_exemption_source(
        source_event_id=event.event_id,
        subject=subject,
        source_kind=source_kind,
        team=None,
        basis=event.payload["basis"],
        instrument_ref=event.payload["instrument_ref"],
        rule_event_id=None,
        added_event_id=event.event_id,
        sequence=sequence,
    )
    sources = _map_item(state, "exemption_source_records", source.source_key, source)
    sequences = _map_item(
        state,
        "exemption_sequence_next",
        github_user_id,
        sequence + 1,
    )
    return _record_state(
        state,
        record,
        exemption_source_records=sources,
        known_exemption_sources=state.known_exemption_sources | {source.source_key},
        exemption_sequence_next=sequences,
    )


def _apply_exemption_snapshot(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    _require_records_authorization(state, event, "exemption_snapshot_add")
    sources = dict(state.exemption_source_records)
    sequences = dict(state.exemption_sequence_next)
    known = set(state.known_exemption_sources)
    for subject in event.target["subjects"]:
        github_user_id = _subject_id(subject)
        sequence = sequences.get(github_user_id, 0)
        source = _make_exemption_source(
            source_event_id=event.event_id,
            subject=subject,
            source_kind="snapshot",
            team=event.payload["team"],
            basis=event.payload["basis"],
            instrument_ref=event.payload["instrument_ref"],
            rule_event_id=None,
            added_event_id=event.event_id,
            sequence=sequence,
        )
        sources[source.source_key] = source
        known.add(source.source_key)
        sequences[github_user_id] = sequence + 1
    return _record_state(
        state,
        record,
        exemption_source_records=sources,
        known_exemption_sources=frozenset(known),
        exemption_sequence_next=sequences,
    )


def _apply_exemption_source_withdrawn(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    _require_records_authorization(state, event, "exemption_source_withdraw")
    source_event_id = event.target["source_event_id"]
    subject = event.target["subject"]
    key = (source_event_id, _subject_id(subject))
    if key not in state.known_exemption_sources:
        _corrupt("exemption withdrawal names a source that never existed for the subject")
    if not _manual_exemption_subject(state, source_event_id, subject):
        _corrupt("exemption withdrawal source identity does not match the exact subject")
    if key not in state.exemption_source_records:
        return _record_state(state, record)
    sources = dict(state.exemption_source_records)
    del sources[key]
    return _record_state(state, record, exemption_source_records=sources)


def _apply_exemption_rule_configured(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    _require_records_authorization(state, event, "exemption_rule_configure")
    rule = ExemptionRule(
        event.event_id,
        event.target["team"],
        event.payload["basis"],
        event.payload["instrument_ref"],
    )
    rules = _map_item(state, "exemption_rules", event.event_id, rule)
    return _record_state(state, record, exemption_rules=rules)


def _apply_exemption_rule_withdrawn(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    _require_records_authorization(state, event, "exemption_rule_withdraw")
    rule_event_id = event.target["rule_event_id"]
    rule = state.exemption_rules.get(rule_event_id)
    if rule is None:
        _corrupt("exemption rule withdrawal names a rule that never existed")
    if not rule.active:
        return _record_state(state, record)
    retired = replace(
        rule,
        materialization_cursors={},
        withdrawal_event_id=event.event_id,
    )
    rules = _map_item(state, "exemption_rules", rule_event_id, retired)
    sources = {
        key: source
        for key, source in state.exemption_source_records.items()
        if source.rule_event_id != rule_event_id
    }
    return _record_state(
        state,
        record,
        exemption_rules=rules,
        exemption_source_records=sources,
    )


def _apply_exemption_materialized(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
    event = record.event
    _require_m17_lifecycle(state, event)
    rule_event_id = event.target["rule_event_id"]
    rule = state.exemption_rules.get(rule_event_id)
    if rule is None or not rule.active:
        _corrupt("exemption materialization does not name an active rule")
    if event.payload["team"] != rule.team:
        _corrupt("exemption materialization team does not match its rule")
    subject = event.target["subject"]
    github_user_id = _subject_id(subject)
    prior = rule.materialization_cursors.get(github_user_id)
    if event.payload["prior_materialization_event_id"] != prior:
        _corrupt("exemption materialization predecessor is stale")
    key = (rule_event_id, github_user_id)
    present = key in state.exemption_source_records
    result = event.payload["result"]
    if result == "add" and present:
        _corrupt("exemption materialization add observes an already-present rule source")
    if result == "withdraw" and not present:
        _corrupt("exemption materialization withdrawal observes a missing rule source")
    cursors = dict(rule.materialization_cursors)
    cursors[github_user_id] = event.event_id
    rules = _map_item(
        state,
        "exemption_rules",
        rule_event_id,
        replace(rule, materialization_cursors=cursors),
    )
    sources = dict(state.exemption_source_records)
    known = set(state.known_exemption_sources)
    sequences = dict(state.exemption_sequence_next)
    if result == "add":
        sequence = sequences.get(github_user_id, 0)
        source = _make_exemption_source(
            source_event_id=rule_event_id,
            subject=subject,
            source_kind="continuous_team",
            team=rule.team,
            basis=rule.basis,
            instrument_ref=rule.instrument_ref,
            rule_event_id=rule_event_id,
            added_event_id=event.event_id,
            sequence=sequence,
        )
        sources[key] = source
        known.add(key)
        sequences[github_user_id] = sequence + 1
    else:
        del sources[key]
    return _record_state(
        state,
        record,
        exemption_rules=rules,
        exemption_source_records=sources,
        known_exemption_sources=frozenset(known),
        exemption_sequence_next=sequences,
    )


def _apply_record(
    state: ReplayState | _ReplayAccumulator,
    record: CanonicalEventRecord,
) -> ReplayState | _ReplayAccumulator:
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
    if event_type == "enforcement_scope_requested":
        return _apply_scope_requested(state, record)
    if event_type == "enforcement_scope_activated":
        return _apply_scope_activated(state, record)
    if event_type == "enforcement_scope_abandoned":
        return _apply_scope_abandoned(state, record)
    if event_type == "override":
        return _apply_override(state, record)
    if event_type == "override_withdrawn":
        return _apply_override_withdrawn(state, record)
    if event_type == "retry_requested":
        return _apply_retry_requested(state, record)
    if event_type == "exemption":
        return _apply_exemption(state, record)
    if event_type == "exemption_snapshot":
        return _apply_exemption_snapshot(state, record)
    if event_type == "exemption_source_withdrawn":
        return _apply_exemption_source_withdrawn(state, record)
    if event_type == "exemption_rule_configured":
        return _apply_exemption_rule_configured(state, record)
    if event_type == "exemption_rule_withdrawn":
        return _apply_exemption_rule_withdrawn(state, record)
    if event_type == "exemption_materialized":
        return _apply_exemption_materialized(state, record)
    _corrupt("event type is not implemented by replay")


def apply_event(state: ReplayState, record: CanonicalEventRecord) -> ReplayState:
    """Apply one record, rejecting any invalid transition as corruption."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    result = _apply_record(state, record)
    if not isinstance(result, ReplayState):
        raise ReplayError("immutable replay transition returned a mutable state")
    return result


def replay_events(project_id: str, base_commit_oid: str, records: Iterable[CanonicalEventRecord]) -> ReplayResult:
    """Fold records in caller-supplied ancestry order.

    Corruption is returned as a whole-fold result with no partially replayed
    state.  The last successfully folded event identity remains available for
    diagnostics and generation bindings.
    """

    initial = initial_replay_state(project_id, base_commit_oid)
    state = _ReplayAccumulator(initial)
    if isinstance(records, (str, bytes, bytearray)) or not isinstance(records, Iterable):
        raise ReplayError("records must be an ordered sequence")
    for record in records:
        try:
            _apply_record(state, record)
        except ReplayCorruptionError as error:
            return ReplayResult(None, error, state.last_event_id, state.last_commit_oid)
    frozen = state.freeze()
    return ReplayResult(frozen, None, state.last_event_id, state.last_commit_oid)


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


def effective_enforcement_scope(state: ReplayState) -> EffectiveEnforcementScope:
    """Return the currently activated scope and its canonical evidence."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    return state.effective_enforcement_scope


def scope_request(state: ReplayState, request_event_id: str) -> ScopeRequest | None:
    """Return one scope request, including pending/terminal status."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    if type(request_event_id) is not str:
        raise ReplayError("request_event_id must be a string")
    return state.scope_requests.get(request_event_id)


def active_overrides(
    state: ReplayState,
    repository_id: int | None = None,
    pull_request_number: int | None = None,
    tree_oid: str | None = None,
) -> tuple[OverrideGrant, ...]:
    """Return active grants in ancestry order, optionally filtered by key."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    return tuple(
        grant
        for grant in state.override_grants.values()
        if grant.active
        and (repository_id is None or grant.repository_id == repository_id)
        and (pull_request_number is None or grant.pull_request_number == pull_request_number)
        and (tree_oid is None or grant.tree_oid == tree_oid)
    )


def retry_event_ids(state: ReplayState) -> tuple[str, ...]:
    """Return retry audit event identities in canonical ancestry order."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    return state.retry_events


def _coerce_subject_id(value: Any) -> int:
    if type(value) is int and value > 0:
        return value
    if isinstance(value, Mapping):
        value = value.get("github_user_id")
    elif hasattr(value, "github_user_id"):
        value = value.github_user_id
    if type(value) is not int or value <= 0:
        raise ReplayError("subject query must identify a positive GitHub user ID")
    return value


def exemption_sources(state: ReplayState, subject: Any) -> tuple[ExemptionSource, ...]:
    """Return every active exemption source for one subject in source order."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    github_user_id = _coerce_subject_id(subject)
    return tuple(
        sorted(
            (
                source
                for source in state.exemption_source_records.values()
                if source.github_user_id == github_user_id
            ),
            key=lambda source: source.sequence,
        )
    )


def is_exempt(state: ReplayState, subject: Any) -> bool:
    """Derive effective exemption from the non-empty source union."""

    return bool(exemption_sources(state, subject))


def active_exemption_rules(state: ReplayState) -> tuple[ExemptionRule, ...]:
    """Return active continuous-team rules in canonical ancestry order."""

    if not isinstance(state, ReplayState):
        raise ReplayError("replay state must be a ReplayState")
    return tuple(rule for rule in state.exemption_rules.values() if rule.active)


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
