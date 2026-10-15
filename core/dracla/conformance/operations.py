"""Pure operation cells and coverage fences from HLD §5.4.

The caller authenticates immutable repository/envelope observations and supplies
completed projection/read-back facts. These functions perform no I/O, grant no
authorization, and never infer a transition from elapsed time. Returned values
are immutable; ordinary construction goes through the closed decoders or the
transition functions. The required byte limit is supplied by the release profile.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from . import events as _events
from .canonical import canonical_json, parse_canonical_json
from .encoding import base64url_decode, base64url_encode


class OperationCorruption(ValueError):
    """Persisted bytes, an immutable reference, or a cross-binding is invalid."""


class OperationConflict(ValueError):
    """A valid state belongs to another operation or forbids this transition."""


_FACTORY = object()
_OWNER = ("operation_id", "operation_sha256")
_SCOPE = ("subjects", "project_wide")
_REFERENCE = ("prepared_commit_oid", "prepared_blob_sha", "prepared_generation")
_PACKAGE = ("prepared_events_head", "event_jcs_b64", "side_artifacts")


@dataclass(frozen=True, slots=True, init=False)
class _State:
    _value: Any

    def __init__(self, value: Any, *, _factory: object = None) -> None:
        if _factory is not _FACTORY:
            raise OperationCorruption("use a closed decoder or transition")
        object.__setattr__(self, "_value", _events._freeze(value))

    def to_dict(self) -> dict[str, Any]:
        return _events._thaw(self._value)


class PreparedOperation(_State):
    """One closed idle, prepared, appending, or terminal cell."""

    __slots__ = ()

    @property
    def state(self) -> str:
        return self._value["state"]

    @property
    def generation(self) -> int:
        return self._value["generation"]


class DecisionFence(_State):
    """One closed idle, mutation, or success_reserved coverage fence."""

    __slots__ = ()

    @property
    def state(self) -> str:
        return self._value["state"]

    @property
    def generation(self) -> int:
        return self._value["generation"]


class InFlightMarker(_State):
    """An empty marker or exactly one owner-bound scoped entry."""

    __slots__ = ()


def _make(cls: type[_State], value: dict[str, Any]) -> Any:
    return cls(value, _factory=_FACTORY)


def _value(value: Any, cls: type[_State]) -> dict[str, Any]:
    if type(value) is not cls:
        raise OperationCorruption("wrong operation-state value type")
    return value.to_dict()


def _exact(value: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    try:
        return _events._exact_object(value, fields, "operation state")
    except (ValueError, TypeError) as error:
        raise OperationCorruption("state has missing or extra members") from error


def _check(validator: Any, value: Any) -> Any:
    try:
        return validator(value, "operation state")
    except (ValueError, TypeError) as error:
        raise OperationCorruption("invalid state scalar") from error


def _token(value: Any) -> str:
    try:
        base64url_decode(value, expected_length=32)
    except (ValueError, TypeError) as error:
        raise OperationCorruption("invalid 32-byte identity") from error
    return value


def _owner(value: dict[str, Any]) -> tuple[str, str]:
    return _token(value["operation_id"]), _check(_events._digest, value["operation_sha256"])


def _require_owner(value: dict[str, Any], operation_id: str, operation_sha256: str) -> None:
    if _owner(value) != _owner(dict(operation_id=operation_id, operation_sha256=operation_sha256)):
        raise OperationConflict("operation owner does not match")


def _scope(value: dict[str, Any]) -> None:
    subjects = value["subjects"]
    if type(value["project_wide"]) is not bool or type(subjects) is not list:
        raise OperationCorruption("invalid mutation scope")
    for subject in subjects:
        _check(_events._positive, subject)
    if subjects != sorted(set(subjects)) or (not subjects) != value["project_wide"]:
        raise OperationCorruption("scope must be project-wide or a nonempty sorted subject set")


def _bounded(data: bytes, limit: int) -> bytes:
    _check(_events._positive, limit)
    if type(data) is not bytes:
        raise OperationCorruption("operation bytes must be bytes")
    if len(data) > limit:
        raise OperationCorruption("prepared operation exceeds its explicit byte limit")
    return data


def _parse(data: bytes) -> dict[str, Any]:
    try:
        value = parse_canonical_json(data)
        if type(value) is not dict:
            raise ValueError("not an object")
        return value
    except (ValueError, TypeError, RecursionError) as error:
        raise OperationCorruption("state bytes must be a canonical JSON object") from error


def append_claim(operation_id: str, operation_sha256: str, append_head: str) -> str:
    """Derive the exact domain-separated HLD append-right claim."""
    value = dict(operation_id=operation_id, operation_sha256=operation_sha256, append_head=append_head)
    _owner(value)
    _check(_events._oid, append_head)
    return base64url_encode(hashlib.sha256(b"dracla-append-claim-v1\0" + canonical_json(value)).digest())


def authoritative_check_identity(repository_id: int, merge_group_head_oid: str,
                                 pull_request_number: int, github_delivery_id: str) -> str:
    """Derive the fence reservation identity; this does not publish a check."""
    value = dict(repository_id=_check(_events._positive, repository_id),
                 merge_group_head_oid=_check(_events._oid, merge_group_head_oid),
                 pull_request_number=_check(_events._positive, pull_request_number),
                 github_delivery_id=_check(_events._string, github_delivery_id))
    return base64url_encode(hashlib.sha256(b"dracla-authoritative-check-v1\0" + canonical_json(value)).digest())


def decode_prepared_operation(data: bytes, *, expected_project_id: str,
                              max_prepared_operation_bytes: int,
                              preconditions: Any = None) -> PreparedOperation:
    """Validate complete cell bytes and the frozen package at its prepared head.

    Prepared/appending states require the earlier kernel's authenticated
    preconditions from prepared_events_head, supplied by the caller.
    """
    _check(_events._string, expected_project_id)
    obj = _parse(_bounded(data, max_prepared_operation_bytes))
    state = obj.get("state")
    fields = ("state", "generation")
    if state in ("prepared", "appending"):
        fields += _OWNER + ("event_id",) + _PACKAGE
        if state == "appending":
            fields += ("append_head", "append_claim")
    elif state == "terminal":
        fields += _OWNER + ("event_id", "result", "observed_events_head", "canonical_commit")
    elif state != "idle":
        raise OperationCorruption("unknown prepared state")
    _exact(obj, fields)
    _check(_events._nonnegative, obj["generation"])
    if state != "idle":
        _owner(obj)
        _token(obj["event_id"])
    if state in ("prepared", "appending"):
        try:
            if type(obj["side_artifacts"]) is not list:
                raise OperationCorruption("side artifacts must be an array")
            for artifact in obj["side_artifacts"]:
                _exact(artifact, ("kind", "path", "bytes_b64", "sha256"))
            head = _check(_events._oid, obj["prepared_events_head"])
            event = _events.parse_event_jcs(base64url_decode(obj["event_jcs_b64"]), expected_project_id=expected_project_id)
            if (event.idempotency_key, event.operation_sha256, event.event_id) != (obj["operation_id"], obj["operation_sha256"], obj["event_id"]):
                raise OperationCorruption("frozen event identity disagrees with cell")
            _events.validate_side_artifact_package(event, obj["side_artifacts"], preconditions=preconditions, expected_head=head)
        except (ValueError, TypeError, KeyError) as error:
            raise OperationCorruption("invalid frozen event or side-artifact package") from error
        if state == "appending" and obj["append_claim"] != append_claim(*_owner(obj), obj["append_head"]):
            raise OperationCorruption("append claim disagrees with cell")
    if state == "terminal":
        _check(_events._oid, obj["observed_events_head"])
        if obj["result"] not in ("landed", "semantic_noop", "conflict"):
            raise OperationCorruption("unknown terminal result")
        if obj["result"] == "landed":
            _check(_events._oid, obj["canonical_commit"])
        elif obj["canonical_commit"] is not None:
            raise OperationCorruption("non-landed result cannot carry a canonical commit")
    return _make(PreparedOperation, obj)


def encode_prepared_operation(cell: PreparedOperation, *, max_prepared_operation_bytes: int) -> bytes:
    return _bounded(canonical_json(_value(cell, PreparedOperation)), max_prepared_operation_bytes)


def decode_decision_fence(data: bytes) -> DecisionFence:
    obj = _parse(data)
    state = obj.get("state")
    fields = ("state", "generation")
    if state == "mutation":
        fields += _OWNER + _SCOPE + _REFERENCE
    elif state == "success_reserved":
        fields += ("check_identity", "projection_commit")
    elif state != "idle":
        raise OperationCorruption("unknown fence state")
    _exact(obj, fields)
    _check(_events._nonnegative, obj["generation"])
    if state == "mutation":
        _owner(obj)
        _scope(obj)
        _check(_events._oid, obj["prepared_commit_oid"])
        _check(_events._oid, obj["prepared_blob_sha"])
        _check(_events._nonnegative, obj["prepared_generation"])
    elif state == "success_reserved":
        _token(obj["check_identity"])
        _check(_events._oid, obj["projection_commit"])
    return _make(DecisionFence, obj)


def encode_decision_fence(fence: DecisionFence) -> bytes:
    return canonical_json(_value(fence, DecisionFence))


def decode_inflight_marker(data: bytes) -> InFlightMarker:
    obj = _exact(_parse(data), ("ops",))
    ops = obj["ops"]
    if type(ops) is not dict or len(ops) > 1:
        raise OperationCorruption("marker must contain zero or one operation")
    for operation_id, entry in ops.items():
        _token(operation_id)
        _exact(entry, ("operation_sha256", "started_at") + _SCOPE)
        _check(_events._digest, entry["operation_sha256"])
        _check(_events._timestamp, entry["started_at"])
        _scope(entry)
    return _make(InFlightMarker, obj)


def encode_inflight_marker(marker: InFlightMarker) -> bytes:
    return canonical_json(_value(marker, InFlightMarker))


@dataclass(frozen=True, slots=True)
class PreparedOperationReference:
    """Caller-authenticated immutable prepared commit and envelope observation."""

    commit_oid: str
    blob_sha: str
    cell: PreparedOperation

    def __post_init__(self) -> None:
        _check(_events._oid, self.commit_oid)
        _check(_events._oid, self.blob_sha)
        if type(self.cell) is not PreparedOperation or self.cell.state != "prepared":
            raise OperationCorruption("reference must contain the original prepared cell")


def _reference(fence: dict[str, Any], cell: dict[str, Any], ref: PreparedOperationReference) -> None:
    if type(ref) is not PreparedOperationReference:
        raise OperationCorruption("mutation requires its authenticated prepared reference")
    original = ref.cell.to_dict()
    expected = (ref.commit_oid, ref.blob_sha, ref.cell.generation)
    if tuple(fence[k] for k in _REFERENCE) != expected:
        raise OperationCorruption("prepared commit, blob or generation disagrees")
    if cell["state"] == "idle" or _owner(fence) != _owner(cell) or _owner(cell) != _owner(original):
        raise OperationCorruption("prepared operation owner disagrees")
    if (cell["event_id"], cell["generation"]) != (original["event_id"], original["generation"]):
        raise OperationCorruption("prepared event or generation disagrees")
    if cell["state"] in ("prepared", "appending") and any(cell[k] != original[k] for k in _PACKAGE):
        raise OperationCorruption("current cell changed its frozen package")


def _marker_matches(marker: dict[str, Any], fence: dict[str, Any]) -> bool:
    ops = marker["ops"]
    if not ops:
        return True
    entry = ops.get(fence["operation_id"])
    return entry is not None and all(entry[k] == fence[k] for k in ("operation_sha256",) + _SCOPE)


def validate_operation_cross_bindings(cell: PreparedOperation, fence: DecisionFence,
                                      marker: InFlightMarker, *,
                                      prepared_reference: PreparedOperationReference | None = None) -> None:
    c, f, m = _value(cell, PreparedOperation), _value(fence, DecisionFence), _value(marker, InFlightMarker)
    if f["state"] == "mutation":
        _reference(f, c, prepared_reference)
        if not _marker_matches(m, f):
            raise OperationCorruption("marker does not match mutation fence")
    elif m["ops"] or c["state"] == "appending":
        raise OperationCorruption("marker or append right lacks a mutation fence")


def prepare_operation(cell: PreparedOperation, event: Any, side_artifacts: Any, *,
                      expected_project_id: str, expected_events_head: str,
                      preconditions: Any, max_prepared_operation_bytes: int) -> PreparedOperation:
    old = _value(cell, PreparedOperation)
    _check(_events._oid, expected_events_head)
    try:
        event = _events.validate_event(event, expected_project_id=expected_project_id)
        artifacts = _events._artifact_map(side_artifacts)
        entries = [dict(kind=a.kind, path=a.path, bytes_b64=base64url_encode(a.bytes), sha256=a.sha256) for a in artifacts.values()]
    except (ValueError, TypeError) as error:
        raise OperationCorruption("invalid proposed event or artifacts") from error
    obj = dict(state="prepared", generation=cell.generation, operation_id=event.idempotency_key,
               operation_sha256=event.operation_sha256, event_id=event.event_id,
               prepared_events_head=expected_events_head,
               event_jcs_b64=base64url_encode(canonical_json(event.to_dict())), side_artifacts=entries)
    candidate = decode_prepared_operation(canonical_json(obj), expected_project_id=expected_project_id,
        preconditions=preconditions, max_prepared_operation_bytes=max_prepared_operation_bytes)
    # A durable preparation must also fit when its append right is recorded.
    largest = dict(obj, state="appending", append_head="f" * 64,
                   append_claim=append_claim(*_owner(obj), "f" * 64))
    _bounded(canonical_json(largest), max_prepared_operation_bytes)
    if old["state"] == "idle":
        return candidate
    if _owner(old) != _owner(obj) or old["event_id"] != obj["event_id"]:
        raise OperationConflict("another operation occupies the cell")
    if old["state"] != "terminal" and any(old[k] != obj[k] for k in _PACKAGE):
        raise OperationConflict("retry changed the frozen event or artifacts")
    return cell


def claim_append(cell: PreparedOperation, *, operation_id: str, operation_sha256: str,
                 fence: DecisionFence, marker: InFlightMarker,
                 prepared_reference: PreparedOperationReference,
                 append_head: str, max_prepared_operation_bytes: int,
                 expected_append_claim: str | None = None) -> PreparedOperation:
    obj = _value(cell, PreparedOperation)
    encode_prepared_operation(cell, max_prepared_operation_bytes=max_prepared_operation_bytes)
    _mutation_binding(cell, fence, marker, prepared_reference)
    if not marker.to_dict()["ops"]:
        raise OperationConflict("append requires the open marker")
    if cell.state not in ("prepared", "appending"):
        raise OperationConflict("cell cannot acquire an append right")
    _require_owner(obj, operation_id, operation_sha256)
    claim = append_claim(operation_id, operation_sha256, append_head)
    if cell.state == "appending":
        if obj["append_head"] == append_head:
            return cell
        if expected_append_claim != obj["append_claim"]:
            raise OperationConflict("append claim changed")
    result = _make(PreparedOperation, dict(obj, state="appending", append_head=append_head, append_claim=claim))
    encode_prepared_operation(result, max_prepared_operation_bytes=max_prepared_operation_bytes)
    return result


def terminal_operation(cell: PreparedOperation, *, operation_id: str, operation_sha256: str,
                       fence: DecisionFence, marker: InFlightMarker,
                       prepared_reference: PreparedOperationReference,
                       result: str, observed_events_head: str,
                       canonical_commit: str | None, projection_verified: bool = False,
                       readback_verified: bool = False) -> PreparedOperation:
    obj = _value(cell, PreparedOperation)
    if cell.state == "idle":
        raise OperationConflict("idle cell has no terminal owner")
    _mutation_binding(cell, fence, marker, prepared_reference)
    _require_owner(obj, operation_id, operation_sha256)
    _check(_events._oid, observed_events_head)
    _check(_events._string, result)
    if result not in ("landed", "semantic_noop", "conflict"):
        raise OperationCorruption("unknown terminal result")
    if result == "landed":
        _check(_events._oid, canonical_commit)
    elif canonical_commit is not None:
        raise OperationCorruption("non-landed result has a canonical commit")
    terminal = {k: obj[k] for k in ("generation",) + _OWNER + ("event_id",)}
    terminal.update(state="terminal", result=result, observed_events_head=observed_events_head, canonical_commit=canonical_commit)
    if cell.state == "terminal":
        if obj != terminal:
            raise OperationConflict("terminal outcome is immutable")
        return cell
    if result == "landed":
        if marker.to_dict()["ops"] or projection_verified is not True or readback_verified is not True:
            raise OperationConflict("landed terminal requires projection, marker close and read-back")
    elif not marker.to_dict()["ops"]:
        raise OperationConflict("semantic revalidation requires the open marker")
    if (result == "landed") != (cell.state == "appending"):
        raise OperationConflict("prepared may terminate without append; appending must repair forward")
    return _make(PreparedOperation, terminal)


def acquire_mutation_fence(fence: DecisionFence, cell: PreparedOperation,
                           prepared_reference: PreparedOperationReference, *,
                           subjects: list[int], project_wide: bool) -> DecisionFence:
    f, c = _value(fence, DecisionFence), _value(cell, PreparedOperation)
    if cell.state not in ("prepared", "appending"):
        raise OperationConflict("mutation needs a prepared operation")
    if type(prepared_reference) is not PreparedOperationReference:
        raise OperationCorruption("missing prepared reference")
    obj = dict(state="mutation", generation=fence.generation, **{k: c[k] for k in _OWNER},
               subjects=subjects, project_wide=project_wide,
               prepared_commit_oid=prepared_reference.commit_oid,
               prepared_blob_sha=prepared_reference.blob_sha, prepared_generation=prepared_reference.cell.generation)
    _scope(obj)
    candidate = decode_decision_fence(canonical_json(obj))
    _reference(obj, c, prepared_reference)
    if fence.state == "mutation" and f == obj:
        return fence
    if fence.state != "idle" or cell.state != "prepared":
        raise OperationConflict("fence is occupied or append already began")
    return candidate


def _mutation_binding(cell: PreparedOperation, fence: DecisionFence, marker: InFlightMarker,
                      reference: PreparedOperationReference) -> None:
    validate_operation_cross_bindings(cell, fence, marker, prepared_reference=reference)
    if fence.state != "mutation":
        raise OperationConflict("transition requires its matching mutation fence")


def open_inflight_marker(marker: InFlightMarker, fence: DecisionFence, *,
                          cell: PreparedOperation, prepared_reference: PreparedOperationReference,
                          started_at: str) -> InFlightMarker:
    m, f = _value(marker, InFlightMarker), _value(fence, DecisionFence)
    _mutation_binding(cell, fence, marker, prepared_reference)
    if cell.state not in ("prepared", "appending"):
        raise OperationConflict("terminal operation cannot reopen its marker")
    _check(_events._timestamp, started_at)
    if m["ops"]:
        return marker
    entry = {k: f[k] for k in ("operation_sha256",) + _SCOPE}
    entry["started_at"] = started_at
    return decode_inflight_marker(canonical_json({"ops": {f["operation_id"]: entry}}))


def close_inflight_marker(marker: InFlightMarker, fence: DecisionFence, *,
                           cell: PreparedOperation, prepared_reference: PreparedOperationReference,
                           projection_verified: bool = False) -> InFlightMarker:
    m = _value(marker, InFlightMarker)
    _mutation_binding(cell, fence, marker, prepared_reference)
    if cell.state == "prepared" or (cell.state == "appending" and projection_verified is not True):
        raise OperationConflict("close requires terminal outcome or complete projection")
    return marker if not m["ops"] else decode_inflight_marker(b'{"ops":{}}')


def _released(fence: DecisionFence, expected: DecisionFence) -> DecisionFence:
    generation = _check(_events._nonnegative, expected.generation + 1)
    if fence.state == "idle" and fence.generation == generation:
        return fence
    if fence != expected:
        raise OperationConflict("fence changed before release")
    return decode_decision_fence(canonical_json(dict(state="idle", generation=generation)))


def release_mutation_fence(fence: DecisionFence, expected_mutation: DecisionFence,
                           cell: PreparedOperation, marker: InFlightMarker, *,
                           prepared_reference: PreparedOperationReference,
                           projection_verified: bool, readback_verified: bool) -> DecisionFence:
    f, c, m = _value(expected_mutation, DecisionFence), _value(cell, PreparedOperation), _value(marker, InFlightMarker)
    _value(fence, DecisionFence)
    if expected_mutation.state != "mutation" or cell.state != "terminal":
        raise OperationConflict("release needs the exact mutation and terminal cell")
    _reference(f, c, prepared_reference)
    if m["ops"] or readback_verified is not True or type(projection_verified) is not bool:
        raise OperationConflict("release needs marker close and verified read-back")
    if c["result"] == "landed" and not projection_verified:
        raise OperationConflict("landed operation needs complete verified projection")
    return _released(fence, expected_mutation)


def clear_prepared_operation(cell: PreparedOperation, expected_terminal: PreparedOperation, *,
                             mutation_fence: DecisionFence, released_fence: DecisionFence,
                             marker: InFlightMarker,
                             prepared_reference: PreparedOperationReference) -> PreparedOperation:
    """Clear only after the caller read back this owner's exact fence release.

    released_fence is that immutable read-back, not a demand that a later
    authoritative check leave the coverage fence unchanged forever.
    """
    c, expected = _value(cell, PreparedOperation), _value(expected_terminal, PreparedOperation)
    f, released, m = _value(mutation_fence, DecisionFence), _value(released_fence, DecisionFence), _value(marker, InFlightMarker)
    if expected_terminal.state != "terminal" or mutation_fence.state != "mutation":
        raise OperationConflict("clear requires terminal owner and matching prior mutation")
    _reference(f, expected, prepared_reference)
    if m["ops"] or released_fence.state != "idle" or released_fence.generation != mutation_fence.generation + 1:
        raise OperationConflict("clear needs the exact fence release read-back")
    if cell.state == "idle" and cell.generation == expected_terminal.generation:
        return cell
    if c != expected:
        raise OperationConflict("terminal cell changed before clear")
    return _make(PreparedOperation, dict(state="idle", generation=cell.generation))


def reserve_success(fence: DecisionFence, marker: InFlightMarker, *,
                    check_identity: str, projection_commit: str) -> DecisionFence:
    """Reserve from fence and marker read at the same immutable coverage head."""
    _value(fence, DecisionFence)
    if _value(marker, InFlightMarker)["ops"]:
        raise OperationConflict("success reservation requires an empty marker")
    _token(check_identity)
    _check(_events._oid, projection_commit)
    candidate = decode_decision_fence(canonical_json(dict(state="success_reserved", generation=fence.generation,
                                                        check_identity=check_identity, projection_commit=projection_commit)))
    if fence == candidate:
        return fence
    if fence.state != "idle":
        raise OperationConflict("success reservation requires idle fence")
    return candidate


def release_success(fence: DecisionFence, expected_reservation: DecisionFence, *, completion_verified: bool) -> DecisionFence:
    _value(fence, DecisionFence)
    _value(expected_reservation, DecisionFence)
    if expected_reservation.state != "success_reserved" or completion_verified is not True:
        raise OperationConflict("reservation needs exact independently verified completion")
    return _released(fence, expected_reservation)
