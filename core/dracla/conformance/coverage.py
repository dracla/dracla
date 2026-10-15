"""Pure closed coverage plaintext contracts (HLD §§5.3, 5.4 and 6.3).

Files are semantic plaintext, before envelope wrapping. The caller authenticates
their project and immutable coverage commit. An optional canonical-head check is
for callers that can read canonical; the enforcer cannot acquire that evidence.
Currency and operational liveness are read overlays, never rewritten into a
subject's durable signature basis. No function reads a clock or performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import events as _events
from .artifacts import override_key
from .canonical import canonical_json, parse_canonical_json
from .operations import (
    DecisionFence, InFlightMarker, decode_decision_fence, decode_inflight_marker,
    encode_decision_fence, encode_inflight_marker,
)
from .replay import ReplayState, active_overrides


class CoverageError(ValueError):
    """Coverage plaintext or its requested context is invalid."""


_SOURCE = "source.enc.json"
_ACTIVE = "agreements/active.enc.json"
_EXEMPT = "exemptions.enc.json"
_MARKER = "inflight.enc.json"
_FENCE = "decision-fence.enc.json"
_SHARDS = tuple(f"users/{i:02d}.enc.json" for i in range(32))
_FILES = (_SOURCE, _ACTIVE, _EXEMPT, _MARKER, _FENCE) + _SHARDS


def _exact(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys):
        raise CoverageError("coverage object has missing or unknown fields")
    return value


def _scalar(validator: Any, value: Any) -> Any:
    try:
        return validator(value, "coverage")
    except (ValueError, TypeError) as error:
        raise CoverageError("invalid coverage scalar") from error


def _id_key(value: Any) -> int:
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise CoverageError("user key must be a canonical positive decimal ID")
    # Avoid parsing an unbounded integer string at this closed boundary.
    if len(value) > 16:
        raise CoverageError("user key exceeds safe integer range")
    n = _scalar(_events._positive, int(value))
    if str(n) != value:
        raise CoverageError("user key must not contain leading zeros")
    return n


def coverage_shard(github_user_id: int, *, shard_count: int) -> int:
    """Use the count from the same active-agreement observation as the shards."""
    if type(shard_count) is not int or shard_count != 32:
        raise CoverageError("projection format 1 requires exactly 32 shards")
    return _scalar(_events._positive, github_user_id) % shard_count


def _active(value: Any) -> None:
    _exact(value, ("agreement_id", "active_version", "accepted_versions",
                   "retired_versions", "activation_event_id", "projection_format",
                   "shard_count"))
    if type(value["projection_format"]) is not int or value["projection_format"] != 1:
        raise CoverageError("unsupported coverage projection format")
    coverage_shard(1, shard_count=value["shard_count"])
    for name in ("accepted_versions", "retired_versions"):
        versions = value[name]
        if type(versions) is not list:
            raise CoverageError("version set must be an array")
        for version in versions:
            _scalar(_events._string, version)
        if versions != sorted(set(versions), key=canonical_json):
            raise CoverageError("version set must be sorted and unique")
    accepted, retired = value["accepted_versions"], value["retired_versions"]
    if set(accepted) & set(retired):
        raise CoverageError("accepted and retired versions overlap")
    activation = [value[k] for k in ("agreement_id", "active_version", "activation_event_id")]
    if all(x is None for x in activation):
        if accepted or retired:
            raise CoverageError("pre-activation currency sets must be empty")
    else:
        _scalar(_events._string, value["agreement_id"])
        _scalar(_events._string, value["active_version"])
        _scalar(_events._event_id, value["activation_event_id"])
        if value["active_version"] not in accepted:
            raise CoverageError("active version must be accepted")


def _operation_pair(marker: Any, fence: Any) -> None:
    try:
        # Reuse the M1-9 closed schemas without requiring records-key access.
        m = decode_inflight_marker(canonical_json(marker)).to_dict()
        f = decode_decision_fence(canonical_json(fence)).to_dict()
    except (ValueError, TypeError) as error:
        raise CoverageError("invalid coverage operation state") from error
    if m["ops"]:
        if f["state"] != "mutation":
            raise CoverageError("marker lacks a mutation fence")
        entry = m["ops"].get(f["operation_id"])
        if entry is None or any(entry[k] != f[k] for k in
                                ("operation_sha256", "subjects", "project_wide")):
            raise CoverageError("marker and fence do not match")


def _validate_files(files: Any) -> None:
    _exact(files, _FILES)
    source = _exact(files[_SOURCE], ("canonical_sha", "built_at", "dracla_version",
                                     "project_state", "successor_project_id"))
    _scalar(_events._oid, source["canonical_sha"])
    _scalar(_events._timestamp, source["built_at"])
    _scalar(_events._string, source["dracla_version"])
    if source["project_state"] == "active":
        if source["successor_project_id"] is not None:
            raise CoverageError("active project cannot name a successor")
    elif source["project_state"] == "succeeded":
        _scalar(_events._string, source["successor_project_id"])
    else:
        raise CoverageError("unknown or unconnected project lifecycle")
    _active(files[_ACTIVE])
    _operation_pair(files[_MARKER], files[_FENCE])
    exemptions = files[_EXEMPT]
    if type(exemptions) is not dict:
        raise CoverageError("exemptions must be an object")
    for key, value in exemptions.items():
        _id_key(key)
        if _exact(value, ("active",))["active"] is not True:
            raise CoverageError("exemption must be active")
    for shard, path in enumerate(_SHARDS):
        users = files[path]
        if type(users) is not dict:
            raise CoverageError("user shard must be an object")
        for key, row in users.items():
            subject = _id_key(key)
            if coverage_shard(subject, shard_count=32) != shard:
                raise CoverageError("user is in the wrong shard")
            _exact(row, ("agreements", "overrides"))
            agreements, overrides = row["agreements"], row["overrides"]
            if type(agreements) is not dict or type(overrides) is not dict:
                raise CoverageError("agreement and override maps must be objects")
            for agreement, decision in agreements.items():
                _scalar(_events._string, agreement)
                _exact(decision, ("decision", "reason_code", "version", "digest"))
                if decision["reason_code"] == "signed":
                    if decision["decision"] != "covered":
                        raise CoverageError("signed row must permit coverage")
                    _scalar(_events._string, decision["version"])
                    _scalar(_events._digest, decision["digest"])
                elif decision["reason_code"] in ("revoked", "not_signed", "indeterminate"):
                    if (decision["decision"] != "uncovered" or
                            decision["version"] is not None or decision["digest"] is not None):
                        raise CoverageError("uncovered row must not carry an acceptance basis")
                else:
                    # Currency and exemptions are separate read-time inputs.
                    # Persisting their effective result would defeat later restore
                    # or require the forbidden currency-driven shard rewrite.
                    raise CoverageError("row reason is not a durable signature basis")
            tuples = set()
            for entry_key, entry in overrides.items():
                _exact(entry, ("repository_id", "pull_request_number", "subject_user_id",
                               "tree_oid", "grant_event_id", "active"))
                for field in ("repository_id", "pull_request_number", "subject_user_id"):
                    _scalar(_events._positive, entry[field])
                _scalar(_events._oid, entry["tree_oid"])
                _scalar(_events._event_id, entry["grant_event_id"])
                if entry["active"] is not True or entry["subject_user_id"] != subject:
                    raise CoverageError("override is inactive or belongs to another subject")
                identity = tuple(entry[k] for k in
                                 ("repository_id", "pull_request_number", "subject_user_id", "tree_oid"))
                computed = override_key(repository_id=identity[0], pull_request_number=identity[1],
                                        subject_user_id=identity[2], tree_oid=identity[3])
                if entry_key != computed or identity in tuples:
                    raise CoverageError("override key or repeated tuple is invalid")
                tuples.add(identity)


@dataclass(frozen=True, slots=True, init=False)
class CoverageProjection:
    """Immutable validated plaintext files with their authenticated project context."""

    project_id: str
    _files: Any

    def __init__(self, project_id: str, files: dict[str, Any]) -> None:
        _scalar(_events._string, project_id)
        # Canonical round-trip also rejects unsafe numbers and non-JSON input.
        try:
            value = parse_canonical_json(canonical_json(files))
        except (ValueError, TypeError) as error:
            raise CoverageError("projection must contain canonical JSON values") from error
        _validate_files(value)
        object.__setattr__(self, "project_id", project_id)
        object.__setattr__(self, "_files", _events._freeze(value))

    def to_dict(self) -> dict[str, Any]:
        return _events._thaw(self._files)

    def plaintext_files(self) -> dict[str, bytes]:
        """Return deterministic logical file bytes before envelope wrapping."""
        return {path: canonical_json(value) for path, value in self.to_dict().items()}


def validate_coverage_projection(projection: CoverageProjection, *, expected_project_id: str,
                                 expected_canonical_oid: str | None = None) -> None:
    _scalar(_events._string, expected_project_id)
    if type(projection) is not CoverageProjection or projection.project_id != expected_project_id:
        raise CoverageError("projection project context does not match")
    files = projection.to_dict()
    _validate_files(files)
    if expected_canonical_oid is not None:
        _scalar(_events._oid, expected_canonical_oid)
        if files[_SOURCE]["canonical_sha"] != expected_canonical_oid:
            raise CoverageError("projection canonical source does not match")
    if files[_SOURCE]["successor_project_id"] == expected_project_id:
        raise CoverageError("project cannot succeed itself")


def materialize_coverage(state: ReplayState,
                         operation_state: tuple[InFlightMarker, DecisionFence], *,
                         canonical_oid: str, built_at: str, dracla_version: str) -> CoverageProjection:
    """Fold replay and the explicit (marker, fence) pair; never infer liveness."""
    if type(state) is not ReplayState:
        raise CoverageError("materialization requires validated replay state")
    _scalar(_events._oid, canonical_oid)
    if state.current_head_oid != canonical_oid:
        raise CoverageError("canonical source must equal the replayed head")
    if type(operation_state) is not tuple or len(operation_state) != 2:
        raise CoverageError("operation state must be an explicit marker/fence pair")
    marker, fence = operation_state
    try:
        marker_value = parse_canonical_json(encode_inflight_marker(marker))
        fence_value = parse_canonical_json(encode_decision_fence(fence))
    except (ValueError, TypeError) as error:
        raise CoverageError("operation state has the wrong value types") from error
    files = {_SOURCE: {"canonical_sha": canonical_oid, "built_at": built_at,
                       "dracla_version": dracla_version, "project_state": state.project_state,
                       "successor_project_id": state.successor_project_id},
             _ACTIVE: {"agreement_id": state.agreement_id if state.active_version else None,
                       "active_version": state.active_version,
                       "accepted_versions": list(state.accepted_versions),
                       "retired_versions": list(state.retired_versions),
                       "activation_event_id": state.activation_event_id,
                       "projection_format": 1, "shard_count": 32},
             _EXEMPT: {}, _MARKER: marker_value, _FENCE: fence_value,
             **{path: {} for path in _SHARDS}}

    def row(subject: int) -> dict[str, Any]:
        path = _SHARDS[coverage_shard(subject, shard_count=32)]
        return files[path].setdefault(str(subject), {"agreements": {}, "overrides": {}})

    for key, decision in state.tuple_decisions.items():
        if (key != decision.tuple_key or decision.project_id != state.project_id or
                state.recipient is None or decision.recipient_id != state.recipient.get("recipient_id")):
            raise CoverageError("tuple decision does not belong to this replay project/recipient")
        row(decision.github_user_id)["agreements"][decision.agreement_id] = {
            "decision": decision.decision,
            "reason_code": "signed" if decision.is_covered else "revoked",
            "version": decision.version, "digest": decision.digest}
    for unresolved in state.unresolved:
        # Replay's closed unresolved identity is ((subject, agreement), event_id).
        if (not isinstance(unresolved, tuple) or len(unresolved) != 2 or
                not isinstance(unresolved[0], tuple) or len(unresolved[0]) != 2):
            raise CoverageError("unresolved replay identity is malformed")
        (subject, agreement), event_id = unresolved
        _scalar(_events._event_id, event_id)
        row(subject)["agreements"][agreement] = {
            "decision": "uncovered", "reason_code": "indeterminate", "version": None, "digest": None}
    for source in state.exemption_source_records.values():
        files[_EXEMPT][str(source.github_user_id)] = {"active": True}
    for grant in active_overrides(state):
        for subject in grant.subjects:
            user_id = subject["github_user_id"]
            key = override_key(repository_id=grant.repository_id,
                               pull_request_number=grant.pull_request_number,
                               subject_user_id=user_id, tree_oid=grant.tree_oid)
            entry = {"repository_id": grant.repository_id,
                     "pull_request_number": grant.pull_request_number,
                     "subject_user_id": user_id, "tree_oid": grant.tree_oid,
                     "grant_event_id": grant.event_id, "active": True}
            overrides = row(user_id)["overrides"]
            if key in overrides:
                raise CoverageError("replay has repeated active override tuples")
            overrides[key] = entry
    projection = CoverageProjection(state.project_id, files)
    validate_coverage_projection(projection, expected_project_id=state.project_id,
                                 expected_canonical_oid=canonical_oid)
    return projection


@dataclass(frozen=True, slots=True)
class CoverageDelta:
    """Changed logical files; no filesystem or branch writes are performed."""

    files: tuple[str, ...]
    shards: tuple[int, ...]


def coverage_delta(before: CoverageProjection, after: CoverageProjection) -> CoverageDelta:
    if type(before) is not CoverageProjection or type(after) is not CoverageProjection:
        raise CoverageError("delta requires validated coverage projections")
    validate_coverage_projection(before, expected_project_id=before.project_id)
    validate_coverage_projection(after, expected_project_id=before.project_id)
    old, new = before.plaintext_files(), after.plaintext_files()
    changed = tuple(sorted(path for path in _FILES if old[path] != new[path]))
    return CoverageDelta(changed, tuple(i for i, path in enumerate(_SHARDS) if path in changed))


@dataclass(frozen=True, slots=True)
class CoverageDecision:
    """Effective bounded decision, with no signer or exemption provenance."""

    decision: str
    reason_code: str | None
    overridden: bool = False
    successor_project_id: str | None = None


def evaluate_subject(projection: CoverageProjection, subject: int, agreement_id: str,
                      override_context: dict[str, Any] | None = None) -> CoverageDecision:
    if type(projection) is not CoverageProjection:
        raise CoverageError("evaluation requires a validated projection")
    validate_coverage_projection(projection, expected_project_id=projection.project_id)
    user = _scalar(_events._positive, subject)
    _scalar(_events._string, agreement_id)
    if override_context is not None:
        _exact(override_context, ("repository_id", "pull_request_number", "tree_oid"))
        _scalar(_events._positive, override_context["repository_id"])
        _scalar(_events._positive, override_context["pull_request_number"])
        _scalar(_events._oid, override_context["tree_oid"])
    files = projection.to_dict()
    if files[_SOURCE]["project_state"] == "succeeded":
        return CoverageDecision("uncovered", None,
                                successor_project_id=files[_SOURCE]["successor_project_id"])
    fence = files[_FENCE]
    if fence["state"] == "mutation" and (fence["project_wide"] or user in fence["subjects"]):
        return CoverageDecision("uncovered", "indeterminate")
    active = files[_ACTIVE]
    if active["agreement_id"] is not None and agreement_id != active["agreement_id"]:
        raise CoverageError("requested agreement does not match active agreement")
    row = files[_SHARDS[coverage_shard(user, shard_count=active["shard_count"])]].get(str(user))
    basis = row["agreements"].get(agreement_id) if row else None
    if basis and basis["reason_code"] == "indeterminate":
        return CoverageDecision("uncovered", "indeterminate")
    if basis and basis["decision"] == "covered" and basis["version"] in active["accepted_versions"]:
        return CoverageDecision("covered", "signed")
    if str(user) in files[_EXEMPT]:
        return CoverageDecision("covered", "exempt")
    if row and override_context is not None:
        key = override_key(subject_user_id=user, **override_context)
        if key in row["overrides"]:
            # An override satisfies this check without claiming a signature.
            # No new persisted generic code or grant provenance is introduced.
            return CoverageDecision("covered", None, overridden=True)
    reason = "version_not_active" if basis and basis["decision"] == "covered" else (
        basis["reason_code"] if basis else "not_signed")
    return CoverageDecision("uncovered", reason)
